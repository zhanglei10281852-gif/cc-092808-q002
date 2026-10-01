from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.forensics.cases import ForensicCaseService
from app.forensics.custody import CustodyService

DECISION_ACTIONS = {
    "accept": "accepted",
    "hold": "held",
    "return": "returned",
    "reopen": "pending",
}


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _loads(raw: str | None, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class IntakeService:
    """分阶段批次受理：委托清单导入、分次实收登记、差异复核与原子建案。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.cases = ForensicCaseService(connection, clock)
        self.custody = CustodyService(connection, clock)

    # ------------------------------------------------------------------ 读取

    def _require_batch(self, batch_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM intake_batches WHERE id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFoundError("受理批次不存在")
        return dict(row)

    def batch_detail(self, batch_id: int) -> dict[str, Any]:
        batch = self._require_batch(batch_id)
        batch["header"] = _loads(batch.pop("header_json"), {})
        batch["manifest"] = [self._manifest_row(row) for row in self.connection.execute(
            "SELECT * FROM intake_manifest_items WHERE batch_id=? ORDER BY line_no", (batch_id,)
        ).fetchall()]
        batch["rounds"] = [self._round_row(row) for row in self.connection.execute(
            "SELECT * FROM intake_rounds WHERE batch_id=? ORDER BY round_no", (batch_id,)
        ).fetchall()]
        packages_by_round: dict[Any, list[dict[str, Any]]] = {}
        loose_packages: list[dict[str, Any]] = []
        for package in self._packages(batch_id):
            if package.get("round_id") is None:
                loose_packages.append(package)
            else:
                packages_by_round.setdefault(package["round_id"], []).append(package)
        for round_item in batch["rounds"]:
            round_item["packages"] = packages_by_round.get(round_item["id"], [])
        batch["correction_packages"] = loose_packages
        batch["lines"] = [self._line_row(row) for row in self.connection.execute(
            "SELECT * FROM intake_review_lines WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall()]
        batch["generations"] = [dict(row) for row in self.connection.execute(
            "SELECT * FROM intake_generations WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall()]
        for generation in batch["generations"]:
            links = _loads(generation.pop("line_ids_json"), [])
            if isinstance(links, dict):
                generation["line_ids"] = links.get("line_ids", [])
                generation["specimen_ids"] = links.get("specimen_ids", [])
            else:
                generation["line_ids"] = links
                generation["specimen_ids"] = links
        batch["summary"] = self.reconcile_summary(batch_id)
        return batch

    def list_batches(self, *, status: str | None, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        where = ""
        params: list[Any] = []
        if status:
            where = " WHERE status=?"
            params.append(status)
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM intake_batches{where}", params).fetchone()[0])
        rows = self.connection.execute(
            f"SELECT * FROM intake_batches{where} ORDER BY id DESC LIMIT ? OFFSET ?", [*params, limit, offset]
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["header"] = _loads(item.pop("header_json"), {})
            items.append(item)
        return items, total

    def line_detail(self, line_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM intake_review_lines WHERE id=?", (line_id,)).fetchone()
        if row is None:
            raise NotFoundError("差异项目不存在")
        line = self._line_row(row)
        line["events"] = [dict(event) for event in self.connection.execute(
            "SELECT * FROM intake_decision_events WHERE line_id=? ORDER BY id", (line_id,)
        ).fetchall()]
        for event in line["events"]:
            event["context"] = _loads(event.pop("context_json"), {})
        line["corrections"] = []
        for correction in self.connection.execute(
            "SELECT * FROM intake_corrections WHERE line_id=? ORDER BY id", (line_id,)
        ).fetchall():
            entry = dict(correction)
            entry["before"] = _loads(entry.pop("before_json"), {})
            entry["after"] = _loads(entry.pop("after_json"), {})
            line["corrections"].append(entry)
        return line

    def _manifest_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["required_documents"] = _loads(item.pop("required_documents_json"), [])
        item["raw"] = _loads(item.pop("raw_json"), {})
        return item

    def _round_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["round_summary"] = _loads(item.pop("round_summary_json"), {})
        item["packages"] = []
        return item

    def _line_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["detail"] = _loads(item.pop("detail_json"), {})
        item["signature"] = _loads(item.pop("signature_json"), {})
        return item

    def _packages(self, batch_id: int) -> list[dict[str, Any]]:
        packages = []
        for row in self.connection.execute(
            "SELECT * FROM intake_received_packages WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall():
            item = dict(row)
            item["documents"] = _loads(item.pop("documents_json"), [])
            packages.append(item)
        return packages

    def _manifest(self, batch_id: int) -> list[dict[str, Any]]:
        return [self._manifest_row(row) for row in self.connection.execute(
            "SELECT * FROM intake_manifest_items WHERE batch_id=? ORDER BY line_no", (batch_id,)
        ).fetchall()]

    def _lines(self, batch_id: int) -> list[dict[str, Any]]:
        return [self._line_row(row) for row in self.connection.execute(
            "SELECT * FROM intake_review_lines WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall()]

    # ------------------------------------------------------------ 清单导入

    def create_batch(self, data: dict[str, Any]) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        source_hash = str(data["source_file_hash"]).strip()
        existing = self.connection.execute(
            "SELECT id FROM intake_batches WHERE source_file_hash=?", (source_hash,)
        ).fetchone()
        if existing:
            return {"batch": self.batch_detail(int(existing[0])), "replayed": True}
        items = data["items"]
        line_nos = [int(item["line_no"]) for item in items]
        if len(set(line_nos)) != len(line_nos):
            raise ValidationError("委托清单行号不能重复")
        batch_no = data.get("batch_no") or f"IB-{source_hash[:12].upper()}"
        try:
            cursor = self.connection.execute(
                "INSERT INTO intake_batches(batch_no,entrust_no,source_name,source_file_name,source_file_hash,"
                "header_json,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,'collecting',?,?,?)",
                (
                    batch_no, data.get("entrust_no", ""), data.get("source_name", ""), data["source_file_name"],
                    source_hash, _dumps(data.get("header", {})), data["created_by"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("批次编号或来源文件哈希已经存在") from exc
        batch_id = int(cursor.lastrowid)
        for item in items:
            documents = item.get("required_documents", [])
            item_hash = _sha256_text(_dumps({
                "line_no": item["line_no"], "seal_no": item["seal_no"], "category": item["category"],
                "quantity": item["quantity"], "documents": documents, "entrust_no": item.get("entrust_no", ""),
            }))
            try:
                self.connection.execute(
                    "INSERT INTO intake_manifest_items(batch_id,line_no,entrust_no,seal_no,category,quantity,"
                    "required_documents_json,raw_json,item_hash) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch_id, item["line_no"], item.get("entrust_no", ""), item["seal_no"], item["category"],
                        item["quantity"], _dumps(documents), _dumps(item.get("raw", {})), item_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("委托清单存在重复项目") from exc
        self._reconcile(batch_id, timestamp)
        summary = self._import_summary(batch_id)
        self._snapshot(batch_id, None, "import", data["created_by"], {"summary": summary}, timestamp)
        self.connection.execute("UPDATE intake_batches SET updated_at=? WHERE id=?", (timestamp, batch_id))
        return {"batch": self.batch_detail(batch_id), "replayed": False, "import_summary": summary}

    # ------------------------------------------------------------ 分次登记

    def register_round(self, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        batch = self._require_batch(batch_id)
        if batch["status"] != "collecting":
            raise ConflictError("批次已提交复核，不能继续登记实收封装")
        timestamp = to_storage(self.clock.now())
        source_hash = str(data["source_hash"]).strip()
        existing_round = self.connection.execute(
            "SELECT id FROM intake_rounds WHERE batch_id=? AND source_hash=?", (batch_id, source_hash)
        ).fetchone()
        if existing_round:
            round_id = int(existing_round[0])
            self.connection.execute(
                "UPDATE intake_rounds SET replayed_count=replayed_count+? WHERE id=?",
                (len(data["packages"]), round_id),
            )
            return {
                "round": self._round_row(self.connection.execute(
                    "SELECT * FROM intake_rounds WHERE id=?", (round_id,)
                ).fetchone()),
                "replayed": True,
                "summary": self.reconcile_summary(batch_id),
            }
        round_no = int(self.connection.execute(
            "SELECT COALESCE(MAX(round_no),0)+1 FROM intake_rounds WHERE batch_id=?", (batch_id,)
        ).fetchone()[0])
        cursor = self.connection.execute(
            "INSERT INTO intake_rounds(batch_id,round_no,source_label,source_hash,received_by,note,package_count,"
            "replayed_count,round_summary_json,created_at) VALUES(?,?,?,?,?,?,0,0,'{}',?)",
            (
                batch_id, round_no, data.get("source_label", ""), source_hash, data["received_by"],
                data.get("note", ""), timestamp,
            ),
        )
        round_id = int(cursor.lastrowid)
        inserted = 0
        replayed = 0
        for index, package in enumerate(data["packages"], start=1):
            record_hash = _sha256_text(_dumps({
                "source_hash": source_hash, "index": index, "seal_no": package["seal_no"],
                "category": package["category"], "quantity": package["quantity"],
                "scan_record_key": package.get("scan_record_key", ""),
                "documents": package.get("documents", []),
                "package_label": package.get("package_label", ""),
            }))
            duplicate = self.connection.execute(
                "SELECT id FROM intake_received_packages WHERE batch_id=? AND record_hash=?", (batch_id, record_hash)
            ).fetchone()
            if duplicate:
                replayed += 1
                continue
            if package.get("scan_record_key"):
                scanned = self.connection.execute(
                    "SELECT id FROM intake_received_packages WHERE batch_id=? AND scan_record_key=?",
                    (batch_id, package["scan_record_key"]),
                ).fetchone()
                if scanned:
                    replayed += 1
                    continue
            try:
                self._insert_package(batch_id, round_id, package, record_hash, timestamp)
            except sqlite3.IntegrityError:
                replayed += 1
                continue
            inserted += 1
        self.connection.execute(
            "UPDATE intake_rounds SET package_count=?,replayed_count=? WHERE id=?",
            (inserted, replayed, round_id),
        )
        self._reconcile(batch_id, timestamp)
        summary = self.reconcile_summary(batch_id)
        self.connection.execute(
            "UPDATE intake_rounds SET round_summary_json=? WHERE id=?", (_dumps(summary), round_id)
        )
        self._snapshot(batch_id, round_id, "round", data["received_by"], {
            "round_no": round_no, "inserted": inserted, "replayed": replayed, "summary": summary,
        }, timestamp)
        self._snapshot(batch_id, round_id, "reconcile", data["received_by"], summary, timestamp)
        self.connection.execute("UPDATE intake_batches SET updated_at=? WHERE id=?", (timestamp, batch_id))
        return {
            "round": self._round_row(self.connection.execute(
                "SELECT * FROM intake_rounds WHERE id=?", (round_id,)
            ).fetchone()),
            "replayed": False,
            "inserted": inserted,
            "replayed_packages": replayed,
            "summary": summary,
        }

    def submit_for_review(self, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        batch = self._require_batch(batch_id)
        self._check_batch_version(batch, int(data["expected_version"]))
        if batch["status"] != "collecting":
            raise ConflictError("批次当前状态不能提交复核")
        round_count = int(self.connection.execute(
            "SELECT COUNT(*) FROM intake_rounds WHERE batch_id=?", (batch_id,)
        ).fetchone()[0])
        if round_count == 0:
            raise ValidationError("至少登记一轮实收封装后才能提交复核")
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE intake_batches SET status='under_review',submitted_by=?,submitted_at=?,version=version+1,"
            "updated_at=? WHERE id=? AND version=? AND status='collecting'",
            (data["actor"], timestamp, timestamp, batch_id, data["expected_version"]),
        )
        if cursor.rowcount != 1:
            raise ConflictError("批次版本冲突或状态已变更")
        self._snapshot(batch_id, None, "decision", data["actor"], {"action": "submit_review"}, timestamp)
        return self.batch_detail(batch_id)

    def conclude(self, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        batch = self._require_batch(batch_id)
        self._check_batch_version(batch, int(data["expected_version"]))
        if batch["status"] != "under_review":
            raise ConflictError("只有复核中的批次可以结论归档")
        outstanding = self.connection.execute(
            "SELECT COUNT(*) FROM intake_review_lines WHERE batch_id=? AND decision IN ('pending','held')",
            (batch_id,),
        ).fetchone()[0]
        if int(outstanding):
            raise ConflictError("仍存在待复核或暂存待补正项目，不能结论批次", context={"outstanding": int(outstanding)})
        ungathered = self.connection.execute(
            "SELECT COUNT(*) FROM intake_review_lines WHERE batch_id=? AND decision='accepted' "
            "AND generated_specimen_id IS NULL",
            (batch_id,),
        ).fetchone()[0]
        if int(ungathered):
            raise ConflictError("已接收项目尚未全部生成正式案件与检材，不能结论批次", context={
                "ungenerated": int(ungathered),
            })
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE intake_batches SET status='concluded',concluded_by=?,concluded_at=?,version=version+1,"
            "updated_at=? WHERE id=? AND version=?",
            (data["actor"], timestamp, timestamp, batch_id, data["expected_version"]),
        )
        if cursor.rowcount != 1:
            raise ConflictError("批次版本冲突")
        self._snapshot(batch_id, None, "conclude", data["actor"], {"summary": self.reconcile_summary(batch_id)}, timestamp)
        return self.batch_detail(batch_id)

    # ------------------------------------------------------------ 差异复核

    def decide_line(self, line_id: int, data: dict[str, Any]) -> dict[str, Any]:
        line = self._require_line(line_id)
        result = self._apply_decision(line, data["action"], data["actor"], data.get("reason", ""), int(data["expected_version"]))
        self._snapshot(int(line["batch_id"]), line.get("round_id"), "decision", data["actor"], {
            "line_id": line_id, "action": data["action"], "reason": data.get("reason", ""),
        }, to_storage(self.clock.now()))
        return result

    def decide_batch(self, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        batch = self._require_batch(batch_id)
        if batch["status"] != "under_review":
            raise ConflictError("批次未处于复核中")
        action = data["action"]
        target = DECISION_ACTIONS[action]
        reason = data.get("reason", "")
        if action in {"hold", "return"} and not reason.strip():
            raise ValidationError("暂存待补正或退回时必须填写理由")
        requested = {int(item["line_id"]): int(item["expected_version"]) for item in data["items"]}
        if len(requested) != len(data["items"]):
            raise ValidationError("批量决定项目不能重复")
        lines = [self._require_line(line_id) for line_id in requested]
        conflicts: list[dict[str, Any]] = []
        for line in lines:
            if int(line["batch_id"]) != batch_id:
                raise ValidationError("批量决定不能跨批次")
            if line["decision"] != "pending":
                conflicts.append({"line_id": line["id"], "reason": "项目已被处理", "current_decision": line["decision"]})
            elif int(line["version"]) != requested[line["id"]]:
                conflicts.append({
                    "line_id": line["id"], "reason": "版本过期", "current_version": line["version"],
                    "decided_by": line["decided_by"],
                })
            elif action == "accept" and line["kind"] != "matched":
                conflicts.append({"line_id": line["id"], "reason": "存在差异的项目不能批量接收", "kind": line["kind"]})
        if conflicts:
            raise ConflictError("批量决定存在冲突项目，未执行任何变更", context={"conflicts": conflicts})
        timestamp = to_storage(self.clock.now())
        decided = []
        for line in lines:
            decided.append(self._apply_decision(line, action, data["actor"], reason, requested[line["id"]], timestamp))
        self._snapshot(batch_id, None, "decision", data["actor"], {
            "action": action, "line_ids": list(requested), "reason": reason,
        }, timestamp)
        return {"action": action, "decided_count": len(decided), "items": decided}

    def _apply_decision(
        self,
        line: dict[str, Any],
        action: str,
        actor: str,
        reason: str,
        expected_version: int,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        target = DECISION_ACTIONS[action]
        timestamp = timestamp or to_storage(self.clock.now())
        if action in {"hold", "return"} and not reason.strip():
            raise ValidationError("暂存待补正或退回时必须填写理由")
        from_version = int(line["version"])
        if action == "accept" and line["generated_specimen_id"] is not None:
            raise ConflictError("项目已生成正式检材，不能变更结论")
        if action == "accept":
            received_quantity = float(line["detail"].get("received_quantity") or 0)
            if not line["detail"].get("received_package_id") or received_quantity <= 0:
                raise ValidationError("没有实收封装的缺件项目不能接收，应退回或补正后再决定")
            if line["kind"] != "matched" and not reason.strip():
                raise ValidationError("存在差异的项目接收时必须填写决定理由")
        if from_version != expected_version:
            raise ConflictError("差异项目版本过期，不能覆盖其他复核人的结论", context={
                "current_version": from_version, "current_decision": line["decision"], "decided_by": line["decided_by"],
            })
        if action == "reopen":
            if line["generated_specimen_id"] is not None:
                raise ConflictError("项目已生成正式检材，不能重新打开")
            if line["decision"] == "pending":
                raise ConflictError("项目尚未作出结论")
        elif line["decision"] != "pending":
            raise ConflictError("项目已被处理，不能覆盖其他复核人的结论", context={
                "current_decision": line["decision"], "decided_by": line["decided_by"],
                "current_version": from_version,
            })
        if action == "reopen":
            cursor = self.connection.execute(
                "UPDATE intake_review_lines SET decision='pending',decided_by=NULL,decided_at=NULL,"
                "decision_reason='',version=version+1,updated_at=? WHERE id=? AND version=?",
                (timestamp, line["id"], expected_version),
            )
        else:
            cursor = self.connection.execute(
                "UPDATE intake_review_lines SET decision=?,decided_by=?,decided_at=?,decision_reason=?,"
                "version=version+1,updated_at=? WHERE id=? AND version=?",
                (target, actor, timestamp, reason, timestamp, line["id"], expected_version),
            )
        if cursor.rowcount != 1:
            raise ConflictError("差异项目版本冲突")
        self.connection.execute(
            "INSERT INTO intake_decision_events(line_id,action,actor,reason,from_version,to_version,context_json,"
            "created_at) VALUES(?,?,?,?,?,?,?,?)",
            (line["id"], action, actor, reason, from_version, from_version + 1, "{}", timestamp),
        )
        return self._line_row(self.connection.execute(
            "SELECT * FROM intake_review_lines WHERE id=?", (line["id"],)
        ).fetchone())

    def _require_line(self, line_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM intake_review_lines WHERE id=?", (line_id,)).fetchone()
        if row is None:
            raise NotFoundError("差异项目不存在")
        return self._line_row(row)

    # ------------------------------------------------------------ 补正轨迹

    def record_correction(self, line_id: int, data: dict[str, Any]) -> dict[str, Any]:
        line = self._require_line(line_id)
        batch = self._require_batch(int(line["batch_id"]))
        if batch["status"] != "under_review":
            raise ConflictError("批次不在复核中，不能登记补正")
        if line["generated_specimen_id"] is not None:
            raise ConflictError("项目已生成正式检材，不能补正")
        if line["decision"] != "held":
            raise ConflictError("只有暂存待补正的项目可以登记补正", context={"current_decision": line["decision"]})
        before = {"kind": line["kind"], "detail": line["detail"], "decision": line["decision"]}
        timestamp = to_storage(self.clock.now())
        detail = dict(line["detail"])
        added = [item.strip() for item in data.get("added_documents", []) if item.strip()]
        round_id = line.get("round_id")
        package_id = line.get("received_package_id")
        inline_package = data.get("package")
        if data.get("received_package_id"):
            package_id = int(data["received_package_id"])
        if inline_package is not None:
            if line.get("manifest_item_id") is None:
                raise ValidationError("只有委托清单内的缺件项目可以补传封装")
            if package_id is not None:
                raise ValidationError("已有对应封装的项目不能再补传封装")
            documents = inline_package.get("documents", [])
            record_hash = _sha256_text(_dumps({
                "correction_for_line": line_id, "seal_no": inline_package["seal_no"],
                "category": inline_package["category"], "quantity": inline_package["quantity"],
                "scan_record_key": inline_package.get("scan_record_key", ""), "documents": documents,
            }))
            duplicate = self.connection.execute(
                "SELECT id FROM intake_received_packages WHERE batch_id=? AND record_hash=?",
                (line["batch_id"], record_hash),
            ).fetchone()
            if duplicate:
                raise ConflictError("补传封装记录重复")
            package_id = self._insert_package(
                int(line["batch_id"]), None, inline_package, record_hash, timestamp
            )
            round_id = None
        if added:
            existing = list(detail.get("corrected_documents", []))
            detail["corrected_documents"] = sorted(set(existing) | set(added))
        if package_id is not None:
            package = self.connection.execute(
                "SELECT * FROM intake_received_packages WHERE id=? AND batch_id=?",
                (package_id, line["batch_id"]),
            ).fetchone()
            if package is None:
                raise ValidationError("补正封装不属于当前批次")
            occupant = self.connection.execute(
                "SELECT id FROM intake_review_lines WHERE batch_id=? AND received_package_id=? AND id<>?",
                (line["batch_id"], package_id, line_id),
            ).fetchone()
            if occupant:
                raise ConflictError("补正封装已被其他差异项目占用", context={"line_id": int(occupant[0])})
            if package["round_id"] is not None:
                round_id = int(package["round_id"])
            package_dict = dict(package)
            package_dict["documents"] = _loads(package_dict.pop("documents_json"), [])
            manifest = self.connection.execute(
                "SELECT * FROM intake_manifest_items WHERE id=?", (line["manifest_item_id"],)
            ).fetchone() if line.get("manifest_item_id") else None
            kind, new_detail = self._classify(
                self._manifest_row(manifest) if manifest else None, package_dict
            )
            if data.get("quantity_override") is not None:
                new_detail["received_quantity"] = float(data["quantity_override"])
                if new_detail.get("manifest_quantity") is not None:
                    new_detail["quantity_delta"] = round(
                        float(data["quantity_override"]) - float(new_detail["manifest_quantity"]), 6
                    )
            if data.get("category_override"):
                new_detail["received_category"] = data["category_override"]
            new_detail["corrected_documents"] = detail.get("corrected_documents", [])
            kind, new_detail = self._reclassify_with_corrections(kind, new_detail)
            signature = {
                "kind": kind, "manifest_item_id": line.get("manifest_item_id"),
                "received_package_id": package_id,
            }
            self.connection.execute(
                "UPDATE intake_review_lines SET round_id=?,received_package_id=?,kind=?,detail_json=?,"
                "signature_json=?,entrust_no=?,seal_no=?,updated_at=? WHERE id=?",
                (
                    round_id, package_id, kind, _dumps(new_detail), _dumps(signature),
                    new_detail.get("manifest_entrust_no") or package_dict.get("entrust_no", ""),
                    new_detail.get("seal_no") or package_dict["seal_no"], timestamp, line_id,
                ),
            )
            detail = new_detail
        elif added:
            if line.get("received_package_id") is None:
                raise ValidationError("缺件项目必须通过补传封装补正，不能只补文书")
            kind, detail = self._reclassify_with_corrections(line["kind"], detail)
            signature = dict(line["signature"])
            signature["kind"] = kind
            self.connection.execute(
                "UPDATE intake_review_lines SET kind=?,detail_json=?,signature_json=?,updated_at=? WHERE id=?",
                (kind, _dumps(detail), _dumps(signature), timestamp, line_id),
            )
        else:
            raise ValidationError("补正必须提供补传文书或补正封装")
        cursor = self.connection.execute(
            "INSERT INTO intake_corrections(line_id,round_id,received_package_id,actor,note,before_json,after_json,"
            "created_at) VALUES(?,?,?,?,?,?,?,?)",
            (line_id, round_id, package_id, data["actor"], data["note"], _dumps(before),
             _dumps({"kind": kind, "detail": detail, "decision": "pending"}), timestamp),
        )
        correction_id = int(cursor.lastrowid)
        from_version = int(line["version"])
        self.connection.execute(
            "UPDATE intake_review_lines SET decision='pending',decided_by=NULL,decided_at=NULL,decision_reason='',"
            "version=version+1,updated_at=? WHERE id=? AND version=?",
            (timestamp, line_id, from_version),
        )
        self.connection.execute(
            "INSERT INTO intake_decision_events(line_id,action,actor,reason,from_version,to_version,context_json,"
            "created_at) VALUES(?,?,?,?,?,?,?,?)",
            (line_id, "reopen", data["actor"], f"补正后重新复核：{data['note']}", from_version, from_version + 1,
             _dumps({"correction_id": correction_id}), timestamp),
        )
        self._snapshot(int(line["batch_id"]), round_id, "correction", data["actor"], {
            "line_id": line_id, "correction_id": correction_id, "kind": kind,
        }, timestamp)
        return self.line_detail(line_id)

    def _reclassify_with_corrections(
        self, kind: str, detail: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        if not detail.get("received_package_id") and kind != "document_missing":
            return kind, detail
        corrected = set(detail.get("corrected_documents", []))
        required = set(detail.get("documents_required", []))
        received = set(detail.get("documents_received", [])) | corrected
        missing = sorted(required - received)
        detail["documents_received"] = sorted(received)
        detail["documents_missing"] = missing
        problems = []
        if abs(float(detail.get("manifest_quantity", 0)) - float(detail.get("received_quantity", 0))) > 1e-9:
            problems.append("quantity_mismatch")
        if detail.get("manifest_category") and detail.get("received_category") and \
                detail["manifest_category"] != detail["received_category"]:
            problems.append("category_mismatch")
        if missing:
            problems.append("document_missing")
        if detail.get("manifest_entrust_no") and detail.get("received_entrust_no") and \
                detail["manifest_entrust_no"] != detail["received_entrust_no"]:
            problems.append("entrust_mismatch")
        new_kind = "mixed" if len(problems) > 1 else (problems[0] if problems else "matched")
        return new_kind, detail

    # ------------------------------------------------------------ 原子建案

    def generate_cases(self, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        batch = self._require_batch(batch_id)
        self._check_batch_version(batch, int(data["expected_version"]))
        if batch["status"] != "under_review":
            raise ConflictError("批次未处于复核中，不能生成正式案件")
        timestamp = to_storage(self.clock.now())
        generated: list[dict[str, Any]] = []
        plans = data["cases"]
        entrust_keys = [str(plan["entrust_no"]) for plan in plans]
        if len(set(entrust_keys)) != len(entrust_keys):
            raise ValidationError("同一委托编号只能对应一个建案计划")
        for plan in plans:
            entrust_no = str(plan["entrust_no"])
            already = self.connection.execute(
                "SELECT id FROM intake_generations WHERE batch_id=? AND entrust_no=?", (batch_id, entrust_no)
            ).fetchone()
            if already:
                raise ConflictError("该委托编号的已确认项目已经生成正式案件", context={
                    "entrust_no": entrust_no, "generation_id": int(already[0]),
                })
            rows = self.connection.execute(
                "SELECT * FROM intake_review_lines WHERE batch_id=? AND entrust_no=? AND decision='accepted' "
                "AND generated_specimen_id IS NULL ORDER BY id",
                (batch_id, entrust_no),
            ).fetchall()
            lines = [self._line_row(row) for row in rows]
            if not lines:
                raise ConflictError("该委托编号下没有可生成案件的已接收项目", context={"entrust_no": entrust_no})
            case = self.cases.create_forensic_case({
                "case_no": plan["case_no"],
                "case_name": plan["case_name"],
                "discipline": plan["discipline"],
                "entrusted_matter": plan.get("entrusted_matter", ""),
                "agency_id": plan.get("agency_id"),
                "case_source": plan["case_source"],
                "accepted_on": plan["accepted_on"].isoformat() if hasattr(plan["accepted_on"], "isoformat") else str(plan["accepted_on"]),
                "passport": {**plan.get("passport", {}), "intake_batch_id": batch_id, "entrust_no": entrust_no},
                "created_by": data["actor"],
            })
            accepted_case = self.cases.transition(case["id"], {
                "target_status": "accepted",
                "reason": f"批次 {batch['batch_no']} 已确认项目原子建案",
                "expected_version": int(case["version"]),
                "actor": data["actor"],
            })
            line_ids: list[int] = []
            specimen_ids: list[int] = []
            quantity_total = 0.0
            for line in lines:
                detail = line["detail"]
                quantity = float(detail.get("received_quantity") or 0)
                if quantity <= 0:
                    raise ConflictError("已接收项目数量异常，不能生成检材", context={"line_id": line["id"]})
                seal_no = detail.get("seal_no") or line["seal_no"]
                specimen = self.custody.create_specimen({
                    "specimen_no": f"SP-IB{batch_id}-L{line['id']}",
                    "case_id": accepted_case["id"],
                    "parent_specimen_id": None,
                    "received_year": int(str(plan["accepted_on"])[:4]),
                    "initial_quantity": quantity,
                    "integrity_percent": None,
                    "packaging": f"封识号 {seal_no}；类别 {detail.get('received_category') or line['kind']}",
                    "sealed_on": detail.get("sealed_on"),
                    "created_by": data["actor"],
                })
                line_ids.append(int(line["id"]))
                specimen_ids.append(int(specimen["id"]))
                quantity_total += quantity
                self.connection.execute(
                    "UPDATE intake_review_lines SET generated_specimen_id=? WHERE id=?",
                    (specimen["id"], line["id"]),
                )
            cursor = self.connection.execute(
                "INSERT INTO intake_generations(batch_id,case_id,entrust_no,generated_by,line_ids_json,"
                "specimen_count,quantity_total,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    batch_id, accepted_case["id"], entrust_no, data["actor"],
                    _dumps({"line_ids": line_ids, "specimen_ids": specimen_ids}),
                    len(specimen_ids), round(quantity_total, 6), timestamp,
                ),
            )
            generated.append({
                "generation_id": int(cursor.lastrowid),
                "case_id": accepted_case["id"],
                "case_no": accepted_case["case_no"],
                "entrust_no": entrust_no,
                "line_ids": line_ids,
                "specimen_ids": specimen_ids,
                "specimen_count": len(specimen_ids),
                "quantity_total": round(quantity_total, 6),
            })
        self.connection.execute(
            "UPDATE intake_batches SET version=version+1,updated_at=? WHERE id=?", (timestamp, batch_id)
        )
        self._snapshot(batch_id, None, "generation", data["actor"], {"generated": generated}, timestamp)
        return {"generated": generated, "summary": self.reconcile_summary(batch_id)}

    # ------------------------------------------------------------ 差异计算

    def _reconcile(self, batch_id: int, timestamp: str) -> None:
        """依据委托清单和全部实收封装重算未决差异行；已下结论行冻结不参与配对。"""
        frozen_rows = self.connection.execute(
            "SELECT * FROM intake_review_lines WHERE batch_id=? AND (decision<>'pending' "
            "OR generated_specimen_id IS NOT NULL) ORDER BY id",
            (batch_id,),
        ).fetchall()
        frozen = [self._line_row(row) for row in frozen_rows]
        self.connection.execute(
            "DELETE FROM intake_review_lines WHERE batch_id=? AND decision='pending' AND generated_specimen_id IS NULL",
            (batch_id,),
        )
        used_manifest = {int(line["manifest_item_id"]) for line in frozen if line.get("manifest_item_id")}
        used_packages = {int(line["received_package_id"]) for line in frozen if line.get("received_package_id")}

        manifest = [item for item in self._manifest(batch_id) if item["id"] not in used_manifest]
        packages = [item for item in self._packages(batch_id) if item["id"] not in used_packages]

        seen_seals: set[str] = set()
        for frozen_line in frozen:
            seal = frozen_line.get("seal_no")
            if seal:
                seen_seals.add(seal)

        free_packages = {int(item["id"]): item for item in packages}
        seal_to_packages: dict[str, list[dict[str, Any]]] = {}
        for item in packages:
            seal_to_packages.setdefault(item["seal_no"], []).append(item)

        manifest_seals = {item["seal_no"] for item in self._manifest(batch_id)}

        for item in manifest:
            if item["seal_no"] in seen_seals:
                self._insert_line(batch_id, None, item, None, "duplicate_seal", {
                    "seal_no": item["seal_no"],
                    "manifest_line_no": item["line_no"],
                    "manifest_quantity": item["quantity"],
                    "reason": "委托清单内封识号重复",
                }, timestamp)
                continue
            seen_seals.add(item["seal_no"])
            candidates = seal_to_packages.get(item["seal_no"], [])
            package = None
            fallback = None
            for candidate in candidates:
                if candidate["id"] not in free_packages:
                    continue
                if fallback is None:
                    fallback = candidate
                if item.get("entrust_no") and candidate.get("entrust_no") == item["entrust_no"]:
                    package = candidate
                    break
            package = package or fallback
            if package is None:
                self._insert_line(batch_id, None, item, None, "missing", {
                    "seal_no": item["seal_no"],
                    "manifest_entrust_no": item.get("entrust_no", ""),
                    "manifest_line_no": item["line_no"],
                    "manifest_category": item["category"],
                    "manifest_quantity": item["quantity"],
                    "documents_required": item["required_documents"],
                    "reason": "委托清单有记载但现场无封装",
                }, timestamp)
                continue
            free_packages.pop(int(package["id"]), None)
            kind, detail = self._classify(item, package)
            self._insert_line(batch_id, int(package["round_id"]), item, package, kind, detail, timestamp)

        for package in free_packages.values():
            if package["seal_no"] in manifest_seals:
                kind = "duplicate_seal"
                reason = "现场出现封识号重复的封装"
            else:
                kind = "surplus"
                reason = "现场封装在委托清单中没有记载"
            self._insert_line(batch_id, int(package["round_id"]), None, package, kind, {
                "seal_no": package["seal_no"],
                "received_entrust_no": package.get("entrust_no", ""),
                "received_category": package["category"],
                "received_quantity": package["quantity"],
                "documents_received": package["documents"],
                "received_package_id": package["id"],
                "round_id": package["round_id"],
                "reason": reason,
            }, timestamp, entrust_no=package.get("entrust_no", ""))

    def _classify(
        self, manifest: dict[str, Any] | None, package: dict[str, Any] | None
    ) -> tuple[str, dict[str, Any]]:
        detail: dict[str, Any] = {
            "seal_no": (manifest or package)["seal_no"],
            "manifest_line_no": manifest["line_no"] if manifest else None,
            "manifest_item_id": manifest["id"] if manifest else None,
            "received_package_id": package["id"] if package else None,
            "round_id": package["round_id"] if package else None,
        }
        problems: list[str] = []
        if manifest:
            detail["manifest_entrust_no"] = manifest.get("entrust_no", "")
            detail["manifest_category"] = manifest["category"]
            detail["manifest_quantity"] = manifest["quantity"]
            detail["documents_required"] = manifest["required_documents"]
        if package:
            detail["received_entrust_no"] = package.get("entrust_no", "")
            detail["received_category"] = package["category"]
            detail["received_quantity"] = package["quantity"]
            detail["documents_received"] = package["documents"]
        if manifest and package:
            if abs(float(manifest["quantity"]) - float(package["quantity"])) > 1e-9:
                problems.append("quantity_mismatch")
                detail["quantity_delta"] = round(float(package["quantity"]) - float(manifest["quantity"]), 6)
            if manifest["category"] != package["category"]:
                problems.append("category_mismatch")
            required = set(manifest["required_documents"])
            received = set(package["documents"])
            missing = sorted(required - received)
            detail["documents_missing"] = missing
            if missing:
                problems.append("document_missing")
            if manifest.get("entrust_no") and package.get("entrust_no") and \
                    manifest["entrust_no"] != package["entrust_no"]:
                problems.append("entrust_mismatch")
        kind = "mixed" if len(problems) > 1 else (problems[0] if problems else "matched")
        if problems:
            detail["reason"] = "、".join(problems)
        return kind, detail

    def _insert_package(
        self,
        batch_id: int,
        round_id: int | None,
        package: dict[str, Any],
        record_hash: str,
        timestamp: str,
    ) -> int:
        documents = package.get("documents", [])
        cursor = self.connection.execute(
            "INSERT INTO intake_received_packages(batch_id,round_id,entrust_no,seal_no,category,quantity,"
            "documents_json,scan_record_key,package_label,record_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                batch_id, round_id, package.get("entrust_no", ""), package["seal_no"], package["category"],
                package["quantity"], _dumps(documents), package.get("scan_record_key", ""),
                package.get("package_label", ""), record_hash, timestamp,
            ),
        )
        return int(cursor.lastrowid)

    def _insert_line(
        self,
        batch_id: int,
        round_id: int | None,
        manifest: dict[str, Any] | None,
        package: dict[str, Any] | None,
        kind: str,
        detail: dict[str, Any],
        timestamp: str,
        entrust_no: str | None = None,
    ) -> None:
        signature = {
            "kind": kind,
            "manifest_item_id": manifest["id"] if manifest else None,
            "received_package_id": package["id"] if package else None,
        }
        seal_no = (manifest or package)["seal_no"]
        line_entrust = entrust_no if entrust_no is not None else (
            (manifest.get("entrust_no") if manifest else None) or (package.get("entrust_no", "") if package else "")
        )
        self.connection.execute(
            "INSERT INTO intake_review_lines(batch_id,round_id,manifest_item_id,received_package_id,entrust_no,"
            "seal_no,kind,detail_json,signature_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                batch_id, round_id, manifest["id"] if manifest else None,
                package["id"] if package else None, line_entrust, seal_no, kind,
                _dumps(detail), _dumps(signature), timestamp, timestamp,
            ),
        )

    # ------------------------------------------------------------ 汇总核对

    def _import_summary(self, batch_id: int) -> dict[str, Any]:
        manifest_total = int(self.connection.execute(
            "SELECT COUNT(*) FROM intake_manifest_items WHERE batch_id=?", (batch_id,)
        ).fetchone()[0])
        manifest_quantity = float(self.connection.execute(
            "SELECT COALESCE(SUM(quantity),0) FROM intake_manifest_items WHERE batch_id=?", (batch_id,)
        ).fetchone()[0])
        return {
            "manifest_count": manifest_total,
            "manifest_quantity": round(manifest_quantity, 6),
            "pending_lines": int(self.connection.execute(
                "SELECT COUNT(*) FROM intake_review_lines WHERE batch_id=? AND decision='pending'", (batch_id,)
            ).fetchone()[0]),
        }

    def reconcile_summary(self, batch_id: int) -> dict[str, Any]:
        self._require_batch(batch_id)
        manifest_rows = self.connection.execute(
            "SELECT entrust_no,COUNT(*) AS c,COALESCE(SUM(quantity),0) AS q FROM intake_manifest_items "
            "WHERE batch_id=? GROUP BY entrust_no ORDER BY entrust_no", (batch_id,)
        ).fetchall()
        package_count, package_quantity = self.connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(quantity),0) FROM intake_received_packages WHERE batch_id=?",
            (batch_id,),
        ).fetchone()
        correction_package_count = int(self.connection.execute(
            "SELECT COUNT(*) FROM intake_received_packages WHERE batch_id=? AND round_id IS NULL", (batch_id,)
        ).fetchone()[0])
        rounds_inserted, rounds_replayed = self.connection.execute(
            "SELECT COALESCE(SUM(package_count),0),COALESCE(SUM(replayed_count),0) FROM intake_rounds WHERE batch_id=?",
            (batch_id,),
        ).fetchone()
        lines = self._lines(batch_id)
        by_kind: dict[str, int] = {}
        by_decision: dict[str, dict[str, float]] = {}
        accepted_qty = 0.0
        returned_qty = 0.0
        held_qty = 0.0
        for line in lines:
            by_kind[line["kind"]] = by_kind.get(line["kind"], 0) + 1
            bucket = by_decision.setdefault(line["decision"], {"count": 0, "quantity": 0.0})
            bucket["count"] += 1
            quantity = float(line["detail"].get("received_quantity") or 0)
            bucket["quantity"] = round(bucket["quantity"] + quantity, 6)
            if line["decision"] == "accepted":
                accepted_qty += quantity
            elif line["decision"] == "returned":
                returned_qty += quantity
            elif line["decision"] == "held":
                held_qty += quantity

        generation_rows = self.connection.execute(
            "SELECT g.*,c.case_no FROM intake_generations g JOIN forensic_cases c ON c.id=g.case_id "
            "WHERE g.batch_id=? ORDER BY g.id", (batch_id,)
        ).fetchall()
        generated_cases = []
        specimen_quantity = 0.0
        specimen_count = 0
        returned_in_custody = []
        for row in generation_rows:
            entry = dict(row)
            links = _loads(entry.pop("line_ids_json"), [])
            if isinstance(links, dict):
                line_ids = links.get("line_ids", [])
                specimen_ids = links.get("specimen_ids", [])
            else:
                line_ids = links
                specimen_ids = links
            if specimen_ids:
                placeholders = ",".join("?" * len(specimen_ids))
                custody_rows = self.connection.execute(
                    f"SELECT id,initial_quantity,available_quantity,status FROM specimens WHERE id IN ({placeholders})",
                    specimen_ids,
                ).fetchall()
            else:
                custody_rows = []
            initial_sum = round(sum(float(item["initial_quantity"]) for item in custody_rows), 6)
            specimen_quantity += initial_sum
            specimen_count += len(custody_rows)
            placement_sum = float(self.connection.execute(
                "SELECT COALESCE(SUM(p.quantity),0) FROM specimen_placements p JOIN specimens s ON s.id=p.specimen_id "
                "WHERE s.case_id=? AND p.removed_at IS NULL", (entry["case_id"],),
            ).fetchone()[0]) if custody_rows else 0.0
            generated_cases.append({
                "generation_id": entry["id"],
                "case_id": entry["case_id"],
                "case_no": entry["case_no"],
                "entrust_no": entry["entrust_no"],
                "line_ids": line_ids,
                "specimen_ids": specimen_ids,
                "specimen_count": entry["specimen_count"],
                "recorded_specimen_count": len(custody_rows),
                "quantity_total": entry["quantity_total"],
                "specimen_initial_quantity": initial_sum,
                "active_placement_quantity": round(placement_sum, 6),
                "ties": len(custody_rows) == entry["specimen_count"]
                and abs(initial_sum - float(entry["quantity_total"])) < 1e-6,
            })
        returned_lines = [
            {
                "line_id": line["id"], "seal_no": line["seal_no"], "entrust_no": line["entrust_no"],
                "kind": line["kind"], "quantity": line["detail"].get("received_quantity", 0),
                "reason": line["decision_reason"], "generated_specimen_id": line["generated_specimen_id"],
            }
            for line in lines if line["decision"] == "returned"
        ]
        for item in returned_lines:
            if item["generated_specimen_id"] is not None:
                returned_in_custody.append(item["line_id"])

        accepted_lines = [line for line in lines if line["decision"] == "accepted"]
        ungathered = [
            line["id"] for line in accepted_lines if line["generated_specimen_id"] is None
        ]
        manifest_coverage = int(self.connection.execute(
            "SELECT COUNT(*) FROM intake_manifest_items m WHERE batch_id=? AND NOT EXISTS ("
            "SELECT 1 FROM intake_review_lines l WHERE l.manifest_item_id=m.id)", (batch_id,)
        ).fetchone()[0])
        package_coverage = int(self.connection.execute(
            "SELECT COUNT(*) FROM intake_received_packages p WHERE batch_id=? AND NOT EXISTS ("
            "SELECT 1 FROM intake_review_lines l WHERE l.received_package_id=p.id)", (batch_id,)
        ).fetchone()[0])

        checks = {
            "manifest_items_all_on_lines": manifest_coverage == 0,
            "packages_all_on_lines": package_coverage == 0,
            "accepted_quantity_matches_specimens": abs(accepted_qty - specimen_quantity) < 1e-6
            and not ungathered,
            "accepted_specimen_count_matches": len([
                line for line in accepted_lines if line["generated_specimen_id"] is not None
            ]) == specimen_count,
            "returned_items_not_in_custody": not returned_in_custody,
            "no_pending_or_held": by_decision.get("pending", {}).get("count", 0) == 0
            and by_decision.get("held", {}).get("count", 0) == 0,
            "round_registered_packages_tie": int(package_count) - correction_package_count == int(rounds_inserted),
        }
        return {
            "batch_id": batch_id,
            "manifest": {
                "count": int(self.connection.execute(
                    "SELECT COUNT(*) FROM intake_manifest_items WHERE batch_id=?", (batch_id,)
                ).fetchone()[0]),
                "quantity": round(sum(float(row["q"]) for row in manifest_rows), 6),
                "by_entrust": [
                    {"entrust_no": row["entrust_no"], "count": int(row["c"]), "quantity": round(float(row["q"]), 6)}
                    for row in manifest_rows
                ],
            },
            "received": {
                "package_count": int(package_count),
                "quantity": round(float(package_quantity), 6),
                "rounds_inserted": int(rounds_inserted),
                "rounds_replayed": int(rounds_replayed),
                "correction_package_count": correction_package_count,
            },
            "lines": {"total": len(lines), "by_kind": by_kind, "by_decision": by_decision},
            "accepted": {
                "count": len(accepted_lines),
                "quantity": round(accepted_qty, 6),
                "generated_specimen_count": specimen_count,
                "generated_quantity": round(specimen_quantity, 6),
                "ungenerated_line_ids": ungathered,
            },
            "held": {"quantity": round(held_qty, 6)},
            "returned": {"count": len(returned_lines), "quantity": round(returned_qty, 6), "items": returned_lines},
            "generated_cases": generated_cases,
            "checks": checks,
            "balanced": all(checks.values()),
        }

    # ------------------------------------------------------------ 内部工具

    def _check_batch_version(self, batch: dict[str, Any], expected_version: int) -> None:
        if int(batch["version"]) != expected_version:
            raise ConflictError("批次版本过期", context={"current_version": int(batch["version"])})

    def _snapshot(
        self,
        batch_id: int,
        round_id: int | None,
        kind: str,
        actor: str,
        payload: dict[str, Any],
        timestamp: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO intake_snapshots(batch_id,round_id,snapshot_kind,actor,snapshot_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (batch_id, round_id, kind, actor, _dumps(payload), timestamp),
        )

    def snapshots(self, batch_id: int) -> list[dict[str, Any]]:
        self._require_batch(batch_id)
        result = []
        for row in self.connection.execute(
            "SELECT * FROM intake_snapshots WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall():
            item = dict(row)
            item["snapshot"] = _loads(item.pop("snapshot_json"), {})
            result.append(item)
        return result
