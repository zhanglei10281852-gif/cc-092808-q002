from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.forensics.cases import ForensicCaseService
from app.forensics.custody import CustodyService
from app.forensics.repository import ForensicRepository, record, records

RECORDING_STATUSES = {"importing", "in_review"}
DECISIONS = {"accepted", "pending_correction", "returned"}
UNMATCHED_LINE_BASE = 900_000

# 差异代码：缺件 / 数量不符 / 类别不符 / 文书缺失 / 重复封识 / 无委托项（多余封装）/ 数量未登记
CODE_MISSING = "package_missing"
CODE_QUANTITY = "quantity_mismatch"
CODE_CATEGORY = "category_mismatch"
CODE_DOCUMENT = "missing_document"
CODE_DUPLICATE_SEAL = "duplicate_seal"
CODE_UNEXPECTED = "unexpected_package"
CODE_QUANTITY_UNKNOWN = "quantity_unknown"


def _canonical_hash(payload: Any) -> str:
    compact = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()


def _as_doc_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    return sorted({str(item).strip() for item in value if str(item).strip()})


class IntakeService:
    """分阶段批次受理：委托清单导入、分次实收登记、差异快照、复核决定与原子立案。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)

    # ------------------------------------------------------------------ 导入

    def import_manifest(self, data: dict[str, Any]) -> dict[str, Any]:
        lines = data.get("lines") or []
        if not lines:
            raise ValidationError("委托清单至少包含一行委托项")
        normalized_lines: list[dict[str, Any]] = []
        seen_line: set[int] = set()
        seen_keys: set[tuple[str, str]] = set()
        seal_owners: dict[str, set[str]] = {}
        for index, raw in enumerate(lines, start=1):
            line_no = int(raw.get("line_no") or index)
            if line_no in seen_line:
                raise ValidationError(f"委托清单行号重复：{line_no}")
            seen_line.add(line_no)
            entrust_no = str(raw.get("entrust_no", "")).strip()
            if not entrust_no:
                raise ValidationError(f"第 {line_no} 行缺少委托编号")
            seal_no = str(raw.get("seal_no", "")).strip().upper()
            try:
                quantity = float(raw.get("expected_quantity", 0))
            except (TypeError, ValueError) as exc:
                raise ValidationError(f"第 {line_no} 行委托数量无效") from exc
            if quantity <= 0:
                raise ValidationError(f"第 {line_no} 行委托数量必须为正数")
            key = (entrust_no, seal_no)
            if key in seen_keys:
                raise ValidationError(
                    f"委托清单中委托编号与封识号组合重复：{entrust_no} / {seal_no or '（无封识）'}"
                )
            seen_keys.add(key)
            if seal_no:
                seal_owners.setdefault(seal_no, set()).add(entrust_no)
            normalized_lines.append({
                "line_no": line_no,
                "entrust_no": entrust_no,
                "seal_no": seal_no,
                "specimen_category": str(raw.get("specimen_category", "")).strip(),
                "expected_quantity": quantity,
                "required_documents": _as_doc_list(raw.get("required_documents")),
                "item_note": str(raw.get("item_note", "")).strip(),
            })
        duplicate_seal_numbers = {seal for seal, owners in seal_owners.items() if len(owners) > 1}

        agency_id = data.get("agency_id")
        if agency_id:
            self.repository.require_agency(int(agency_id))
        source_filename = str(data.get("source_filename", "")).strip()
        source_hash = str(data.get("source_file_hash") or "").strip().lower()
        if not source_hash:
            source_hash = _canonical_hash([source_filename, normalized_lines])

        previous = self.repository.intake_batch_by_hash(source_hash)
        if previous:
            detail = self.repository.intake_batch_detail(int(previous["id"]))
            return {"batch": detail, "replayed": True, "stage": "import_manifest"}

        timestamp = to_storage(self.clock.now())
        batch_no = str(data["batch_no"]).strip().upper()
        try:
            cursor = self.connection.execute(
                "INSERT INTO intake_batches(batch_no,agency_id,case_source,received_on,discipline,status,"
                "source_filename,source_file_hash,manifest_summary_json,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,'','in_review',?,?,?,?,?,?)",
                (
                    batch_no, agency_id, data["case_source"], data["received_on"],
                    source_filename, source_hash,
                    json.dumps({"line_count": len(normalized_lines)}, ensure_ascii=False),
                    data["created_by"], timestamp, timestamp,
                ),
        )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("批次编号或来源文件已经存在") from exc
        batch_id = int(cursor.lastrowid)

        for line in normalized_lines:
            self.connection.execute(
                "INSERT INTO intake_manifest_items(batch_id,line_no,entrust_no,seal_no,specimen_category,"
                "expected_quantity,required_documents_json,item_note,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    batch_id, line["line_no"], line["entrust_no"], line["seal_no"], line["specimen_category"],
                    line["expected_quantity"], json.dumps(line["required_documents"], ensure_ascii=False),
                    line["item_note"], timestamp,
                ),
            )
            codes = [CODE_MISSING]
            if line["seal_no"] in duplicate_seal_numbers:
                codes.append(CODE_DUPLICATE_SEAL)
            initial_snapshot = {"expected": line, "received": None}
            item_cursor = self.connection.execute(
                "INSERT INTO intake_review_items(batch_id,line_no,entrust_no,seal_no,specimen_category,"
                "expected_quantity,expected_documents_json,discrepancy_codes_json,discrepancy_detail_json,"
                "snapshot_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    batch_id, line["line_no"], line["entrust_no"], line["seal_no"], line["specimen_category"],
                    line["expected_quantity"], json.dumps(line["required_documents"], ensure_ascii=False),
                    json.dumps(codes, ensure_ascii=False),
                    json.dumps({"duplicate_entrust_nos": sorted(seal_owners[line["seal_no"]])}, ensure_ascii=False)
                    if line["seal_no"] in duplicate_seal_numbers else json.dumps({}, ensure_ascii=False),
                    json.dumps(initial_snapshot, ensure_ascii=False), timestamp, timestamp,
                ),
            )
            self.connection.execute(
                "INSERT INTO intake_review_snapshots(review_item_id,batch_id,content_version,round_id,"
                "discrepancy_codes_json,snapshot_json,created_at) VALUES(?,?,1,NULL,?,?,?)",
                (
                    int(item_cursor.lastrowid), batch_id, json.dumps(codes, ensure_ascii=False),
                    json.dumps(initial_snapshot, ensure_ascii=False), timestamp,
                ),
            )

        summary = {
            "source_filename": source_filename,
            "source_file_hash": source_hash,
            "line_count": len(normalized_lines),
            "expected_quantity_total": round(sum(line["expected_quantity"] for line in normalized_lines), 6),
            "duplicate_seal_numbers": sorted(duplicate_seal_numbers),
            "required_document_set": sorted({doc for line in normalized_lines for doc in line["required_documents"]}),
        }
        self.connection.execute(
            "UPDATE intake_batches SET manifest_summary_json=? WHERE id=?",
            (json.dumps(summary, ensure_ascii=False, sort_keys=True), batch_id),
        )
        self._append_round(batch_id, 0, data["created_by"], 0, 0, 0, {
            "stage": "import_manifest", **summary,
        }, timestamp)
        return {"batch": self.repository.intake_batch_detail(batch_id), "replayed": False, "stage": "import_manifest"}

    # ------------------------------------------------------------- 实收登记

    def record_packages(self, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        batch = self.repository.require_intake_batch(batch_id)
        if batch["status"] not in RECORDING_STATUSES:
            raise ConflictError("批次已结束登记，不能继续录入封装", context={"status": batch["status"]})
        packages = data.get("packages") or []
        if not packages:
            raise ValidationError("本轮至少登记一个实收封装")

        timestamp = to_storage(self.clock.now())
        actor = data["recorded_by"]
        inserted_rows: list[dict[str, Any]] = []
        replayed_rows: list[dict[str, Any]] = []
        for index, raw in enumerate(packages, start=1):
            scan_key = str(raw.get("scan_key", "")).strip()
            if not scan_key:
                raise ValidationError(f"第 {index} 个封装缺少扫描记录键")
            existing = self.connection.execute(
                "SELECT id FROM intake_actual_packages WHERE batch_id=? AND scan_key=?", (batch_id, scan_key)
            ).fetchone()
            if existing:
                replayed_rows.append({"scan_key": scan_key, "package_id": int(existing[0])})
                continue
            quantity = raw.get("received_quantity")
            if quantity is not None:
                try:
                    quantity = float(quantity)
                except (TypeError, ValueError) as exc:
                    raise ValidationError(f"扫描记录 {scan_key} 的实收数量无效") from exc
                if quantity <= 0:
                    raise ValidationError(f"扫描记录 {scan_key} 的实收数量必须为正数")
            inserted_rows.append({
                "scan_key": scan_key,
                "package_label": str(raw.get("package_label", "")).strip(),
                "entrust_no": str(raw.get("entrust_no", "")).strip(),
                "seal_no": str(raw.get("seal_no", "")).strip().upper(),
                "specimen_category": str(raw.get("specimen_category", "")).strip(),
                "received_quantity": quantity,
                "documents": _as_doc_list(raw.get("documents")),
                "received_by": actor,
            })

        if not inserted_rows:
            latest = records(self.connection.execute(
                "SELECT * FROM intake_rounds WHERE batch_id=? ORDER BY round_no DESC LIMIT 1", (batch_id,)
            ).fetchall())
            return {
                "batch": self.repository.intake_batch_detail(batch_id), "replayed": True,
                "inserted_count": 0, "replayed_count": len(replayed_rows), "round": latest[0] if latest else None,
            }

        next_round = int(self.connection.execute(
            "SELECT COALESCE(MAX(round_no),0)+1 FROM intake_rounds WHERE batch_id=? AND round_no>0", (batch_id,)
        ).fetchone()[0])
        cursor = self._append_round(batch_id, next_round, actor, len(packages), len(inserted_rows), len(replayed_rows), {
            "stage": "record_packages",
            "scan_keys": [row["scan_key"] for row in inserted_rows],
            "replayed_scan_keys": [row["scan_key"] for row in replayed_rows],
        }, timestamp)
        round_id = int(cursor.lastrowid)

        for row in inserted_rows:
            self.connection.execute(
                "INSERT INTO intake_actual_packages(batch_id,round_id,scan_key,package_label,entrust_no,seal_no,"
                "specimen_category,received_quantity,documents_json,received_by,received_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    batch_id, round_id, row["scan_key"], row["package_label"], row["entrust_no"], row["seal_no"],
                    row["specimen_category"], row["received_quantity"],
                    json.dumps(row["documents"], ensure_ascii=False), row["received_by"], timestamp,
                ),
            )

        matched, unmatched = self._rebuild_review(batch_id, round_id, timestamp)
        self.connection.execute(
            "UPDATE intake_rounds SET summary_json=? WHERE id=?",
            (json.dumps({
                "stage": "record_packages",
                "scan_keys": [row["scan_key"] for row in inserted_rows],
                "replayed_scan_keys": [row["scan_key"] for row in replayed_rows],
                "matched_line_nos": matched,
                "unmatched_scan_keys": unmatched,
            }, ensure_ascii=False), round_id),
        )
        self.connection.execute("UPDATE intake_batches SET updated_at=? WHERE id=?", (timestamp, batch_id))
        return {
            "batch": self.repository.intake_batch_detail(batch_id), "replayed": False,
            "round": record(self.connection.execute("SELECT * FROM intake_rounds WHERE id=?", (round_id,)).fetchone()),
            "inserted_count": len(inserted_rows), "replayed_count": len(replayed_rows),
            "matched_line_nos": matched, "unmatched_scan_keys": unmatched,
        }

    def _rebuild_review(self, batch_id: int, round_id: int, timestamp: str) -> tuple[list[int], list[str]]:
        """按委托编号+封识号把全部实收封装归并到复核单项，重算差异与快照。"""
        manifest_rows = records(self.connection.execute(
            "SELECT * FROM intake_manifest_items WHERE batch_id=? ORDER BY line_no", (batch_id,)
        ).fetchall())
        packages = records(self.connection.execute(
            "SELECT * FROM intake_actual_packages WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall())

        matched_lines: set[int] = set()
        unmatched_keys: list[str] = []
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for package in packages:
            key = (package["entrust_no"], package["seal_no"])
            grouped.setdefault(key, []).append(package)

        # 重复封识：同一非空封识号跨不同委托编号出现（同编号分次补件属合法累加）
        seal_owners: dict[str, set[str]] = {}
        for line in manifest_rows:
            if line["seal_no"]:
                seal_owners.setdefault(line["seal_no"], set()).add(line["entrust_no"])
        for package in packages:
            if package["seal_no"]:
                seal_owners.setdefault(package["seal_no"], set()).add(package["entrust_no"])
        duplicate_seals = {seal for seal, owners in seal_owners.items() if len(owners) > 1}

        for line in manifest_rows:
            key = (line["entrust_no"], line["seal_no"])
            line_packages = grouped.get(key, [])
            if line_packages:
                matched_lines.add(int(line["line_no"]))
            self._apply_review_snapshot(batch_id, int(line["line_no"]), line, line_packages, duplicate_seals, round_id, timestamp)

        # 无委托项：找不到任何清单行的封装，生成可退回的伪复核单项
        manifest_index = {(line["entrust_no"], line["seal_no"]): line for line in manifest_rows}
        for key, line_packages in grouped.items():
            if key in manifest_index:
                continue
            entrust_no, seal_no = line_packages[0]["entrust_no"], line_packages[0]["seal_no"]
            unmatched_keys.extend(package["scan_key"] for package in line_packages)
            pseudo_line = UNMATCHED_LINE_BASE + int(line_packages[0]["id"])
            existing = self.connection.execute(
                "SELECT * FROM intake_review_items WHERE batch_id=? AND line_no=?", (batch_id, pseudo_line)
            ).fetchone()
            snapshot = {
                "expected": None,
                "unmatched": True,
                "received": {
                    "package_count": len(line_packages),
                    "categories": sorted({p["specimen_category"] for p in line_packages if p["specimen_category"]}),
                    "scan_keys": [p["scan_key"] for p in line_packages],
                },
            }
            if not existing:
                self.connection.execute(
                    "INSERT INTO intake_review_items(batch_id,line_no,entrust_no,seal_no,specimen_category,"
                    "expected_quantity,expected_documents_json,discrepancy_codes_json,discrepancy_detail_json,"
                    "snapshot_json,created_at,updated_at) VALUES(?,?,?,?,?,NULL,'[]',?,?,?,?,?)",
                    (
                        batch_id, pseudo_line, entrust_no, seal_no, line_packages[0]["specimen_category"],
                        json.dumps([CODE_UNEXPECTED], ensure_ascii=False),
                        json.dumps({"scan_keys": [p["scan_key"] for p in line_packages]}, ensure_ascii=False),
                        json.dumps(snapshot, ensure_ascii=False, sort_keys=True), timestamp, timestamp,
                    ),
                )
            elif existing["status"] not in {"accepted", "returned"}:
                self.connection.execute(
                    "UPDATE intake_review_items SET seal_no=?,specimen_category=?,discrepancy_detail_json=?,"
                    "snapshot_json=?,content_version=content_version+1,updated_at=? WHERE id=?",
                    (
                        seal_no, line_packages[0]["specimen_category"],
                        json.dumps({"scan_keys": [p["scan_key"] for p in line_packages]}, ensure_ascii=False),
                        json.dumps(snapshot, ensure_ascii=False, sort_keys=True), timestamp, existing["id"],
                    ),
                )
        return sorted(matched_lines), unmatched_keys

    def _apply_review_snapshot(
        self,
        batch_id: int,
        line_no: int,
        line: dict[str, Any],
        line_packages: list[dict[str, Any]],
        duplicate_seals: set[str],
        round_id: int,
        timestamp: str,
    ) -> None:
        item = record(self.connection.execute(
            "SELECT * FROM intake_review_items WHERE batch_id=? AND line_no=?", (batch_id, line_no)
        ).fetchone())
        if item is None:
            raise NotFoundError(f"复核单项缺失：行 {line_no}")
        # 已作接收/退回终局结论的单项不被新一轮扫描改写，只在快照历史中留痕
        locked = item["status"] in {"accepted", "returned"}
        codes: list[str] = []
        detail: dict[str, Any] = {}
        quantities = [p["received_quantity"] for p in line_packages if p["received_quantity"] is not None]
        unknown_quantity = bool(line_packages) and len(quantities) != len(line_packages)
        received_quantity = round(sum(quantities), 6) if quantities else None
        received_documents = sorted({doc for p in line_packages for doc in p["documents"]})
        categories = {p["specimen_category"] for p in line_packages if p["specimen_category"]}

        if not line_packages:
            codes.append(CODE_MISSING)
        else:
            if unknown_quantity:
                codes.append(CODE_QUANTITY_UNKNOWN)
            elif received_quantity is not None and abs(received_quantity - float(line["expected_quantity"])) > 1e-6:
                codes.append(CODE_QUANTITY)
                detail["expected_quantity"] = line["expected_quantity"]
                detail["received_quantity"] = received_quantity
            if line["specimen_category"] and categories and line["specimen_category"] not in categories:
                codes.append(CODE_CATEGORY)
                detail["expected_category"] = line["specimen_category"]
                detail["received_categories"] = sorted(categories)
            missing_docs = [doc for doc in line["required_documents"] if doc not in received_documents]
            if missing_docs:
                codes.append(CODE_DOCUMENT)
                detail["missing_documents"] = missing_docs
        if line["seal_no"] and line["seal_no"] in duplicate_seals:
            codes.append(CODE_DUPLICATE_SEAL)

        snapshot = {
            "expected": {
                "entrust_no": line["entrust_no"], "seal_no": line["seal_no"],
                "category": line["specimen_category"], "quantity": line["expected_quantity"],
                "documents": line["required_documents"],
            },
            "received": {
                "package_count": len(line_packages), "quantity": received_quantity,
                "documents": received_documents, "categories": sorted(categories),
                "scan_keys": [p["scan_key"] for p in line_packages],
            },
        }
        new_content_version = int(item["content_version"]) + 1
        self.connection.execute(
            "INSERT INTO intake_review_snapshots(review_item_id,batch_id,content_version,round_id,"
            "discrepancy_codes_json,snapshot_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                item["id"], batch_id, new_content_version, round_id,
                json.dumps(codes, ensure_ascii=False), json.dumps(snapshot, ensure_ascii=False, sort_keys=True), timestamp,
            ),
        )
        if locked:
            return
        self.connection.execute(
            "UPDATE intake_review_items SET received_quantity=?,received_documents_json=?,discrepancy_codes_json=?,"
            "discrepancy_detail_json=?,snapshot_json=?,content_version=?,updated_at=? WHERE id=?",
            (
                received_quantity, json.dumps(received_documents, ensure_ascii=False),
                json.dumps(codes, ensure_ascii=False), json.dumps(detail, ensure_ascii=False, sort_keys=True),
                json.dumps(snapshot, ensure_ascii=False, sort_keys=True), new_content_version, timestamp, item["id"],
            ),
        )

    def _snapshot_all(self, batch_id: int, round_id: int | None, timestamp: str) -> None:
        manifest_rows = records(self.connection.execute(
            "SELECT * FROM intake_manifest_items WHERE batch_id=? ORDER BY line_no", (batch_id,)
        ).fetchall())
        packages = records(self.connection.execute(
            "SELECT * FROM intake_actual_packages WHERE batch_id=?", (batch_id,)
        ).fetchall())
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for package in packages:
            grouped.setdefault((package["entrust_no"], package["seal_no"]), []).append(package)
        seal_owners: dict[str, set[str]] = {}
        for line in manifest_rows:
            if line["seal_no"]:
                seal_owners.setdefault(line["seal_no"], set()).add(line["entrust_no"])
        for package in packages:
            if package["seal_no"]:
                seal_owners.setdefault(package["seal_no"], set()).add(package["entrust_no"])
        duplicate_seals = {seal for seal, owners in seal_owners.items() if len(owners) > 1}
        for line in manifest_rows:
            self._apply_review_snapshot(
                batch_id, int(line["line_no"]), line,
                grouped.get((line["entrust_no"], line["seal_no"]), []), duplicate_seals, round_id, timestamp,
            )

    # ----------------------------------------------------------------- 复核

    def list_review_items(self, batch_id: int, status: str | None = None) -> dict[str, Any]:
        self.repository.require_intake_batch(batch_id)
        sql = "SELECT * FROM intake_review_items WHERE batch_id=?"
        params: list[Any] = [batch_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY line_no,id"
        items = records(self.connection.execute(sql, params).fetchall())
        return {"batch_id": batch_id, "items": items, "total": len(items)}

    def decide_item(self, review_item_id: int, data: dict[str, Any]) -> dict[str, Any]:
        item = self.repository.require_review_item(review_item_id)
        batch = self.repository.require_intake_batch(int(item["batch_id"]))
        if batch["status"] not in RECORDING_STATUSES:
            raise ConflictError("批次已终局，复核结论不能再变更", context={"status": batch["status"]})
        decision = str(data["decision"])
        if decision not in DECISIONS:
            raise ValidationError("复核决定必须是 accepted、pending_correction 或 returned")
        expected_version = int(data["expected_version"])
        if int(item["version"]) != expected_version:
            if item["decision_by"] and item["decision_by"] != data["actor"]:
                message = "版本已过期，不能覆盖另一位复核人的结论"
            else:
                message = "复核单项版本冲突"
            raise ConflictError(message, context={
                "current_version": item["version"], "decided_by": item["decision_by"],
            })
        reason = str(data.get("reason", "")).strip()
        if decision in {"pending_correction", "returned"} and not reason:
            raise ValidationError("暂存待补正或退回单项时必须填写理由")
        if decision == "accepted" and item["discrepancy_codes"]:
            raise ConflictError("该单项仍有未消除差异，不能接收入账", context={
                "discrepancy_codes": item["discrepancy_codes"],
            })
        return self._apply_decision(item, decision, data["actor"], reason, expected_version)

    def _apply_decision(
        self, item: dict[str, Any], decision: str, actor: str, reason: str, expected_version: int
    ) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE intake_review_items SET status=?,decision_by=?,decision_at=?,decision_reason=?,"
            "decided_version=version+1,version=version+1,updated_at=? WHERE id=? AND version=?",
            (decision, actor, timestamp, reason, timestamp, item["id"], expected_version),
        )
        if cursor.rowcount != 1:
            current = self.repository.require_review_item(int(item["id"]))
            raise ConflictError("版本已过期，不能覆盖另一位复核人的结论", context={
                "current_version": current["version"], "decided_by": current["decision_by"],
            })
        new_version = expected_version + 1
        self.connection.execute(
            "INSERT INTO intake_decision_logs(batch_id,review_item_id,from_status,to_status,actor,reason,"
            "expected_version,new_version,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (item["batch_id"], item["id"], item["status"], decision, actor, reason, expected_version, new_version, timestamp),
        )
        if decision == "returned":
            self.connection.execute(
                "INSERT INTO batch_return_records(batch_id,review_item_id,entrust_no,seal_no,specimen_category,"
                "quantity,reason,returned_by,returned_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(review_item_id) DO UPDATE SET reason=excluded.reason,returned_by=excluded.returned_by,"
                "returned_at=excluded.returned_at",
                (
                    item["batch_id"], item["id"], item["entrust_no"], item["seal_no"], item["specimen_category"],
                    item["received_quantity"], reason, actor, timestamp,
                ),
            )
        elif decision != "returned":
            self.connection.execute("DELETE FROM batch_return_records WHERE review_item_id=?", (item["id"],))
        return self.repository.review_item_detail(int(item["id"]))

    def decide_uncontested(self, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        """对无争议项（待决定且零差异）批量给出同一决定，已被他人决定的单项绝不覆盖。"""
        batch = self.repository.require_intake_batch(batch_id)
        if batch["status"] not in RECORDING_STATUSES:
            raise ConflictError("批次已结束，不能继续复核", context={"status": batch["status"]})
        decision = str(data["decision"])
        if decision not in {"accepted", "returned"}:
            raise ValidationError("批量决定仅支持接收或退回")
        reason = str(data.get("reason", "")).strip()
        if decision == "returned" and not reason:
            raise ValidationError("批量退回时必须填写理由")
        timestamp = to_storage(self.clock.now())
        rows = self.connection.execute(
            "SELECT * FROM intake_review_items WHERE batch_id=? AND status='pending' AND discrepancy_codes_json='[]' "
            "ORDER BY line_no,id",
            (batch_id,),
        ).fetchall()
        applied: list[int] = []
        for row in rows:
            item = record(row) or {}
            # 条件更新保证并发下不会覆盖另一位复核人刚刚写下的结论
            updated = self.connection.execute(
                "UPDATE intake_review_items SET status=?,decision_by=?,decision_at=?,decision_reason=?,"
                "decided_version=version+1,version=version+1,updated_at=? WHERE id=? AND status='pending' "
                "AND discrepancy_codes_json='[]' AND version=?",
                (decision, data["actor"], timestamp, reason, timestamp, item["id"], item["version"]),
            )
            if updated.rowcount != 1:
                continue
            new_version = int(item["version"]) + 1
            self.connection.execute(
                "INSERT INTO intake_decision_logs(batch_id,review_item_id,from_status,to_status,actor,reason,"
                "expected_version,new_version,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    batch_id, item["id"], "pending", decision, data["actor"], reason,
                    item["version"], new_version, timestamp,
                ),
            )
            if decision == "returned":
                self.connection.execute(
                    "INSERT INTO batch_return_records(batch_id,review_item_id,entrust_no,seal_no,specimen_category,"
                    "quantity,reason,returned_by,returned_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch_id, item["id"], item["entrust_no"], item["seal_no"], item["specimen_category"],
                        item["received_quantity"], reason, data["actor"], timestamp,
                    ),
                )
            applied.append(int(item["id"]))
        return {
            "batch_id": batch_id, "decision": decision, "applied_item_ids": applied,
            "applied_count": len(applied), "actor": data["actor"],
        }

    # ----------------------------------------------------------------- 补正

    def submit_correction(self, review_item_id: int, data: dict[str, Any]) -> dict[str, Any]:
        item = self.repository.require_review_item(review_item_id)
        if item["status"] != "pending_correction":
            raise ConflictError("只有暂存待补正的单项可以提交补正", context={"status": item["status"]})
        batch_id = int(item["batch_id"])
        batch = self.repository.require_intake_batch(batch_id)
        if batch["status"] not in RECORDING_STATUSES:
            raise ConflictError("批次已结束，不能补正")
        timestamp = to_storage(self.clock.now())
        actor = data["submitted_by"]

        packages = data.get("packages") or []
        document_additions = _as_doc_list(data.get("document_additions"))
        round_id: int | None = None
        inserted_scan: list[str] = []
        if packages or document_additions:
            next_round = int(self.connection.execute(
                "SELECT COALESCE(MAX(round_no),0)+1 FROM intake_rounds WHERE batch_id=? AND round_no>0", (batch_id,)
            ).fetchone()[0])
            cursor = self._append_round(batch_id, next_round, actor, len(packages), 0, 0, {
                "stage": "correction", "review_item_id": review_item_id,
                "document_additions": document_additions,
            }, timestamp)
            round_id = int(cursor.lastrowid)
            inserted = 0
            replayed = 0
            for raw in packages:
                scan_key = str(raw.get("scan_key", "")).strip()
                if not scan_key:
                    raise ValidationError("补正封装缺少扫描记录键")
                quantity = raw.get("received_quantity")
                if quantity is not None:
                    quantity = float(quantity)
                existing = self.connection.execute(
                    "SELECT id FROM intake_actual_packages WHERE batch_id=? AND scan_key=?", (batch_id, scan_key)
                ).fetchone()
                if existing:
                    replayed += 1
                    continue
                self.connection.execute(
                    "INSERT INTO intake_actual_packages(batch_id,round_id,scan_key,package_label,entrust_no,seal_no,"
                    "specimen_category,received_quantity,documents_json,received_by,received_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        batch_id, round_id, scan_key, str(raw.get("package_label", "")).strip(),
                        str(raw.get("entrust_no", item["entrust_no"])).strip(),
                        str(raw.get("seal_no", item["seal_no"])).strip().upper(),
                        str(raw.get("specimen_category", "")).strip(), quantity,
                        json.dumps(_as_doc_list(raw.get("documents")), ensure_ascii=False), actor, timestamp,
                    ),
                )
                inserted += 1
                inserted_scan.append(scan_key)
            # 行级补交文书：并集写入该委托项名下全部已登记封装
            if document_additions:
                existing_packages = records(self.connection.execute(
                    "SELECT * FROM intake_actual_packages WHERE batch_id=? AND entrust_no=? AND seal_no=?",
                    (batch_id, item["entrust_no"], item["seal_no"]),
                ).fetchall())
                if not existing_packages:
                    raise ConflictError("该单项尚无实收封装，缺件项必须补寄实物后才能补交文书")
                for package in existing_packages:
                    merged = sorted(set(package["documents"]) | set(document_additions))
                    self.connection.execute(
                        "UPDATE intake_actual_packages SET documents_json=? WHERE id=?",
                        (json.dumps(merged, ensure_ascii=False), package["id"]),
                    )
            self.connection.execute(
                "UPDATE intake_rounds SET inserted_count=?,replayed_count=?,summary_json=? WHERE id=?",
                (inserted, replayed, json.dumps({
                    "stage": "correction", "review_item_id": review_item_id,
                    "inserted_scan_keys": inserted_scan,
                    "document_additions": document_additions,
                }, ensure_ascii=False), round_id),
            )

        correction_no = int(self.connection.execute(
            "SELECT COALESCE(MAX(correction_no),0)+1 FROM intake_corrections WHERE review_item_id=?", (review_item_id,)
        ).fetchone()[0])
        self.connection.execute(
            "INSERT INTO intake_corrections(batch_id,review_item_id,round_id,correction_no,payload_json,note,"
            "submitted_by,submitted_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                batch_id, review_item_id, round_id, correction_no,
                json.dumps(data.get("payload", {}), ensure_ascii=False, sort_keys=True),
                str(data.get("note", "")).strip(), actor, timestamp,
            ),
        )
        self._snapshot_all(batch_id, round_id, timestamp)
        refreshed = self.repository.require_review_item(review_item_id)
        # 差异已消除则回到待决定队列，由复核人重新裁决；版本号不变，沿用复核链路
        if not refreshed["discrepancy_codes"]:
            self.connection.execute(
                "UPDATE intake_review_items SET status='pending',updated_at=? WHERE id=? AND status='pending_correction'",
                (timestamp, review_item_id),
            )
            self.connection.execute(
                "INSERT INTO intake_decision_logs(batch_id,review_item_id,from_status,to_status,actor,reason,"
                "expected_version,new_version,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    batch_id, review_item_id, "pending_correction", "pending", actor,
                    f"补正第 {correction_no} 轮，差异已消除", refreshed["version"], refreshed["version"], timestamp,
                ),
            )
        self.connection.execute("UPDATE intake_batches SET updated_at=? WHERE id=?", (timestamp, batch_id))
        return self.repository.review_item_detail(review_item_id)

    # ------------------------------------------------------- 原子立案与汇总

    def confirm_batch(self, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        batch = self.repository.require_intake_batch(batch_id)
        if batch["status"] == "confirmed":
            return self.reconciliation(batch_id) | {"replayed": True}
        if batch["status"] not in RECORDING_STATUSES:
            raise ConflictError("批次当前状态不能确认立案", context={"status": batch["status"]})
        if int(batch["version"]) != int(data["expected_version"]):
            raise ConflictError("批次版本冲突", context={"current_version": batch["version"]})

        items = records(self.connection.execute(
            "SELECT * FROM intake_review_items WHERE batch_id=? ORDER BY line_no,id", (batch_id,)
        ).fetchall())
        pending = [item for item in items if item["status"] in {"pending", "pending_correction"}]
        if pending:
            raise ConflictError("仍有单项未完成复核，不能确认立案", context={
                "pending_item_ids": [item["id"] for item in pending],
            })
        accepted = [item for item in items if item["status"] == "accepted"]
        returned = [item for item in items if item["status"] == "returned"]
        if not accepted:
            raise ConflictError("没有接收项，不能生成正式案件")
        for item in accepted:
            if item["discrepancy_codes"]:
                raise ConflictError("接收项仍带差异，不能立案", context={"review_item_id": item["id"]})
            if item["received_quantity"] is None or float(item["received_quantity"]) <= 0:
                raise ConflictError("接收项缺少有效实收数量", context={"review_item_id": item["id"]})

        timestamp = to_storage(self.clock.now())
        actor = data["confirmed_by"]
        case_service = ForensicCaseService(self.connection, self.clock)
        custody = CustodyService(self.connection, self.clock)

        case_no = str(data["case_no"]).strip().upper()
        case_name = str(data["case_name"]).strip()
        if not case_name:
            raise ValidationError("确认立案时必须提供案件名称")
        accepted_on = str(data.get("accepted_on") or batch["received_on"])
        passport = {
            "generated_from_intake_batch": batch["batch_no"],
            "intake_batch_id": batch_id,
            "manifest_summary": batch.get("manifest_summary", {}),
            "accepted_review_item_ids": [item["id"] for item in accepted],
            "returned_review_item_ids": [item["id"] for item in returned],
        }
        passport.update(data.get("passport") or {})
        forensic_case = case_service.create_forensic_case({
            "case_no": case_no,
            "case_name": case_name,
            "discipline": str(data.get("discipline") or batch.get("discipline") or "法医物证").strip(),
            "entrusted_matter": str(data.get("entrusted_matter", "")).strip(),
            "agency_id": batch.get("agency_id"),
            "case_source": batch["case_source"],
            "accepted_on": accepted_on,
            "passport": passport,
            "created_by": actor,
        })
        forensic_case = case_service.transition(forensic_case["id"], {
            "target_status": "accepted",
            "reason": f"批次 {batch['batch_no']} 受理复核完成，{len(accepted)} 项接收、{len(returned)} 项退回",
            "expected_version": forensic_case["version"],
            "actor": actor,
        })
        self.connection.execute(
            "UPDATE forensic_cases SET intake_batch_id=? WHERE id=?", (batch_id, forensic_case["id"])
        )

        specimen_overrides = {
            int(entry["review_item_id"]): entry for entry in data.get("specimen_overrides", [])
        }
        generated_specimens: list[dict[str, Any]] = []
        for item in accepted:
            override = specimen_overrides.get(int(item["id"]), {})
            specimen_no = str(override.get("specimen_no") or f"{case_no}-L{int(item['line_no']):03d}").strip().upper()
            packages = records(self.connection.execute(
                "SELECT * FROM intake_actual_packages WHERE batch_id=? AND entrust_no=? AND seal_no=? ORDER BY id",
                (batch_id, item["entrust_no"], item["seal_no"]),
            ).fetchall())
            sealed_on = next((p["received_at"][:10] for p in packages if p.get("received_at")), None)
            packaging = "；".join(dict.fromkeys(
                p["package_label"] for p in packages if p.get("package_label")
            ))
            specimen = custody.create_specimen({
                "specimen_no": specimen_no,
                "case_id": forensic_case["id"],
                "parent_specimen_id": None,
                "received_year": int(accepted_on[:4]),
                "initial_quantity": float(item["received_quantity"]),
                "integrity_percent": override.get("integrity_percent", 100),
                "packaging": packaging,
                "sealed_on": sealed_on,
                "created_by": actor,
            })
            self.connection.execute(
                "UPDATE specimens SET intake_batch_id=?,intake_review_item_id=? WHERE id=?",
                (batch_id, item["id"], specimen["id"]),
            )
            generated_specimens.append({
                "review_item_id": item["id"], "specimen_id": specimen["id"], "specimen_no": specimen_no,
                "quantity": float(item["received_quantity"]),
            })

        updated = self.connection.execute(
            "UPDATE intake_batches SET status='confirmed',confirmed_at=?,confirmed_by=?,generated_case_id=?,"
            "version=version+1,updated_at=? WHERE id=? AND version=? AND status!='confirmed'",
            (timestamp, actor, forensic_case["id"], timestamp, batch_id, data["expected_version"]),
        )
        if updated.rowcount != 1:
            raise ConflictError("批次已被其他人确认或版本已过期")

        result = self.reconciliation(batch_id)
        result["replayed"] = False
        return result

    def reconciliation(self, batch_id: int) -> dict[str, Any]:
        """受理汇总：与案件档案、保管记录、退回清单逐件核对。"""
        batch = self.repository.intake_batch_detail(batch_id)
        items = records(self.connection.execute(
            "SELECT * FROM intake_review_items WHERE batch_id=? ORDER BY line_no,id", (batch_id,)
        ).fetchall())
        accepted = [item for item in items if item["status"] == "accepted"]
        returned = [item for item in items if item["status"] == "returned"]
        pending = [item for item in items if item["status"] in {"pending", "pending_correction"}]
        returns = records(self.connection.execute(
            "SELECT * FROM batch_return_records WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall())
        unique_packages = int(self.connection.execute(
            "SELECT COUNT(*) FROM intake_actual_packages WHERE batch_id=?", (batch_id,)
        ).fetchone()[0])
        manifest_lines = int(self.connection.execute(
            "SELECT COUNT(*) FROM intake_manifest_items WHERE batch_id=?", (batch_id,)
        ).fetchone()[0])

        specimens: list[dict[str, Any]] = []
        case_check: dict[str, Any] = {"exists": False}
        if batch.get("generated_case_id"):
            forensic_case = record(self.connection.execute(
                "SELECT * FROM forensic_cases WHERE id=?", (batch["generated_case_id"],)
            ).fetchone())
            if forensic_case:
                case_check = {
                    "exists": True, "case_id": forensic_case["id"], "case_no": forensic_case["case_no"],
                    "status": forensic_case["status"], "intake_batch_id": forensic_case.get("intake_batch_id"),
                    "status_is_accepted": forensic_case["status"] == "accepted",
                }
            specimens = records(self.connection.execute(
                "SELECT * FROM specimens WHERE intake_batch_id=? ORDER BY id", (batch_id,)
            ).fetchall())

        custody_rows = records(self.connection.execute(
            "SELECT e.id,e.specimen_id,e.movement_type,e.quantity,s.intake_review_item_id "
            "FROM custody_events e JOIN specimens s ON s.id=e.specimen_id WHERE s.intake_batch_id=? ORDER BY e.id",
            (batch_id,),
        ).fetchall())
        accepted_quantity = round(sum(float(item["received_quantity"] or 0) for item in accepted), 6)
        returned_quantity = round(sum(float(item["received_quantity"] or 0) for item in returned), 6)
        specimen_quantity = round(sum(float(s["initial_quantity"]) for s in specimens), 6)
        accepted_ids = {item["id"] for item in accepted}
        returned_ids = {item["id"] for item in returned}
        specimen_item_ids = {int(s["intake_review_item_id"]) for s in specimens if s.get("intake_review_item_id")}
        ledger_item_ids = {int(row["intake_review_item_id"]) for row in custody_rows if row["intake_review_item_id"]}

        checks = {
            "case_matches_batch": case_check["exists"] and case_check.get("intake_batch_id") == batch_id,
            "case_status_accepted": case_check.get("status_is_accepted", False),
            "accepted_items_have_specimen": accepted_ids == specimen_item_ids,
            "accepted_quantity_matches_specimen": abs(accepted_quantity - specimen_quantity) < 1e-6,
            "returned_items_have_no_specimen": returned_ids.isdisjoint(specimen_item_ids),
            "custody_ledger_only_covers_accepted": ledger_item_ids <= accepted_ids,
            "return_list_matches_returned": {r["review_item_id"] for r in returns} == returned_ids,
            "all_items_decided": not pending,
        }
        return {
            "batch": batch,
            "summary": {
                "status": batch["status"],
                "manifest_lines": manifest_lines,
                "review_items": len(items),
                "unique_packages_recorded": unique_packages,
                "accepted_count": len(accepted),
                "returned_count": len(returned),
                "pending_count": len(pending),
                "accepted_quantity": accepted_quantity,
                "returned_quantity": returned_quantity,
                "specimen_count": len(specimens),
                "specimen_quantity_total": specimen_quantity,
                "return_record_count": len(returns),
            },
            "case": case_check,
            "accepted_items": [
                {
                    "review_item_id": item["id"], "line_no": item["line_no"], "entrust_no": item["entrust_no"],
                    "seal_no": item["seal_no"], "category": item["specimen_category"],
                    "received_quantity": item["received_quantity"], "decision_by": item["decision_by"],
                }
                for item in accepted
            ],
            "specimens": [
                {"specimen_id": s["id"], "specimen_no": s["specimen_no"], "case_id": s["case_id"],
                 "review_item_id": s["intake_review_item_id"], "initial_quantity": s["initial_quantity"],
                 "available_quantity": s["available_quantity"], "status": s["status"]}
                for s in specimens
            ],
            "returned_items": returns,
            "reconciliation_checks": checks,
            "all_checks_passed": all(checks.values()) if batch["status"] == "confirmed" else False,
        }

    # ------------------------------------------------------------------ 工具

    def _append_round(
        self,
        batch_id: int,
        round_no: int,
        actor: str,
        package_count: int,
        inserted_count: int,
        replayed_count: int,
        summary: dict[str, Any],
        timestamp: str,
    ):
        return self.connection.execute(
            "INSERT INTO intake_rounds(batch_id,round_no,recorded_by,package_count,inserted_count,replayed_count,"
            "summary_json,recorded_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                batch_id, round_no, actor, package_count, inserted_count, replayed_count,
                json.dumps(summary, ensure_ascii=False, sort_keys=True), timestamp,
            ),
        )
