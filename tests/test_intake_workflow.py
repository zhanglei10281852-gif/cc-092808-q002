from __future__ import annotations

import pytest

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.database import transaction
from app.forensics.service import ForensicService


def create_agency(service: ForensicService, suffix: str = "001") -> dict:
    return service.forensic_cases.create_agency({
        "agency_code": f"INTAKE-ORG-{suffix}", "agency_name": "刑侦支队物证中心", "jurisdiction_code": "CN",
        "contact_address": "刑侦路 1 号", "licensed_on": "2025-01-01", "accreditation_no": None, "restrictions": {},
    })


def manifest_payload(suffix: str = "001", **overrides) -> dict:
    payload = {
        "batch_no": f"BATCH-{suffix}",
        "case_source": "委托",
        "received_on": "2026-09-21",
        "source_filename": f"entrust-{suffix}.xlsx",
        "created_by": "登记员甲",
        "lines": [
            {
                "line_no": 1, "entrust_no": f"WT-{suffix}-01", "seal_no": f"SEAL-{suffix}-01",
                "specimen_category": "血样", "expected_quantity": 3,
                "required_documents": ["委托函", "封装清单"],
            },
            {
                "line_no": 2, "entrust_no": f"WT-{suffix}-02", "seal_no": f"SEAL-{suffix}-02",
                "specimen_category": "毛发", "expected_quantity": 2,
                "required_documents": ["委托函"],
            },
            {
                "line_no": 3, "entrust_no": f"WT-{suffix}-03", "seal_no": f"SEAL-{suffix}-03",
                "specimen_category": "织物", "expected_quantity": 1,
                "required_documents": ["委托函", "封装清单"],
            },
        ],
    }
    payload.update(overrides)
    return payload


def code_map(service: ForensicService, batch_id: int) -> dict[int, list[str]]:
    listing = service.intake.list_review_items(batch_id)
    return {item["line_no"]: item["discrepancy_codes"] for item in listing["items"]}


def item_by_line(service: ForensicService, batch_id: int, line_no: int) -> dict:
    for item in service.intake.list_review_items(batch_id)["items"]:
        if item["line_no"] == line_no:
            return item
    raise KeyError(line_no)


def test_manifest_import_marks_all_lines_missing_and_replay_is_idempotent(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service)
        payload = manifest_payload(agency_id=agency["id"])
        first = service.intake.import_manifest(payload)
        assert first["replayed"] is False
        batch_id = first["batch"]["id"]
        assert first["batch"]["manifest_item_count"] == 3
        assert code_map(service, batch_id) == {1: ["package_missing"], 2: ["package_missing"], 3: ["package_missing"]}

        # 同一来源文件（相同内容哈希）重传不复制数据
        second = service.intake.import_manifest(payload)
        assert second["replayed"] is True
        assert second["batch"]["id"] == batch_id
        listing = service.intake.list_review_items(batch_id)
        assert len(listing["items"]) == 3
        rounds = connection.execute("SELECT COUNT(*) FROM intake_rounds WHERE batch_id=?", (batch_id,)).fetchone()[0]
        assert rounds == 1  # 重传不再生成导入轮次


def test_manifest_duplicate_seal_in_list_is_flagged(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        payload = manifest_payload("DUP")
        payload["lines"][1]["seal_no"] = "SEAL-DUP-01"
        payload["lines"][2]["seal_no"] = "SEAL-DUP-01"
        result = service.intake.import_manifest(payload)
        codes = code_map(service, result["batch"]["id"])
        assert "duplicate_seal" in codes[2]
        assert "duplicate_seal" in codes[3]


def test_split_round_recording_builds_itemized_discrepancies_and_scan_replay(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service)
        batch_id = service.intake.import_manifest(manifest_payload(agency_id=agency["id"]))["batch"]["id"]

        # 第一轮：第 1 项齐全；第 2 项数量不符、类别不符且缺文书；第 3 项仍缺件
        first = service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "scan-01", "entrust_no": "WT-001-01", "seal_no": "SEAL-001-01",
                 "specimen_category": "血样", "received_quantity": 3, "documents": ["委托函", "封装清单"]},
                {"scan_key": "scan-02", "entrust_no": "WT-001-02", "seal_no": "SEAL-001-02",
                 "specimen_category": "烟蒂", "received_quantity": 1, "documents": []},
            ],
        })
        assert first["inserted_count"] == 2
        codes = code_map(service, batch_id)
        assert codes[1] == []
        assert set(codes[2]) == {"quantity_mismatch", "category_mismatch", "missing_document"}
        assert codes[3] == ["package_missing"]

        # 同一扫描记录重传：不复制封装、不再开新轮次
        replay = service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "scan-01", "entrust_no": "WT-001-01", "seal_no": "SEAL-001-01",
                 "specimen_category": "血样", "received_quantity": 3, "documents": ["委托函", "封装清单"]},
            ],
        })
        assert replay["replayed"] is True
        assert replay["inserted_count"] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM intake_actual_packages WHERE batch_id=?", (batch_id,)
        ).fetchone()[0] == 2

        # 第二轮：补齐第 2 项数量/类别/文书，第 3 项依然缺件
        second = service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "scan-03", "entrust_no": "WT-001-02", "seal_no": "SEAL-001-02",
                 "specimen_category": "毛发", "received_quantity": 1, "documents": ["委托函"]},
            ],
        })
        assert second["inserted_count"] == 1
        item2 = item_by_line(service, batch_id, 2)
        assert item2["discrepancy_codes"] == []
        assert item2["received_quantity"] == 2  # 两轮数量累加
        assert item2["content_version"] >= 3
        history = connection.execute(
            "SELECT content_version FROM intake_review_snapshots WHERE review_item_id=? ORDER BY content_version",
            (item2["id"],),
        ).fetchall()
        assert [row[0] for row in history] == list(range(1, len(history) + 1))


def test_unexpected_package_and_duplicate_seal_become_returnable_items(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service)
        batch_id = service.intake.import_manifest(manifest_payload(agency_id=agency["id"]))["batch"]["id"]
        service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "scan-11", "entrust_no": "WT-001-01", "seal_no": "SEAL-001-01",
                 "specimen_category": "血样", "received_quantity": 3, "documents": ["委托函", "封装清单"]},
                {"scan_key": "scan-12", "entrust_no": "WT-001-02", "seal_no": "SEAL-001-02",
                 "specimen_category": "毛发", "received_quantity": 2, "documents": ["委托函"]},
                {"scan_key": "scan-13", "entrust_no": "WT-001-03", "seal_no": "SEAL-001-03",
                 "specimen_category": "织物", "received_quantity": 1, "documents": ["委托函", "封装清单"]},
                # 封识号 SEAL-001-03 又出现在另一个委托编号下（重复封识）
                {"scan_key": "scan-14", "entrust_no": "WT-001-09", "seal_no": "SEAL-001-03",
                 "specimen_category": "织物", "received_quantity": 1, "documents": ["委托函", "封装清单"]},
                # 无委托项
                {"scan_key": "scan-99", "entrust_no": "WT-001-XX", "seal_no": "SEAL-UNKNOWN",
                 "specimen_category": "不明粉末", "received_quantity": 1, "documents": []},
            ],
        })
        codes = code_map(service, batch_id)
        assert "duplicate_seal" in codes[3]
        unexpected = [item for item in service.intake.list_review_items(batch_id)["items"]
                      if "unexpected_package" in item["discrepancy_codes"]]
        assert len(unexpected) == 2
        assert all(item["expected_quantity"] is None for item in unexpected)

        # 无委托项直接退回，进入退回清单
        detail = service.intake.decide_item(unexpected[0]["id"], {
            "decision": "returned", "expected_version": 1, "actor": "复核员甲", "reason": "清单无此委托编号",
        })
        assert detail["status"] == "returned"
        assert detail["return_record"]["reason"] == "清单无此委托编号"


def test_accept_blocked_while_discrepancies_remain(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service)
        batch_id = service.intake.import_manifest(manifest_payload(agency_id=agency["id"]))["batch"]["id"]
        item = item_by_line(service, batch_id, 1)
        with pytest.raises(ConflictError) as exc:
            service.intake.decide_item(item["id"], {
                "decision": "accepted", "expected_version": 1, "actor": "复核员甲", "reason": "",
            })
        assert exc.value.context["discrepancy_codes"] == ["package_missing"]


def test_pending_correction_then_resubmit_creates_audit_trail(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service)
        batch_id = service.intake.import_manifest(manifest_payload(agency_id=agency["id"]))["batch"]["id"]
        service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "scan-21", "entrust_no": "WT-001-01", "seal_no": "SEAL-001-01",
                 "specimen_category": "血样", "received_quantity": 3, "documents": ["委托函"]},
            ],
        })
        item = item_by_line(service, batch_id, 1)
        held = service.intake.decide_item(item["id"], {
            "decision": "pending_correction", "expected_version": 1,
            "actor": "复核员甲", "reason": "缺封装清单",
        })
        assert held["status"] == "pending_correction"
        assert held["version"] == 2

        corrected = service.intake.submit_correction(item["id"], {
            "submitted_by": "登记员甲", "note": "现场补交封装清单扫描件",
            "payload": {"channel": "窗口补交"}, "document_additions": ["封装清单"], "packages": [],
        })
        assert corrected["status"] == "pending"  # 差异消除后回到待决定队列
        assert corrected["discrepancy_codes"] == []
        assert corrected["received_quantity"] == 3
        assert corrected["corrections"][0]["note"] == "现场补交封装清单扫描件"
        assert "封装清单" in corrected["packages"][0]["documents"]
        transitions = [row["to_status"] for row in connection.execute(
            "SELECT to_status FROM intake_decision_logs WHERE review_item_id=? ORDER BY id", (item["id"],)
        ).fetchall()]
        assert transitions == ["pending_correction", "pending"]
        assert connection.execute(
            "SELECT COUNT(*) FROM intake_corrections WHERE review_item_id=?", (item["id"],)
        ).fetchone()[0] == 1
        # 补正后由复核人按新版本重新决定
        accepted = service.intake.decide_item(item["id"], {
            "decision": "accepted", "expected_version": corrected["version"], "actor": "复核员甲", "reason": "补正齐全",
        })
        assert accepted["status"] == "accepted"


def test_stale_version_cannot_overwrite_another_reviewer(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service)
        batch_id = service.intake.import_manifest(manifest_payload(agency_id=agency["id"]))["batch"]["id"]
        service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "scan-31", "entrust_no": "WT-001-01", "seal_no": "SEAL-001-01",
                 "specimen_category": "血样", "received_quantity": 3, "documents": ["委托函", "封装清单"]},
                {"scan_key": "scan-32", "entrust_no": "WT-001-02", "seal_no": "SEAL-001-02",
                 "specimen_category": "毛发", "received_quantity": 2, "documents": ["委托函"]},
                {"scan_key": "scan-33", "entrust_no": "WT-001-03", "seal_no": "SEAL-001-03",
                 "specimen_category": "织物", "received_quantity": 1, "documents": ["委托函", "封装清单"]},
            ],
        })
        item = item_by_line(service, batch_id, 1)
        service.intake.decide_item(item["id"], {
            "decision": "accepted", "expected_version": 1, "actor": "复核员甲", "reason": "无误",
        })
        # 复核员乙拿着过期版本（1）试图改成退回
        with pytest.raises(ConflictError) as exc:
            service.intake.decide_item(item["id"], {
                "decision": "returned", "expected_version": 1, "actor": "复核员乙", "reason": "事后争议",
            })
        assert "另一位复核人" in exc.value.message
        assert exc.value.context["current_version"] == 2
        # 原结论未被覆盖
        still = service.repository.require_review_item(item["id"])
        assert still["status"] == "accepted" and still["decision_by"] == "复核员甲"


def test_batch_decide_only_applies_to_uncontested_items(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service)
        batch_id = service.intake.import_manifest(manifest_payload(agency_id=agency["id"]))["batch"]["id"]
        service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "scan-41", "entrust_no": "WT-001-01", "seal_no": "SEAL-001-01",
                 "specimen_category": "血样", "received_quantity": 3, "documents": ["委托函", "封装清单"]},
                {"scan_key": "scan-42", "entrust_no": "WT-001-02", "seal_no": "SEAL-001-02",
                 "specimen_category": "毛发", "received_quantity": 2, "documents": ["委托函"]},
                # 第 3 项缺失，保持 package_missing
            ],
        })
        result = service.intake.decide_uncontested(batch_id, {
            "decision": "accepted", "actor": "复核员甲", "reason": "无差异批量接收",
        })
        assert sorted(result["applied_item_ids"]) == sorted(
            [item_by_line(service, batch_id, 1)["id"], item_by_line(service, batch_id, 2)["id"]]
        )
        remaining = service.intake.list_review_items(batch_id, status="pending")
        assert [item["line_no"] for item in remaining["items"]] == [3]


def test_confirm_atomically_generates_case_and_specimens_and_reconciles(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service)
        imported = service.intake.import_manifest(manifest_payload(agency_id=agency["id"]))
        batch_id = imported["batch"]["id"]
        batch_version = imported["batch"]["version"]
        service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "scan-51", "entrust_no": "WT-001-01", "seal_no": "SEAL-001-01",
                 "specimen_category": "血样", "received_quantity": 3, "documents": ["委托函", "封装清单"]},
                {"scan_key": "scan-52", "entrust_no": "WT-001-02", "seal_no": "SEAL-001-02",
                 "specimen_category": "毛发", "received_quantity": 2, "documents": ["委托函"]},
                # 第 3 项到件但缺封装清单，走退回
                {"scan_key": "scan-53", "entrust_no": "WT-001-03", "seal_no": "SEAL-001-03",
                 "specimen_category": "织物", "received_quantity": 1, "documents": ["委托函"]},
            ],
        })
        item1 = item_by_line(service, batch_id, 1)
        item2 = item_by_line(service, batch_id, 2)
        item3 = item_by_line(service, batch_id, 3)
        service.intake.decide_item(item1["id"], {
            "decision": "accepted", "expected_version": 1, "actor": "复核员甲", "reason": "无误",
        })
        service.intake.decide_item(item2["id"], {
            "decision": "accepted", "expected_version": 1, "actor": "复核员甲", "reason": "无误",
        })
        service.intake.decide_item(item3["id"], {
            "decision": "returned", "expected_version": 1, "actor": "复核员甲", "reason": "缺封装清单，退回刑侦",
        })

        # 不存在的批次不能确认
        with pytest.raises(NotFoundError):
            service.intake.confirm_batch(batch_id + 99999, {
                "expected_version": 1, "confirmed_by": "复核员甲", "case_no": "NO-SUCH", "case_name": "X",
            })

        result = service.intake.confirm_batch(batch_id, {
            "expected_version": batch_version, "confirmed_by": "复核员甲",
            "case_no": "CASE-INTAKE-001", "case_name": "盗窃案物证鉴定",
            "discipline": "法医物证", "entrusted_matter": "同一认定",
        })
        summary = result["summary"]
        assert summary["accepted_count"] == 2
        assert summary["returned_count"] == 1
        assert summary["pending_count"] == 0
        assert summary["accepted_quantity"] == 5
        assert summary["specimen_count"] == 2
        assert summary["specimen_quantity_total"] == 5
        assert summary["return_record_count"] == 1
        assert result["all_checks_passed"] is True
        assert all(result["reconciliation_checks"].values())

        # 正式案件与检材回链批次；退回项没有检材、没有保管台账记录
        case = result["case"]
        assert case["case_no"] == "CASE-INTAKE-001" and case["status_is_accepted"] is True
        specimen_item_ids = {s["review_item_id"] for s in result["specimens"]}
        assert specimen_item_ids == {item1["id"], item2["id"]}
        assert item3["id"] not in specimen_item_ids
        ledger = connection.execute(
            "SELECT COUNT(*) FROM custody_events e JOIN specimens s ON s.id=e.specimen_id "
            "WHERE s.intake_batch_id=?", (batch_id,)
        ).fetchone()[0]
        assert ledger == 0  # 未办理入库摆放，保管台账自然无记录
        returned_ids = {row["review_item_id"] for row in result["returned_items"]}
        assert returned_ids == {item3["id"]}

        # 确认后批次终局，不能再录封装
        with pytest.raises(ConflictError):
            service.intake.record_packages(batch_id, {
                "recorded_by": "登记员甲",
                "packages": [{"scan_key": "late-1", "entrust_no": "WT-001-01", "seal_no": "SEAL-001-01"}],
            })

        # 重复确认返回同一份汇总（幂等）
        again = service.intake.confirm_batch(batch_id, {
            "expected_version": batch_version, "confirmed_by": "复核员甲",
            "case_no": "CASE-INTAKE-001", "case_name": "盗窃案物证鉴定",
        })
        assert again["replayed"] is True
        assert connection.execute("SELECT COUNT(*) FROM forensic_cases WHERE intake_batch_id=?", (batch_id,)).fetchone()[0] == 1


def test_returned_items_never_enter_custody_after_placement(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        agency = create_agency(service, "R")
        payload = manifest_payload("R", agency_id=agency["id"])
        payload["lines"] = payload["lines"][:2]
        payload["lines"][0]["expected_quantity"] = 4
        batch_id = service.intake.import_manifest(payload)["batch"]["id"]
        version = service.repository.require_intake_batch(batch_id)["version"]
        service.intake.record_packages(batch_id, {
            "recorded_by": "登记员甲",
            "packages": [
                {"scan_key": "r-1", "entrust_no": "WT-R-01", "seal_no": "SEAL-R-01",
                 "specimen_category": "血样", "received_quantity": 4, "documents": ["委托函", "封装清单"]},
                {"scan_key": "r-2", "entrust_no": "WT-R-02", "seal_no": "SEAL-R-02",
                 "specimen_category": "毛发", "received_quantity": 1, "documents": []},
            ],
        })
        keep = item_by_line(service, batch_id, 1)
        gone = item_by_line(service, batch_id, 2)
        service.intake.decide_item(keep["id"], {
            "decision": "accepted", "expected_version": 1, "actor": "复核员甲", "reason": "ok",
        })
        service.intake.decide_item(gone["id"], {
            "decision": "returned", "expected_version": 1, "actor": "复核员甲", "reason": "文书全缺",
        })
        result = service.intake.confirm_batch(batch_id, {
            "expected_version": version, "confirmed_by": "复核员甲",
            "case_no": "CASE-R-001", "case_name": "退回核对案",
        })
        assert result["all_checks_passed"] is True
        # 接收检材办理入库后，保管台账仍只覆盖接收项
        specimen_id = result["specimens"][0]["specimen_id"]
        location = service.custody.create_location({
            "location_code": "INTAKE-R-V", "facility": "保管室", "room": "一室", "rack": "R1", "shelf": "S1",
            "capacity_units": 100, "reference_value": 4, "humidity_percent": 40,
        })
        service.custody.place_specimen({
            "specimen_id": specimen_id, "location_id": location["id"], "quantity": 4,
            "container_code": "BOX-R-1", "idempotency_key": "intake-r-place-1", "actor": "保管员",
        })
        recon = service.intake.reconciliation(batch_id)
        assert recon["reconciliation_checks"]["custody_ledger_only_covers_accepted"] is True
        assert recon["all_checks_passed"] is True
