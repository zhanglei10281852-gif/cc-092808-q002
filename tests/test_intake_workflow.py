from __future__ import annotations

import pytest

from app.core.errors import ConflictError, ValidationError
from app.database import transaction
from app.forensics.service import ForensicService


MANIFEST_ITEMS = [
    {"line_no": 1, "entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
     "quantity": 2, "required_documents": ["委托书", "封装清单"]},
    {"line_no": 2, "entrust_no": "WT-27", "seal_no": "SEAL-02", "category": "毛发",
     "quantity": 1, "required_documents": ["委托书"]},
    {"line_no": 3, "entrust_no": "WT-27", "seal_no": "SEAL-03", "category": "烟头",
     "quantity": 3, "required_documents": ["委托书", "封装清单"]},
    {"line_no": 4, "entrust_no": "WT-27", "seal_no": "SEAL-04", "category": "织物",
     "quantity": 1, "required_documents": ["委托书"]},
]


def make_batch(service: ForensicService, *, items=None, file_hash: str = "a" * 64) -> dict:
    result = service.intake.create_batch({
        "batch_no": None, "entrust_no": "WT-27", "source_name": "市刑侦支队",
        "source_file_name": "entrust-27.xlsx", "source_file_hash": file_hash,
        "header": {"declared_packages": 27}, "created_by": "登记员甲",
        "items": items or MANIFEST_ITEMS,
    })
    assert result["replayed"] is False
    return result["batch"]


def test_import_manifest_produces_missing_lines_and_is_replayable(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        batch = make_batch(service)
        assert batch["status"] == "collecting"
        kinds = {line["seal_no"]: line["kind"] for line in batch["lines"]}
        assert kinds == {"SEAL-01": "missing", "SEAL-02": "missing",
                         "SEAL-03": "missing", "SEAL-04": "missing"}
        assert batch["summary"]["manifest"]["count"] == 4

        replay = service.intake.create_batch({
            "batch_no": None, "entrust_no": "WT-27", "source_name": "市刑侦支队",
            "source_file_name": "entrust-27.xlsx", "source_file_hash": "a" * 64,
            "header": {}, "created_by": "登记员甲", "items": MANIFEST_ITEMS,
        })
        assert replay["replayed"] is True
        assert replay["batch"]["id"] == batch["id"]
        count = connection.execute("SELECT COUNT(*) FROM intake_batches").fetchone()[0]
        assert count == 1
        manifest_count = connection.execute("SELECT COUNT(*) FROM intake_manifest_items").fetchone()[0]
        assert manifest_count == 4


def test_staged_rounds_detect_each_discrepancy_kind(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        batch = make_batch(service)

        first_round = service.intake.register_round(batch["id"], {
            "source_hash": "b" * 64, "source_label": "第一次清点", "received_by": "登记员甲",
            "note": "首批",
            "packages": [
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 2, "documents": ["委托书", "封装清单"], "scan_record_key": "SCAN-1"},
                # SEAL-02: 数量不符
                {"entrust_no": "WT-27", "seal_no": "SEAL-02", "category": "毛发",
                 "quantity": 2, "documents": ["委托书"], "scan_record_key": "SCAN-2"},
                # SEAL-03: 类别不符 + 缺封装清单 → mixed
                {"entrust_no": "WT-27", "seal_no": "SEAL-03", "category": "烟蒂",
                 "quantity": 3, "documents": ["委托书"], "scan_record_key": "SCAN-3"},
                # SEAL-04 仍缺件；另出现清单外多件
                {"entrust_no": "WT-27", "seal_no": "SEAL-99", "category": "不明物",
                 "quantity": 1, "documents": [], "scan_record_key": "SCAN-99"},
            ],
        })
        assert first_round["inserted"] == 4
        assert first_round["replayed_packages"] == 0

        second_round = service.intake.register_round(batch["id"], {
            "source_hash": "c" * 64, "source_label": "第二次清点", "received_by": "登记员乙",
            "note": "补到重复封识",
            "packages": [
                # 重复封识
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 1, "documents": ["委托书"], "scan_record_key": "SCAN-1DUP"},
            ],
        })
        assert second_round["inserted"] == 1

        detail = service.intake.batch_detail(batch["id"])
        kinds = {}
        for line in detail["lines"]:
            kinds.setdefault(line["seal_no"], []).append(line["kind"])
        assert kinds["SEAL-01"] == ["matched", "duplicate_seal"]
        assert kinds["SEAL-02"] == ["quantity_mismatch"]
        assert kinds["SEAL-03"] == ["mixed"]
        assert kinds["SEAL-04"] == ["missing"]
        assert kinds["SEAL-99"] == ["surplus"]
        by_kind = detail["summary"]["lines"]["by_kind"]
        assert by_kind["matched"] == 1
        assert by_kind["missing"] == 1
        assert by_kind["surplus"] == 1
        assert by_kind["duplicate_seal"] == 1


def test_same_source_file_or_scan_record_retransmit_does_not_duplicate(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        batch = make_batch(service)
        payload = {
            "source_hash": "b" * 64, "source_label": "第一次清点", "received_by": "登记员甲",
            "note": "",
            "packages": [
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 2, "documents": ["委托书", "封装清单"], "scan_record_key": "SCAN-1"},
            ],
        }
        first = service.intake.register_round(batch["id"], payload)
        assert first["replayed"] is False
        replay = service.intake.register_round(batch["id"], payload)
        assert replay["replayed"] is True
        # 不同轮次但同扫描记录
        other_round = service.intake.register_round(batch["id"], {
            "source_hash": "d" * 64, "source_label": "重传扫描", "received_by": "登记员甲",
            "note": "",
            "packages": [
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 2, "documents": ["委托书", "封装清单"], "scan_record_key": "SCAN-1"},
            ],
        })
        assert other_round["inserted"] == 0
        assert other_round["replayed_packages"] == 1
        assert connection.execute("SELECT COUNT(*) FROM intake_received_packages").fetchone()[0] == 1


def test_reviewer_single_decisions_and_stale_version_blocked(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        batch = make_batch(service)
        service.intake.register_round(batch["id"], {
            "source_hash": "b" * 64, "source_label": "清点", "received_by": "登记员甲", "note": "",
            "packages": [
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 2, "documents": ["委托书", "封装清单"], "scan_record_key": "SCAN-1"},
                {"entrust_no": "WT-27", "seal_no": "SEAL-02", "category": "毛发",
                 "quantity": 2, "documents": ["委托书"], "scan_record_key": "SCAN-2"},
            ],
        })
        service.intake.submit_for_review(batch["id"], {"actor": "登记员甲", "expected_version": 1})
        lines = {line["seal_no"]: line for line in service.intake.batch_detail(batch["id"])["lines"]}
        matched = lines["SEAL-01"]
        mismatched = lines["SEAL-02"]

        accepted = service.intake.decide_line(matched["id"], {
            "action": "accept", "reason": "", "expected_version": 1, "actor": "复核员甲",
        })
        assert accepted["decision"] == "accepted"
        assert accepted["decided_by"] == "复核员甲"

        # 版本过期不得覆盖另一位复核人的结论
        with pytest.raises(ConflictError) as exc:
            service.intake.decide_line(matched["id"], {
                "action": "return", "reason": "试图推翻", "expected_version": 1, "actor": "复核员乙",
            })
        assert exc.value.context["current_version"] == 2

        # 暂存待补正必须有理由
        with pytest.raises(ValidationError):
            service.intake.decide_line(mismatched["id"], {
                "action": "hold", "reason": "  ", "expected_version": 1, "actor": "复核员甲",
            })
        held = service.intake.decide_line(mismatched["id"], {
            "action": "hold", "reason": "数量不符待补正", "expected_version": 1, "actor": "复核员甲",
        })
        assert held["decision"] == "held"

        detail = service.intake.line_detail(matched["id"])
        assert [event["action"] for event in detail["events"]] == ["accept"]
        assert detail["events"][0]["reason"] == ""


def test_batch_decision_only_for_uncontested_and_is_atomic_on_conflict(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        batch = make_batch(service)
        service.intake.register_round(batch["id"], {
            "source_hash": "b" * 64, "source_label": "清点", "received_by": "登记员甲", "note": "",
            "packages": [
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 2, "documents": ["委托书", "封装清单"], "scan_record_key": "SCAN-1"},
                {"entrust_no": "WT-27", "seal_no": "SEAL-02", "category": "毛发",
                 "quantity": 2, "documents": ["委托书"], "scan_record_key": "SCAN-2"},
            ],
        })
        service.intake.submit_for_review(batch["id"], {"actor": "登记员甲", "expected_version": 1})
        lines = service.intake.batch_detail(batch["id"])["lines"]
        matched = next(line for line in lines if line["kind"] == "matched")
        mismatch = next(line for line in lines if line["kind"] == "quantity_mismatch")

        # 含差异项的批量接收整体拒绝
        with pytest.raises(ConflictError) as exc:
            service.intake.decide_batch(batch["id"], {
                "action": "accept", "actor": "复核员甲", "reason": "",
                "items": [{"line_id": matched["id"], "expected_version": 1},
                          {"line_id": mismatch["id"], "expected_version": 1}],
            })
        assert any(item["line_id"] == mismatch["id"] for item in exc.value.context["conflicts"])
        untouched = service.intake.line_detail(matched["id"])
        assert untouched["decision"] == "pending"

        # 无争议项批量接收
        result = service.intake.decide_batch(batch["id"], {
            "action": "accept", "actor": "复核员甲", "reason": "",
            "items": [{"line_id": matched["id"], "expected_version": 1}],
        })
        assert result["decided_count"] == 1

        # 其他复核人已处理 + 版本过期 → 批量冲突
        with pytest.raises(ConflictError) as exc:
            service.intake.decide_batch(batch["id"], {
                "action": "return", "actor": "复核员乙", "reason": "过期请求",
                "items": [{"line_id": matched["id"], "expected_version": 1}],
            })
        assert exc.value.context["conflicts"][0]["reason"] in {"项目已被处理", "版本过期"}


def test_correction_trail_reopens_held_item_and_resolves_missing(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        batch = make_batch(service)
        service.intake.register_round(batch["id"], {
            "source_hash": "b" * 64, "source_label": "清点", "received_by": "登记员甲", "note": "",
            "packages": [
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 2, "documents": ["委托书"], "scan_record_key": "SCAN-1"},
            ],
        })
        service.intake.submit_for_review(batch["id"], {"actor": "登记员甲", "expected_version": 1})
        lines = {line["seal_no"]: line for line in service.intake.batch_detail(batch["id"])["lines"]}
        doc_line = lines["SEAL-01"]  # document_missing
        missing_line = lines["SEAL-02"]  # missing

        held_doc = service.intake.decide_line(doc_line["id"], {
            "action": "hold", "reason": "缺封装清单", "expected_version": 1, "actor": "复核员甲",
        })
        held_missing = service.intake.decide_line(missing_line["id"], {
            "action": "hold", "reason": "现场缺件", "expected_version": 1, "actor": "复核员甲",
        })

        corrected = service.intake.record_correction(held_doc["id"], {
            "actor": "登记员甲", "note": "补交封装清单扫描件", "added_documents": ["封装清单"],
        })
        assert corrected["kind"] == "matched"
        assert corrected["decision"] == "pending"
        assert corrected["version"] == 3
        assert len(corrected["corrections"]) == 1
        assert corrected["corrections"][0]["after"]["kind"] == "matched"

        resolved = service.intake.record_correction(held_missing["id"], {
            "actor": "登记员乙", "note": "找到遗漏封装", "added_documents": [],
            "package": {"entrust_no": "WT-27", "seal_no": "SEAL-02", "category": "毛发",
                        "quantity": 1, "documents": ["委托书"], "scan_record_key": "SCAN-2FIND"},
        })
        assert resolved["kind"] == "matched"
        assert resolved["received_package_id"] is not None
        # 补正封装不会复制为差异行
        seal02_lines = [line for line in service.intake.batch_detail(batch["id"])["lines"]
                        if line["seal_no"] == "SEAL-02"]
        assert len(seal02_lines) == 1


def _agency(service: ForensicService) -> dict:
    return service.forensic_cases.create_agency({
        "agency_code": "ORG-INTAKE", "agency_name": "市公安局物证中心", "jurisdiction_code": "CN",
        "contact_address": "司法路", "licensed_on": "2025-10-02", "accreditation_no": None,
        "restrictions": {},
    })


def _review_ready_batch(service: ForensicService) -> dict:
    agency = _agency(service)
    batch = make_batch(service)
    service.intake.register_round(batch["id"], {
        "source_hash": "b" * 64, "source_label": "清点", "received_by": "登记员甲", "note": "",
        "packages": [
            {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
             "quantity": 2, "documents": ["委托书", "封装清单"], "scan_record_key": "SCAN-1"},
            {"entrust_no": "WT-27", "seal_no": "SEAL-02", "category": "毛发",
             "quantity": 1, "documents": ["委托书"], "scan_record_key": "SCAN-2"},
            {"entrust_no": "WT-27", "seal_no": "SEAL-03", "category": "烟头",
             "quantity": 3, "documents": ["委托书"], "scan_record_key": "SCAN-3"},
            {"entrust_no": "WT-27", "seal_no": "SEAL-04", "category": "织物",
             "quantity": 1, "documents": ["委托书"], "scan_record_key": "SCAN-4"},
        ],
    })
    service.intake.submit_for_review(batch["id"], {"actor": "登记员甲", "expected_version": 1})
    lines = service.intake.batch_detail(batch["id"])["lines"]
    # SEAL-03 缺封装清单 → 退回；SEAL-04 matched 接收；SEAL-01/02 接收
    accepted_ids = []
    for line in lines:
        if line["seal_no"] in {"SEAL-01", "SEAL-02", "SEAL-04"}:
            accepted_ids.append(line["id"])
            service.intake.decide_line(line["id"], {
                "action": "accept", "reason": "", "expected_version": line["version"], "actor": "复核员甲",
            })
        elif line["seal_no"] == "SEAL-03":
            service.intake.decide_line(line["id"], {
                "action": "return", "reason": "缺少封装清单，退回刑侦补正",
                "expected_version": line["version"], "actor": "复核员甲",
            })
    return {"batch": service.intake.batch_detail(batch["id"]), "agency": agency, "accepted_ids": accepted_ids}


def test_cases_and_specimens_generated_atomically_from_confirmed_items(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ready = _review_ready_batch(service)
        batch = ready["batch"]
        result = service.intake.generate_cases(batch["id"], {
            "actor": "登记员甲", "expected_version": 2,
            "cases": [{
                "entrust_no": "WT-27", "case_no": "CASE-INTAKE-1", "case_name": "生物物证鉴定",
                "discipline": "法医物证", "case_source": "委托", "accepted_on": "2026-09-28",
                "agency_id": ready["agency"]["id"], "entrusted_matter": "同一认定",
            }],
        })
        generation = result["generated"][0]
        assert generation["specimen_count"] == 3
        assert generation["quantity_total"] == 4  # 2 + 1 + 1

        case = service.repository.forensic_case_detail(generation["case_id"])
        assert case["status"] == "accepted"
        assert len(case["lots"]) == 3
        # 退回的 SEAL-03 没有进入保管台账
        specimens = connection.execute(
            "SELECT id FROM specimens WHERE case_id=?", (generation["case_id"],)
        ).fetchall()
        assert len(specimens) == 3

        # 同委托编号不能重复建案
        with pytest.raises(ConflictError):
            service.intake.generate_cases(batch["id"], {
                "actor": "登记员甲", "expected_version": 3,
                "cases": [{
                    "entrust_no": "WT-27", "case_no": "CASE-INTAKE-2", "case_name": "重复建案",
                    "discipline": "法医物证", "case_source": "委托", "accepted_on": "2026-09-28",
                    "agency_id": ready["agency"]["id"],
                }],
            })

        # 已生成检材的项目不能再改结论
        generated_line = service.intake.line_detail(generation["line_ids"][0])
        assert generated_line["generated_specimen_id"] in generation["specimen_ids"]
        with pytest.raises(ConflictError):
            service.intake.decide_line(generated_line["id"], {
                "action": "return", "reason": "事后退回", "expected_version": 2, "actor": "复核员乙",
            })


def test_final_summary_reconciles_case_archive_custody_and_returns(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ready = _review_ready_batch(service)
        batch = ready["batch"]
        service.intake.generate_cases(batch["id"], {
            "actor": "登记员甲", "expected_version": 2,
            "cases": [{
                "entrust_no": "WT-27", "case_no": "CASE-INTAKE-9", "case_name": "生物物证鉴定",
                "discipline": "法医物证", "case_source": "委托", "accepted_on": "2026-09-28",
                "agency_id": ready["agency"]["id"],
            }],
        })
        summary = service.intake.reconcile_summary(batch["id"])
        assert summary["accepted"]["count"] == 3
        assert summary["accepted"]["quantity"] == 4
        assert summary["accepted"]["generated_specimen_count"] == 3
        assert summary["accepted"]["generated_quantity"] == 4
        assert summary["returned"]["count"] == 1
        returned = summary["returned"]["items"][0]
        assert returned["seal_no"] == "SEAL-03"
        assert returned["generated_specimen_id"] is None
        assert summary["checks"]["accepted_quantity_matches_specimens"] is True
        assert summary["checks"]["returned_items_not_in_custody"] is True
        assert summary["checks"]["manifest_items_all_on_lines"] is True
        assert summary["checks"]["packages_all_on_lines"] is True
        gen_case = summary["generated_cases"][0]
        assert gen_case["ties"] is True
        assert gen_case["recorded_specimen_count"] == 3

        # 退回清单逐件可核对：台账中不存在 SEAL-03 的检材
        seal03 = connection.execute(
            "SELECT COUNT(*) FROM specimens s JOIN intake_review_lines l "
            "ON l.generated_specimen_id=s.id WHERE l.batch_id=? AND l.seal_no='SEAL-03'",
            (batch["id"],),
        ).fetchone()[0]
        assert seal03 == 0

        # 全部项目已处置，批次可以结论
        concluded = service.intake.conclude(batch["id"], {"actor": "复核员甲", "expected_version": 3})
        assert concluded["status"] == "concluded"


def test_conclude_blocked_when_pending_or_held(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        batch = make_batch(service)
        service.intake.register_round(batch["id"], {
            "source_hash": "b" * 64, "source_label": "清点", "received_by": "登记员甲", "note": "",
            "packages": [
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 2, "documents": ["委托书", "封装清单"], "scan_record_key": "SCAN-1"},
            ],
        })
        service.intake.submit_for_review(batch["id"], {"actor": "登记员甲", "expected_version": 1})
        with pytest.raises(ConflictError) as exc:
            service.intake.conclude(batch["id"], {"actor": "复核员甲", "expected_version": 2})
        assert exc.value.context["outstanding"] >= 1


def test_snapshots_cover_import_rounds_decisions_corrections(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        batch = make_batch(service)
        service.intake.register_round(batch["id"], {
            "source_hash": "b" * 64, "source_label": "清点", "received_by": "登记员甲", "note": "",
            "packages": [
                {"entrust_no": "WT-27", "seal_no": "SEAL-01", "category": "血样",
                 "quantity": 2, "documents": ["委托书"], "scan_record_key": "SCAN-1"},
            ],
        })
        service.intake.submit_for_review(batch["id"], {"actor": "登记员甲", "expected_version": 1})
        line = next(line for line in service.intake.batch_detail(batch["id"])["lines"]
                    if line["seal_no"] == "SEAL-01")
        held = service.intake.decide_line(line["id"], {
            "action": "hold", "reason": "缺封装清单", "expected_version": 1, "actor": "复核员甲",
        })
        service.intake.record_correction(held["id"], {
            "actor": "登记员甲", "note": "补齐文书", "added_documents": ["封装清单"],
        })
        kinds = [snap["snapshot_kind"] for snap in service.intake.snapshots(batch["id"])]
        assert "import" in kinds
        assert "round" in kinds
        assert "reconcile" in kinds
        assert "decision" in kinds
        assert "correction" in kinds
