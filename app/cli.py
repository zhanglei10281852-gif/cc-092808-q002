from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.database import database_path, get_connection, init_db, transaction
from app.forensics.service import ForensicService


def init_command() -> dict:
    init_db()
    return {"database": str(database_path()), "initialized": True}


def check_command() -> dict:
    init_db()
    connection = get_connection()
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    required = {
        "forensic_cases", "specimens", "storage_locations", "examinations",
        "review_schedules", "quality_alerts", "outbox_events",
        "intake_batches", "intake_manifest_items", "intake_actual_packages",
        "intake_review_items", "intake_rounds", "batch_return_records",
    }
    actual = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    return {
        "database": str(database_path()),
        "integrity": integrity,
        "foreign_key_errors": len(foreign_keys),
        "required_tables_present": required.issubset(actual),
        "table_count": len(actual),
    }


def smoke_command() -> dict:
    from app.main import app

    init_db()
    with TestClient(app) as client:
        root = client.get("/")
        health = client.get("/api/system/health")
    if root.status_code != 200 or health.status_code != 200:
        raise RuntimeError("HTTP 冒烟检查失败")
    return {"root": root.json(), "health": health.json(), "status": "ok"}


def demo_command() -> dict:
    init_db()
    service = ForensicService(get_connection())
    suffix = get_connection().execute("SELECT COUNT(*) FROM forensic_cases").fetchone()[0] + 1
    with transaction(immediate=True):
        source = service.forensic_cases.create_agency({
            "agency_code": f"DEMO-{suffix:04d}",
            "agency_name": "示范公安分局",
            "jurisdiction_code": "CN",
            "contact_address": "示范区法医物证受理中心",
            "licensed_on": "2026-09-01",
            "accreditation_no": None,
            "restrictions": {},
        })
        forensic_case = service.forensic_cases.create_forensic_case({
            "case_no": f"CASE-DEMO-{suffix:04d}",
            "case_name": "示范区身份关系鉴定",
            "discipline": "法医物证",
            "entrusted_matter": "亲缘关系鉴定",
            "agency_id": source["id"],
            "case_source": "委托",
            "accepted_on": "2026-09-20",
            "passport": {"commission_document": "DEMO-2026"},
            "created_by": "cli",
        })
        accepted = service.forensic_cases.transition(forensic_case["id"], {
            "target_status": "accepted", "reason": "资料齐全", "expected_version": 1, "actor": "cli"
        })
        location = service.custody.create_location({
            "location_code": f"DEMO-VAULT-{suffix:04d}", "facility": "检材保管室", "room": "冷藏区",
            "rack": "R1", "shelf": "S1", "capacity_units": 5000,
            "reference_value": -18, "humidity_percent": 30,
        })
        specimen = service.custody.create_specimen({
            "specimen_no": f"SP-DEMO-{suffix:04d}", "case_id": accepted["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 5, "integrity_percent": 100,
            "packaging": "独立封袋，封识完整", "sealed_on": "2026-09-21", "created_by": "cli",
        })
        placement = service.custody.place_specimen({
            "specimen_id": specimen["id"], "location_id": location["id"], "quantity": 5,
            "container_code": f"BOX-DEMO-{suffix:04d}", "idempotency_key": f"demo-place-{suffix:08d}", "actor": "cli",
        })
    return {
        "case_no": accepted["case_no"],
        "specimen_no": specimen["specimen_no"],
        "location": location["location_code"],
        "placement_id": placement["placement"]["id"],
        "dashboard": service.dashboard(),
    }


def intake_demo_command() -> dict:
    init_db()
    service = ForensicService(get_connection())
    suffix = get_connection().execute("SELECT COUNT(*) FROM intake_batches").fetchone()[0] + 1
    with transaction(immediate=True):
        source = service.forensic_cases.create_agency({
            "agency_code": f"INTAKE-DEMO-{suffix:04d}",
            "agency_name": "示范刑侦支队物证中心",
            "jurisdiction_code": "CN",
            "contact_address": "示范区刑侦路",
            "licensed_on": "2026-09-01",
            "accreditation_no": None,
            "restrictions": {},
        })
        imported = service.intake.import_manifest({
            "batch_no": f"INB-DEMO-{suffix:04d}",
            "agency_id": source["id"],
            "case_source": "委托",
            "received_on": "2026-09-21",
            "source_filename": f"entrust-demo-{suffix:04d}.xlsx",
            "created_by": "登记员",
            "lines": [
                {"line_no": 1, "entrust_no": f"WT-D{suffix}-01", "seal_no": f"FS-D{suffix}-01",
                 "specimen_category": "血样", "expected_quantity": 3, "required_documents": ["委托函", "封装清单"]},
                {"line_no": 2, "entrust_no": f"WT-D{suffix}-02", "seal_no": f"FS-D{suffix}-02",
                 "specimen_category": "毛发", "expected_quantity": 2, "required_documents": ["委托函"]},
            ],
        })
        batch_id = imported["batch"]["id"]
        service.intake.record_packages(batch_id, {
            "recorded_by": "登记员",
            "packages": [
                {"scan_key": f"scan-d{suffix}-1", "entrust_no": f"WT-D{suffix}-01", "seal_no": f"FS-D{suffix}-01",
                 "specimen_category": "血样", "received_quantity": 3, "documents": ["委托函", "封装清单"]},
                {"scan_key": f"scan-d{suffix}-2", "entrust_no": f"WT-D{suffix}-02", "seal_no": f"FS-D{suffix}-02",
                 "specimen_category": "毛发", "received_quantity": 1, "documents": []},
            ],
        })
        items = service.intake.list_review_items(batch_id)["items"]
        keep = next(item for item in items if item["line_no"] == 1)
        short = next(item for item in items if item["line_no"] == 2)
        service.intake.decide_item(keep["id"], {
            "decision": "accepted", "expected_version": keep["version"], "actor": "复核员", "reason": "封装与文书齐全",
        })
        service.intake.decide_item(short["id"], {
            "decision": "returned", "expected_version": short["version"], "actor": "复核员",
            "reason": "实收数量不符且缺委托函",
        })
        reconciliation = service.intake.confirm_batch(batch_id, {
            "expected_version": imported["batch"]["version"], "confirmed_by": "复核员",
            "case_no": f"CASE-INB-{suffix:04d}", "case_name": "示范批次受理案",
            "discipline": "法医物证", "entrusted_matter": "同一认定",
        })
    return {
        "batch_no": reconciliation["batch"]["batch_no"],
        "case_no": reconciliation["case"]["case_no"],
        "summary": reconciliation["summary"],
        "checks_passed": reconciliation["all_checks_passed"],
    }


def export_command(path: str) -> dict:
    init_db()
    service = ForensicService(get_connection())
    items, total = service.repository.list_forensic_cases(status=None, crop=None, limit=10_000, offset=0)
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"path": str(target), "count": total}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="司法鉴定机构运维命令")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="执行 HTTP 冒烟检查")
    subparsers.add_parser("demo", help="写入一组示范入库数据")
    subparsers.add_parser("intake-demo", help="写入一组示范分阶段批次受理数据")
    export = subparsers.add_parser("export-forensic_cases", help="导出案件档案")
    export.add_argument("path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "init-db":
            result = init_command()
        elif args.command == "check-db":
            result = check_command()
        elif args.command == "smoke":
            result = smoke_command()
        elif args.command == "demo":
            result = demo_command()
        elif args.command == "intake-demo":
            result = intake_demo_command()
        else:
            result = export_command(args.path)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (sqlite3.Error, RuntimeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
