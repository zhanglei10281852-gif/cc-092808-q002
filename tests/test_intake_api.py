from __future__ import annotations


def _login(client, username: str, password: str = "Passw0rd!!") -> dict:
    response = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": "test"})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _make_user(client, admin_headers: dict, username: str, role: str) -> dict:
    created = client.post("/api/users", headers=admin_headers, json={
        "username": username, "password": "Passw0rd!!", "display_name": username, "role_codes": [role],
    })
    assert created.status_code == 201, created.text
    return _login(client, username)


def _agency(client, headers: dict, code: str = "HTTP-INTAKE-ORG") -> int:
    response = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": code, "agency_name": "刑侦支队", "jurisdiction_code": "CN",
        "contact_address": "刑侦路", "restrictions": {},
    })
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _manifest(batch_no: str = "HTTP-BATCH-1") -> dict:
    return {
        "batch_no": batch_no,
        "case_source": "委托",
        "received_on": "2026-09-21",
        "source_filename": "entrust-http-1.xlsx",
        "created_by": "登记员甲",
        "lines": [
            {"line_no": 1, "entrust_no": "W-HTTP-1", "seal_no": "S-HTTP-1", "specimen_category": "血样",
             "expected_quantity": 2, "required_documents": ["委托函", "封装清单"]},
            {"line_no": 2, "entrust_no": "W-HTTP-2", "seal_no": "S-HTTP-2", "specimen_category": "毛发",
             "expected_quantity": 1, "required_documents": ["委托函"]},
        ],
    }


def test_intake_role_boundaries_and_full_http_flow(client, admin):
    admin_headers = admin["headers"]
    registrar = _make_user(client, admin_headers, "reg01", "registrar")
    curator = _make_user(client, admin_headers, "cur01", "curator")
    auditor = _make_user(client, admin_headers, "aud01", "auditor")

    # 登记员导入清单；审核员与审计员不能导入
    agency_id = _agency(client, admin_headers)
    payload = _manifest()
    payload["agency_id"] = agency_id
    imported = client.post("/api/forensics/intake/batches", headers=registrar, json=payload)
    assert imported.status_code == 201, imported.text
    batch_id = imported.json()["batch"]["id"]
    body = imported.json()
    assert body["replayed"] is False

    forbidden = client.post("/api/forensics/intake/batches", headers=curator, json=payload)
    assert forbidden.status_code == 403

    # 相同来源内容重传：返回既有批次且不复制
    replay = client.post("/api/forensics/intake/batches", headers=registrar, json=payload)
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True
    assert replay.json()["batch"]["id"] == batch_id

    # 审核员不能登记封装
    denied_record = client.post(f"/api/forensics/intake/batches/{batch_id}/rounds", headers=curator, json={
        "recorded_by": "登记员甲",
        "packages": [{"scan_key": "h1", "entrust_no": "W-HTTP-1", "seal_no": "S-HTTP-1",
                      "specimen_category": "血样", "received_quantity": 2,
                      "documents": ["委托函", "封装清单"]}],
    })
    assert denied_record.status_code == 403

    # 登记员分两轮登记：第一轮只到第 1 项，第二轮到第 2 项
    first_round = client.post(f"/api/forensics/intake/batches/{batch_id}/rounds", headers=registrar, json={
        "recorded_by": "登记员甲",
        "packages": [{"scan_key": "h1", "entrust_no": "W-HTTP-1", "seal_no": "S-HTTP-1",
                      "specimen_category": "血样", "received_quantity": 2,
                      "documents": ["委托函", "封装清单"]}],
    })
    assert first_round.status_code == 201, first_round.text
    # 扫描记录重传不复制数据
    replay_round = client.post(f"/api/forensics/intake/batches/{batch_id}/rounds", headers=registrar, json={
        "recorded_by": "登记员甲",
        "packages": [{"scan_key": "h1", "entrust_no": "W-HTTP-1", "seal_no": "S-HTTP-1",
                      "specimen_category": "血样", "received_quantity": 2,
                      "documents": ["委托函", "封装清单"]}],
    })
    assert replay_round.status_code == 201
    assert replay_round.json()["replayed"] is True
    assert replay_round.json()["inserted_count"] == 0

    second_round = client.post(f"/api/forensics/intake/batches/{batch_id}/rounds", headers=registrar, json={
        "recorded_by": "登记员甲",
        "packages": [{"scan_key": "h2", "entrust_no": "W-HTTP-2", "seal_no": "S-HTTP-2",
                      "specimen_category": "毛发", "received_quantity": 1, "documents": ["委托函"]}],
    })
    assert second_round.status_code == 201, second_round.text

    items = client.get(f"/api/forensics/intake/batches/{batch_id}/review-items", headers=auditor)
    assert items.status_code == 200
    assert all(item["discrepancy_codes"] == [] for item in items.json()["items"])

    # 登记员不能复核；审核员批量接收无争议项
    curator_forbidden = client.post(f"/api/forensics/intake/batches/{batch_id}/decisions", headers=registrar, json={
        "decision": "accepted", "actor": "登记员甲", "reason": "x",
    })
    assert curator_forbidden.status_code == 403
    bulk = client.post(f"/api/forensics/intake/batches/{batch_id}/decisions", headers=curator, json={
        "decision": "accepted", "actor": "审核员甲", "reason": "无差异批量接收",
    })
    assert bulk.status_code == 200, bulk.text
    assert bulk.json()["applied_count"] == 2

    batch_view = client.get(f"/api/forensics/intake/batches/{batch_id}", headers=auditor)
    assert batch_view.status_code == 200
    assert batch_view.json()["decision_counts"] == {"accepted": 2}

    # 确认立案：登记员无权，审核员执行，正式案件与检材原子生成
    confirm_by_registrar = client.post(f"/api/forensics/intake/batches/{batch_id}/confirm", headers=registrar, json={
        "expected_version": 1, "confirmed_by": "审核员甲", "case_no": "HTTP-CASE-INTAKE-1",
        "case_name": "http 批次立案案",
    })
    assert confirm_by_registrar.status_code == 403

    confirm = client.post(f"/api/forensics/intake/batches/{batch_id}/confirm", headers=curator, json={
        "expected_version": 1, "confirmed_by": "审核员甲", "case_no": "HTTP-CASE-INTAKE-1",
        "case_name": "http 批次立案案", "discipline": "法医物证",
    })
    assert confirm.status_code == 200, confirm.text
    reconciliation = confirm.json()
    assert reconciliation["summary"]["accepted_count"] == 2
    assert reconciliation["summary"]["returned_count"] == 0
    assert reconciliation["summary"]["specimen_count"] == 2
    assert reconciliation["all_checks_passed"] is True
    case_id = reconciliation["case"]["case_id"]

    case_detail = client.get(f"/api/forensics/cases/{case_id}", headers=auditor)
    assert case_detail.status_code == 200
    assert case_detail.json()["status"] == "accepted"
    assert len(case_detail.json()["lots"]) == 2

    # 独立汇总端点给出的数量与案件档案一致
    summary_endpoint = client.get(f"/api/forensics/intake/batches/{batch_id}/reconciliation", headers=auditor)
    assert summary_endpoint.status_code == 200
    assert summary_endpoint.json()["summary"]["specimen_quantity_total"] == 3
    assert summary_endpoint.json()["reconciliation_checks"]["case_status_accepted"] is True
