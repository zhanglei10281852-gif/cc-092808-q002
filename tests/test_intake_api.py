from __future__ import annotations


def _manifest(entrust_no: str = "WT-HTTP-1"):
    return [
        {"line_no": 1, "entrust_no": entrust_no, "seal_no": "H-SEAL-1", "category": "血样",
         "quantity": 1, "required_documents": ["委托书"]},
        {"line_no": 2, "entrust_no": entrust_no, "seal_no": "H-SEAL-2", "category": "毛发",
         "quantity": 2, "required_documents": ["委托书"]},
    ]


def test_intake_http_full_flow(client, admin):
    headers = admin["headers"]
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": "HTTP-IB-ORG", "agency_name": "刑侦支队", "jurisdiction_code": "CN",
        "contact_address": "司法路", "restrictions": {},
    })
    assert agency.status_code == 201, agency.text

    create_body = {
        "batch_no": "IB-HTTP-1", "entrust_no": "WT-HTTP-1", "source_name": "刑侦部门",
        "source_file_name": "list.xlsx", "source_file_hash": "f" * 64,
        "header": {"declared": 27}, "created_by": "登记员", "items": _manifest(),
    }
    created = client.post("/api/forensics/intake/batches", headers=headers, json=create_body)
    assert created.status_code == 201, created.text
    assert created.json()["replayed"] is False
    batch_id = created.json()["batch"]["id"]

    replayed = client.post("/api/forensics/intake/batches", headers=headers, json=create_body)
    assert replayed.status_code == 201
    assert replayed.json()["replayed"] is True

    round_body = {
        "source_hash": "e" * 64, "source_label": "首轮", "received_by": "登记员", "note": "",
        "packages": [
            {"entrust_no": "WT-HTTP-1", "seal_no": "H-SEAL-1", "category": "血样",
             "quantity": 1, "documents": ["委托书"], "scan_record_key": "H-SCAN-1"},
            {"entrust_no": "WT-HTTP-1", "seal_no": "H-SEAL-2", "category": "毛发",
             "quantity": 1, "documents": ["委托书"], "scan_record_key": "H-SCAN-2"},
        ],
    }
    first = client.post(f"/api/forensics/intake/batches/{batch_id}/rounds", headers=headers, json=round_body)
    assert first.status_code == 201, first.text
    assert first.json()["inserted"] == 2
    replay = client.post(f"/api/forensics/intake/batches/{batch_id}/rounds", headers=headers, json=round_body)
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True

    submitted = client.post(f"/api/forensics/intake/batches/{batch_id}/submit-review", headers=headers, json={
        "actor": "登记员", "expected_version": 1,
    })
    assert submitted.status_code == 200, submitted.text

    lines = client.get(f"/api/forensics/intake/batches/{batch_id}", headers=headers).json()["lines"]
    matched = next(line for line in lines if line["kind"] == "matched")
    mismatch = next(line for line in lines if line["kind"] == "quantity_mismatch")

    ok = client.post(f"/api/forensics/intake/lines/{matched['id']}/decision", headers=headers, json={
        "action": "accept", "reason": "", "expected_version": 1, "actor": "复核员甲",
    })
    assert ok.status_code == 200, ok.text

    stale = client.post(f"/api/forensics/intake/lines/{matched['id']}/decision", headers=headers, json={
        "action": "return", "reason": "过期覆盖", "expected_version": 1, "actor": "复核员乙",
    })
    assert stale.status_code == 409
    assert stale.json()["error"]["context"]["current_version"] == 2

    held = client.post(f"/api/forensics/intake/lines/{mismatch['id']}/decision", headers=headers, json={
        "action": "hold", "reason": "数量不符待补正", "expected_version": 1, "actor": "复核员甲",
    })
    assert held.status_code == 200

    corrected = client.post(f"/api/forensics/intake/lines/{mismatch['id']}/corrections", headers=headers, json={
        "actor": "登记员", "note": "确认为两件，差额补登记", "added_documents": [],
        "quantity_override": 2,
    })
    assert corrected.status_code == 201, corrected.text
    assert corrected.json()["kind"] == "matched"

    fixed = next(
        line for line in client.get(f"/api/forensics/intake/batches/{batch_id}", headers=headers).json()["lines"]
        if line["id"] == mismatch["id"]
    )
    accepted = client.post(f"/api/forensics/intake/lines/{fixed['id']}/decision", headers=headers, json={
        "action": "accept", "reason": "补正后相符", "expected_version": fixed["version"], "actor": "复核员甲",
    })
    assert accepted.status_code == 200

    generated = client.post(f"/api/forensics/intake/batches/{batch_id}/generate-cases", headers=headers, json={
        "actor": "登记员", "expected_version": 2,
        "cases": [{
            "entrust_no": "WT-HTTP-1", "case_no": "HTTP-IB-CASE-1", "case_name": "生物物证鉴定",
            "discipline": "法医物证", "case_source": "委托", "accepted_on": "2026-09-30",
            "agency_id": agency.json()["id"],
        }],
    })
    assert generated.status_code == 200, generated.text
    assert generated.json()["generated"][0]["specimen_count"] == 2

    summary = client.get(f"/api/forensics/intake/batches/{batch_id}/summary", headers=headers)
    assert summary.status_code == 200
    body = summary.json()
    assert body["balanced"] is True
    assert body["accepted"]["generated_quantity"] == 3
    assert body["generated_cases"][0]["ties"] is True

    concluded = client.post(f"/api/forensics/intake/batches/{batch_id}/conclude", headers=headers, json={
        "actor": "复核员甲", "expected_version": 3,
    })
    assert concluded.status_code == 200
    assert concluded.json()["status"] == "concluded"


def test_intake_batch_decision_rejects_disputed_item(client, admin):
    headers = admin["headers"]
    created = client.post("/api/forensics/intake/batches", headers=headers, json={
        "batch_no": "IB-HTTP-2", "entrust_no": "WT-HTTP-2", "source_name": "刑侦部门",
        "source_file_name": "list2.xlsx", "source_file_hash": "9" * 64,
        "header": {}, "created_by": "登记员", "items": _manifest("WT-HTTP-2"),
    })
    assert created.status_code == 201, created.text
    batch_id = created.json()["batch"]["id"]
    client.post(f"/api/forensics/intake/batches/{batch_id}/rounds", headers=headers, json={
        "source_hash": "8" * 64, "source_label": "首轮", "received_by": "登记员", "note": "",
        "packages": [
            {"entrust_no": "WT-HTTP-2", "seal_no": "H-SEAL-1", "category": "血样",
             "quantity": 1, "documents": ["委托书"], "scan_record_key": "H2-SCAN-1"},
        ],
    })
    client.post(f"/api/forensics/intake/batches/{batch_id}/submit-review", headers=headers, json={
        "actor": "登记员", "expected_version": 1,
    })
    lines = client.get(f"/api/forensics/intake/batches/{batch_id}", headers=headers).json()["lines"]
    matched = next(line for line in lines if line["kind"] == "matched")
    missing = next(line for line in lines if line["kind"] == "missing")

    response = client.post(f"/api/forensics/intake/batches/{batch_id}/decisions", headers=headers, json={
        "action": "accept", "actor": "复核员甲", "reason": "",
        "items": [{"line_id": matched["id"], "expected_version": 1},
                  {"line_id": missing["id"], "expected_version": 1}],
    })
    assert response.status_code == 409
    conflicts = response.json()["error"]["context"]["conflicts"]
    assert any(item["line_id"] == missing["id"] for item in conflicts)

    # 整批失败不留下决定
    detail = client.get(f"/api/forensics/intake/lines/{matched['id']}", headers=headers).json()
    assert detail["decision"] == "pending"


def test_intake_requires_authentication(client):
    response = client.get("/api/forensics/intake/batches")
    assert response.status_code == 401
