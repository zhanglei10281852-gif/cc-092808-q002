from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.core.errors import PermissionDeniedError
from app.core.security import Principal
from app.api.dependencies import current_principal
from app.database import get_connection, transaction
from app.forensics.schemas import (
    IntakeBatchCreate,
    IntakeBatchDecision,
    IntakeConclude,
    IntakeCorrection,
    IntakeGenerate,
    IntakeLineDecision,
    IntakeRoundCreate,
    IntakeSubmitReview,
)
from app.forensics.service import ForensicService


router = APIRouter(prefix="/api/forensics/intake", tags=["批次受理"])


def _service() -> ForensicService:
    return ForensicService(get_connection())


def _require_intake_read(principal: Principal) -> None:
    if not (principal.can("intake.write") or principal.can("intake.review") or principal.can("intake.read")):
        raise PermissionDeniedError("缺少权限：intake.read、intake.write 或 intake.review")


@router.post("/batches", status_code=201)
def create_intake_batch(data: IntakeBatchCreate, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("intake.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).intake.create_batch(data.model_dump(mode="json"))


@router.get("/batches")
def list_intake_batches(
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(current_principal),
) -> dict:
    _require_intake_read(principal)
    items, total = _service().intake.list_batches(status=status, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/batches/{batch_id}")
def intake_batch_detail(batch_id: int, principal: Principal = Depends(current_principal)) -> dict:
    _require_intake_read(principal)
    return _service().intake.batch_detail(batch_id)


@router.get("/batches/{batch_id}/summary")
def intake_batch_summary(batch_id: int, principal: Principal = Depends(current_principal)) -> dict:
    _require_intake_read(principal)
    return _service().intake.reconcile_summary(batch_id)


@router.get("/batches/{batch_id}/snapshots")
def intake_batch_snapshots(batch_id: int, principal: Principal = Depends(current_principal)) -> list[dict]:
    _require_intake_read(principal)
    return _service().intake.snapshots(batch_id)


@router.post("/batches/{batch_id}/rounds", status_code=201)
def register_intake_round(
    batch_id: int, data: IntakeRoundCreate, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("intake.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).intake.register_round(batch_id, data.model_dump(mode="json"))


@router.post("/batches/{batch_id}/submit-review")
def submit_intake_batch(
    batch_id: int, data: IntakeSubmitReview, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("intake.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).intake.submit_for_review(batch_id, data.model_dump(mode="json"))


@router.post("/batches/{batch_id}/conclude")
def conclude_intake_batch(
    batch_id: int, data: IntakeConclude, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("intake.review")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).intake.conclude(batch_id, data.model_dump(mode="json"))


@router.post("/batches/{batch_id}/decisions")
def decide_intake_batch(
    batch_id: int, data: IntakeBatchDecision, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("intake.review")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).intake.decide_batch(batch_id, data.model_dump(mode="json"))


@router.post("/batches/{batch_id}/generate-cases")
def generate_intake_cases(
    batch_id: int, data: IntakeGenerate, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("intake.review")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).intake.generate_cases(batch_id, data.model_dump(mode="json"))


@router.get("/lines/{line_id}")
def intake_line_detail(line_id: int, principal: Principal = Depends(current_principal)) -> dict:
    _require_intake_read(principal)
    return _service().intake.line_detail(line_id)


@router.post("/lines/{line_id}/decision")
def decide_intake_line(
    line_id: int, data: IntakeLineDecision, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("intake.review")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).intake.decide_line(line_id, data.model_dump(mode="json"))


@router.post("/lines/{line_id}/corrections", status_code=201)
def correct_intake_line(
    line_id: int, data: IntakeCorrection, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("intake.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).intake.record_correction(line_id, data.model_dump(mode="json", exclude_unset=True))
