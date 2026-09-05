from __future__ import annotations

from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.activity_logger import log_activity
from app.core.audit import vendor as audit_vendor
from app.core.exceptions import NotFoundError
from app.models import User, Vendor
from app.schemas.vendor import VendorCreate, VendorRead, VendorUpdate
from app.services.transaction_boundary import commit_service_boundary

from .policy import (
    assert_vendor_archive_allowed,
    assert_vendor_create_allowed,
    assert_vendor_governance_update_allowed,
    assert_vendor_ordinary_mutation_allowed,
    assert_vendor_readable,
    assert_vendor_restore_allowed,
    assert_vendor_update_allowed,
    load_vendor_with_deps,
)
from .projection import serialize_vendor_detail_with_derived


async def create_vendor_detail(
    *,
    db: AsyncSession,
    payload: VendorCreate,
    current_user: User,
) -> VendorRead | JSONResponse:
    from app.services._governed_mutations.vendor_mutations import (
        acquire_vendor_creation_name_lock,
        submit_vendor_creation_if_required,
    )

    await acquire_vendor_creation_name_lock(db, vendor_name=payload.name)
    await assert_vendor_create_allowed(
        db,
        current_user=current_user,
        department_id=payload.department_id,
        owner_user_id=payload.outsourcing_owner_user_id,
    )
    queued = await submit_vendor_creation_if_required(
        db=db,
        payload=payload,
        current_user=current_user,
    )
    if queued is not None:
        return queued

    vendor = Vendor(**payload.model_dump(exclude={"request_reason"}))
    db.add(vendor)
    await db.flush()

    await audit_vendor.vendor_created(
        db,
        actor=current_user,
        vendor=vendor,
        log_activity_func=log_activity,
    )
    await commit_service_boundary(db, boundary="vendor_create")
    await db.refresh(vendor)

    refreshed = await load_vendor_with_deps(db, vendor.id)
    if not refreshed:
        raise NotFoundError("Vendor not found")
    return await serialize_vendor_detail_with_derived(db, refreshed, current_user=current_user)


async def read_vendor_detail(
    *,
    db: AsyncSession,
    vendor_id: int,
    current_user: User,
) -> VendorRead:
    vendor = await assert_vendor_readable(db, vendor_id=vendor_id, current_user=current_user)
    return await serialize_vendor_detail_with_derived(db, vendor, current_user=current_user)


async def update_vendor_detail(
    *,
    db: AsyncSession,
    vendor_id: int,
    payload: VendorUpdate,
    current_user: User,
) -> VendorRead | JSONResponse:
    vendor = await assert_vendor_update_allowed(db, vendor_id=vendor_id, current_user=current_user)
    updates = {field: getattr(payload, field) for field in payload.model_fields_set}
    updates.pop("request_reason", None)
    updates = {
        field: value
        for field, value in updates.items()
        if getattr(vendor, field) != (
            value.value if hasattr(value, "value") else value
        )
    }
    if not updates:
        return await serialize_vendor_detail_with_derived(db, vendor, current_user=current_user)

    proposed_owner_id = updates.get(
        "outsourcing_owner_user_id",
        vendor.outsourcing_owner_user_id,
    )
    vendor = await assert_vendor_ordinary_mutation_allowed(
        db,
        vendor_id=vendor_id,
        current_user=current_user,
        additional_owner_user_ids=(proposed_owner_id,),
    )
    await assert_vendor_governance_update_allowed(db, current_user=current_user, vendor=vendor, updates=updates)
    from app.services._governed_mutations.vendor_mutations import (
        submit_vendor_edit_if_required,
    )

    queued = await submit_vendor_edit_if_required(
        db=db,
        vendor=vendor,
        payload=payload,
        current_user=current_user,
        updates=updates,
    )
    if queued is not None:
        return queued
    changes = audit_vendor.vendor_update_changes(vendor, updates)
    for field, value in updates.items():
        if hasattr(value, "value"):
            value = value.value
        setattr(vendor, field, value)
    vendor.governance_version += 1

    await audit_vendor.vendor_updated(
        db,
        actor=current_user,
        vendor=vendor,
        changes=changes,
        log_activity_func=log_activity,
    )
    await commit_service_boundary(db, boundary="vendor_update")
    await db.refresh(vendor)

    refreshed = await load_vendor_with_deps(db, vendor.id)
    if not refreshed:
        raise NotFoundError("Vendor not found")
    return await serialize_vendor_detail_with_derived(db, refreshed, current_user=current_user)


async def archive_vendor_detail(
    *,
    db: AsyncSession,
    vendor_id: int,
    current_user: User,
    request_reason: str | None = None,
) -> JSONResponse | None:
    vendor = await assert_vendor_archive_allowed(db, vendor_id=vendor_id, current_user=current_user)
    from app.services._governed_mutations.vendor_mutations import (
        submit_vendor_archive_if_required,
    )

    queued = await submit_vendor_archive_if_required(
        db=db,
        vendor=vendor,
        current_user=current_user,
        request_reason=request_reason,
    )
    if queued is not None:
        return queued
    changes = audit_vendor.vendor_archive_changes(vendor)
    vendor.mark_archived(current_user)
    vendor.governance_version += 1

    await audit_vendor.vendor_archived(
        db,
        actor=current_user,
        vendor=vendor,
        changes=changes,
        log_activity_func=log_activity,
    )
    await commit_service_boundary(db, boundary="vendor_archive")
    return None


async def restore_vendor_detail(
    *,
    db: AsyncSession,
    vendor_id: int,
    current_user: User,
) -> VendorRead:
    vendor = await assert_vendor_restore_allowed(db, vendor_id=vendor_id, current_user=current_user)
    changes = audit_vendor.vendor_restore_changes(vendor)
    vendor.mark_restored(current_user)
    vendor.governance_version += 1
    await audit_vendor.vendor_restored(
        db,
        actor=current_user,
        vendor=vendor,
        changes=changes,
        log_activity_func=log_activity,
    )
    await commit_service_boundary(db, boundary="vendor_restore")
    await db.refresh(vendor)

    refreshed = await load_vendor_with_deps(db, vendor.id)
    if not refreshed:
        raise NotFoundError("Vendor not found")
    return await serialize_vendor_detail_with_derived(db, refreshed, current_user=current_user)
