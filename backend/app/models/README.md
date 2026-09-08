# backend/app/models

## Purpose

ORM models and persistence entities.

## Contents

- `__init__.py`
- `__pycache__/`
- `activity_log.py`
- `approval_request.py`
- `approval_scenario.py`
- `control.py`
- `control_execution.py`
- `department.py`
- `global_config.py`
- `issue.py`
- `key_risk_indicator.py`
- `kri_history.py`
- `notification.py`
- `orphaned_item.py`
- `quarterly_metric_snapshot.py`
- `...`

## Notes

Mixin inventory:

- `ArchivableMixin` owns archive columns for soft-deletable registers.
- `AbstractVendorLink` is an abstract mixin for vendor-risk, vendor-control,
  and vendor-KRI junction tables. It provides the shared `id`, `vendor_id`
  (`ON DELETE CASCADE`), and `created_at` shape; vendor-link tables are not
  archivable.

Keep this README updated when responsibilities or structure in this folder change.

- `installation_identity.py`: explicit singleton deployment identity binding.
