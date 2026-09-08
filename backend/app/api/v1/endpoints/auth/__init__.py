"""Authentication endpoints for login, logout, and current user."""

from fastapi import APIRouter

from app.services.sso_token_service import verify_entra_id_token as verify_entra_id_token

from . import config, csrf, demo, local, logout, me, password, refresh, sso

router = APIRouter()
router.include_router(config.router)
router.include_router(csrf.router)
router.include_router(password.router)
router.include_router(me.router)
router.include_router(refresh.router)
router.include_router(logout.router)
router.include_router(sso.router)
router.include_router(demo.router)
router.include_router(local.router)

__all__ = [
    "router",
    "verify_entra_id_token",
]
