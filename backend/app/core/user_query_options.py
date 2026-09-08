"""
Shared query options for User model selectinload patterns.

Centralizes relationship-loading specifications used across user-related endpoints
to reduce duplication while preserving exact loading semantics.
"""

from sqlalchemy.orm import selectinload

from app.models import Role, RolePermission, User


def user_selectinload_options(*, include_permissions: bool = False, include_manager: bool = True) -> list:
    """
    Build SQLAlchemy selectinload options for User queries.

    Args:
        include_permissions: If True, include role->permissions->permission chain
                            (heavier, used by access management endpoints).
                            If False, load role without its permission chain.
        include_manager: Include the self-referential display relationship.
                         Disable for populate_existing authority queries: a manager
                         may also be a selected User, and refreshing it through a
                         second loader path can expire its already-loaded role.

    Returns:
        List of selectinload options to pass to .options().
    """
    role_option = selectinload(User.role)
    if include_permissions:
        role_option = role_option.selectinload(Role.permissions).selectinload(RolePermission.permission)
    options = [role_option, selectinload(User.department)]
    if include_manager:
        options.append(selectinload(User.manager))
    return options
