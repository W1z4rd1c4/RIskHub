/**
 * Access management types matching backend schemas.
 */

export type AccessScopeEnum = 'global' | 'department' | 'manager';

export interface PermissionRead {
    resource: string;
    action: string;
    description: string | null;
}

export interface RoleWithPermissions {
    id: number;
    name: string;
    display_name: string;
    description: string | null;
    permissions: PermissionRead[];
}

export interface AccessUserRead {
    id: number;
    email: string;
    name: string;
    is_active: boolean;
    local_suspended?: boolean;
    local_enrollment_state?: string | null;
    role_id: number;
    role: {
        id: number;
        name: string;
        display_name: string;
        description: string | null;
    };
    department_id: number | null;
    department_name: string | null;
    manager_id: number | null;
    manager_name: string | null;
    access_scope: AccessScopeEnum;
    scope_label: string;
    effective_permissions: string[];
    external_id?: string | null;
    job_title?: string | null;
    entra_business_role?: string | null;
    directory_last_checked_at?: string | null;
    directory_last_seen_at?: string | null;
    directory_sync_status?: string | null;
    deprovisioned_at?: string | null;
    deprovision_reason?: string | null;
    capabilities: AccessUserCapabilities;
}

export interface AccessUserCapabilities {
    can_edit_identity: boolean;
    can_edit_business_access: boolean;
    can_edit_role: boolean;
    can_deactivate: boolean;
    can_change_active_status: boolean;
    can_break_glass_enable: boolean;
    can_revoke_sessions: boolean;
    can_resume?: boolean;
    active_status_block_reason?: string | null;
    directory_owned_fields?: string[];
}

export interface AccessUserUpdate {
    name?: string;
    email?: string;
    role_id?: number;
    department_id?: number | null;
    manager_id?: number | null;
    access_scope?: AccessScopeEnum;
    is_active?: boolean;
}

export interface AccessUserFilters {
    department_id?: number;
    role_id?: number;
    access_scope?: AccessScopeEnum;
    is_privileged?: boolean;
}
