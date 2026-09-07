import type {
    AccessUserRead,
    PermissionRead as AccessPermissionRead,
    RoleWithPermissions,
} from '@/types/access';
import type { DirectoryImportResponse, DirectoryUser } from '@/types/directory';
import type { ThreatStewardLookup, UserDirectoryEntry, UserDirectoryListResponse, UserDirectoryRoleFacet, UserLookup, UserRead, UserShellSummary, Role } from '@/types/user';

import {
    passthroughObject,
    stringArraySchema,
    z,
} from '../common';

const roleSchema: z.ZodType<Role> = passthroughObject({
    id: z.number(),
    name: z.string(),
    display_name: z.string(),
    description: z.string().nullable(),
});

export const userReadSchema: z.ZodType<UserRead> = passthroughObject({
    id: z.number(),
    email: z.string(),
    name: z.string(),
    is_active: z.boolean(),
    role: roleSchema,
    entra_business_role: z.string().nullable().optional(),
    department_id: z.number().nullable(),
    manager_id: z.number().nullable(),
    manager_name: z.string().nullable(),
    created_at: z.string(),
    updated_at: z.string(),
});
export const userReadArraySchema = z.array(userReadSchema);

export const userLookupSchema: z.ZodType<UserLookup> = passthroughObject({
    id: z.number(),
    name: z.string(),
    email: z.string(),
    role_name: z.string().nullable().optional(),
    department_id: z.number().nullable().optional(),
    department_name: z.string().nullable().optional(),
    manager_id: z.number().nullable().optional(),
});
export const userLookupArraySchema = z.array(userLookupSchema);

export const threatStewardLookupSchema: z.ZodType<ThreatStewardLookup> = passthroughObject({
    id: z.number(),
    name: z.string(),
    email: z.string(),
});
export const threatStewardLookupArraySchema = z.array(threatStewardLookupSchema);

export const userDirectoryEntrySchema: z.ZodType<UserDirectoryEntry> = passthroughObject({
    id: z.number(),
    name: z.string(),
    email: z.string(),
    role_name: z.string().nullable().optional(),
    role_display_name: z.string().nullable().optional(),
    department_id: z.number().nullable().optional(),
    department_name: z.string().nullable().optional(),
});
export const userDirectoryRoleFacetSchema: z.ZodType<UserDirectoryRoleFacet> = passthroughObject({
    name: z.string(),
    display_name: z.string(),
    count: z.number(),
});
export const userDirectoryCapabilitiesSchema = passthroughObject({
    can_read_directory: z.boolean(),
    can_view_access_details: z.boolean(),
    can_use_role_facets: z.boolean(),
    can_create_local_user: z.boolean(),
    can_import_directory_user: z.boolean(),
});
export const userDirectoryListResponseSchema: z.ZodType<UserDirectoryListResponse> =
    passthroughObject({
        items: z.array(userDirectoryEntrySchema),
        available_roles: z.array(userDirectoryRoleFacetSchema),
        total: z.number(),
        skip: z.number(),
        limit: z.number(),
        capabilities: userDirectoryCapabilitiesSchema.nullable().optional(),
    });

export const userShellSummarySchema: z.ZodType<UserShellSummary> = passthroughObject({
    unread_notifications_count: z.number(),
    pending_approvals_count: z.number(),
    questionnaire_inbox_count: z.number(),
    orphan_total_count: z.number(),
    can_view_governance: z.boolean(),
    generated_at: z.string(),
});

const accessPermissionReadSchema: z.ZodType<AccessPermissionRead> = passthroughObject({
    resource: z.string(),
    action: z.string(),
    description: z.string().nullable(),
});
export const accessUserCapabilitiesSchema = passthroughObject({
    can_edit_identity: z.boolean(),
    can_edit_business_access: z.boolean(),
    can_edit_role: z.boolean(),
    can_deactivate: z.boolean(),
    can_change_active_status: z.boolean(),
    can_break_glass_enable: z.boolean(),
    can_revoke_sessions: z.boolean(),
    can_resume: z.boolean().optional(),
    active_status_block_reason: z.string().nullable().optional(),
    directory_owned_fields: z.array(z.string()).optional(),
});
export const accessUserReadSchema: z.ZodType<AccessUserRead> = passthroughObject({
    id: z.number(),
    email: z.string(),
    name: z.string(),
    is_active: z.boolean(),
    local_suspended: z.boolean().optional(),
    local_enrollment_state: z.string().nullable().optional(),
    role_id: z.number(),
    role: passthroughObject({
        id: z.number(),
        name: z.string(),
        display_name: z.string(),
        description: z.string().nullable(),
    }),
    department_id: z.number().nullable(),
    department_name: z.string().nullable(),
    manager_id: z.number().nullable(),
    manager_name: z.string().nullable(),
    access_scope: z.enum(['global', 'department', 'manager']),
    scope_label: z.string(),
    effective_permissions: stringArraySchema,
    external_id: z.string().nullable().optional(),
    job_title: z.string().nullable().optional(),
    entra_business_role: z.string().nullable().optional(),
    directory_last_checked_at: z.string().nullable().optional(),
    directory_last_seen_at: z.string().nullable().optional(),
    directory_sync_status: z.string().nullable().optional(),
    deprovisioned_at: z.string().nullable().optional(),
    deprovision_reason: z.string().nullable().optional(),
    capabilities: accessUserCapabilitiesSchema,
});
export const accessUserReadArraySchema = z.array(accessUserReadSchema);
export const roleWithPermissionsSchema: z.ZodType<RoleWithPermissions> = passthroughObject({
    id: z.number(),
    name: z.string(),
    display_name: z.string(),
    description: z.string().nullable(),
    permissions: z.array(accessPermissionReadSchema),
});
export const roleWithPermissionsArraySchema = z.array(roleWithPermissionsSchema);

export const directoryUserSchema: z.ZodType<DirectoryUser> = passthroughObject({
    external_id: z.string(),
    display_name: z.string(),
    email: z.string().nullable(),
    user_principal_name: z.string().nullable(),
    department: z.string().nullable(),
    job_title: z.string().nullable(),
    account_enabled: z.boolean(),
    source: z.enum(['graph', 'ad_emulator']),
});
export const directoryUserArraySchema = z.array(directoryUserSchema);
export const directoryImportResponseSchema: z.ZodType<DirectoryImportResponse> =
    passthroughObject({
        status: z.enum(['created', 'updated']),
        user_id: z.number(),
        email: z.string(),
        name: z.string(),
        external_id: z.string(),
        department_id: z.number().nullable(),
        department_name: z.string().nullable(),
        entra_business_role: z.string().nullable(),
        role_id: z.number(),
        role_name: z.string().nullable(),
        directory_sync_status: z.string().nullable(),
    });
