// Role templates and the capability vocabulary shared by the neutral app and the host monitors.
// Roles are deliberately coarse-grained (viewer -> developer -> team_lead -> admin -> owner) so a
// workspace automation or team membership can be reasoned about as an indirect grant path.
export const ROLE_TEMPLATES: Record<string, { label: string; permissions: string[] }> = {
  viewer: {
    label: 'Viewer',
    permissions: ['org:read', 'project:read', 'pipeline:read', 'build:read', 'secret:read'],
  },
  developer: {
    label: 'Developer',
    permissions: [
      'org:read', 'project:read', 'project:write', 'pipeline:read', 'pipeline:write',
      'build:read', 'build:run', 'secret:read', 'secret:write', 'deployment:submit',
      'token:create', 'artifact:read', 'webhook:read',
    ],
  },
  team_lead: {
    label: 'Team Lead',
    permissions: [
      'org:read', 'project:read', 'project:write', 'pipeline:read', 'pipeline:write',
      'build:read', 'build:run', 'secret:read', 'secret:write', 'deployment:submit',
      'token:create', 'artifact:read', 'webhook:read',
      'team:manage', 'member:invite', 'automation:create',
    ],
  },
  admin: {
    label: 'Administrator',
    permissions: [
      'org:read', 'org:admin', 'project:read', 'project:write', 'project:transfer',
      'pipeline:read', 'pipeline:write', 'build:read', 'build:run',
      'secret:read', 'secret:write', 'deployment:submit', 'deployment:approve',
      'token:create', 'token:revoke', 'artifact:read', 'artifact:share',
      'webhook:read', 'webhook:manage', 'team:manage', 'member:invite', 'member:manage',
      'automation:create', 'audit:read',
    ],
  },
  owner: {
    label: 'Owner',
    permissions: [
      'org:read', 'org:admin', 'org:billing', 'project:read', 'project:write', 'project:transfer',
      'pipeline:read', 'pipeline:write', 'build:read', 'build:run',
      'secret:read', 'secret:write', 'deployment:submit', 'deployment:approve', 'deployment:release',
      'token:create', 'token:revoke', 'artifact:read', 'artifact:share',
      'webhook:read', 'webhook:manage', 'team:manage', 'member:invite', 'member:manage',
      'automation:create', 'audit:read',
    ],
  },
}

export function permissionsForRole(role: string): string[] {
  return ROLE_TEMPLATES[role]?.permissions.slice() ?? ROLE_TEMPLATES.viewer!.permissions.slice()
}

export function hasPermission(permissions: readonly string[], needed: string): boolean {
  if (permissions.includes(needed)) return true
  if (permissions.includes('org:admin')) {
    // Administrators own every tenant-scoped capability except billing/release sign-off semantics
    // that the workflow itself enforces separately.
    return !needed.startsWith('org:billing') && needed !== 'deployment:release'
  }
  return false
}

export const ROLE_RANK: Record<string, number> = {
  viewer: 0, developer: 1, team_lead: 2, admin: 3, owner: 4,
}

export function roleRank(role: string): number {
  return ROLE_RANK[role] ?? 0
}

/** Roles that carry organization administration authority. */
export const ORG_ADMIN_ROLES = new Set(['admin', 'owner'])
