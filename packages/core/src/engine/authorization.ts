import type { DbAdapter } from '../interfaces/db-adapter.js';
import type { Role, PolicyCondition } from '../types/entities.js';

export class AuthorizationEngine {
  constructor(private db: DbAdapter) {}

  async authorize(userId: string, action: string, context?: Record<string, unknown>): Promise<boolean> {
    // 1. Get user (roles, permissions)
    const user = await this.db.findUserById(userId);
    if (!user) return false;

    // 2. Check access policies first - deny policies override everything
    const policies = await this.db.listPolicies();
    let policyAllowed = false;

    for (const policy of policies) {
      const actionMatches = policy.actions.some(a => this.matchesPermission(a, action));
      if (!actionMatches) continue;

      // Evaluate all conditions
      const conditionsMet = policy.conditions.length === 0 ||
        policy.conditions.every(c => this.evaluateCondition(c, context ?? {}));

      if (!conditionsMet) continue;

      // Deny policies override everything (including role permissions)
      if (policy.effect === 'deny') {
        return false;
      }

      if (policy.effect === 'allow') {
        policyAllowed = true;
      }
    }

    // 3. Check direct user permissions
    for (const perm of user.permissions) {
      if (this.matchesPermission(perm, action)) {
        return true;
      }
    }

    // 4. Resolve role hierarchy and check role permissions
    const roleNames = user.roles;
    const roles: Role[] = [];
    for (const roleName of roleNames) {
      const role = await this.db.getRole(roleName);
      if (role) roles.push(role);
    }

    const resolvedPermissions = await this.resolvePermissions(roles);
    for (const perm of resolvedPermissions) {
      if (this.matchesPermission(perm, action)) {
        return true;
      }
    }

    // 5. If an ABAC allow policy matched, grant access
    return policyAllowed;
  }

  async resolvePermissions(roles: Role[]): Promise<string[]> {
    const visited = new Set<string>();
    const permissions = new Set<string>();

    const resolve = async (roleList: Role[]): Promise<void> => {
      for (const role of roleList) {
        if (visited.has(role.name)) continue;
        visited.add(role.name);

        // Add this role's permissions
        for (const perm of role.permissions) {
          permissions.add(perm);
        }

        // Recursively resolve inherited roles
        const inheritedRoles: Role[] = [];
        for (const parentName of role.inherits) {
          const parentRole = await this.db.getRole(parentName);
          if (parentRole) inheritedRoles.push(parentRole);
        }

        if (inheritedRoles.length > 0) {
          await resolve(inheritedRoles);
        }
      }
    };

    await resolve(roles);
    return [...permissions];
  }

  matchesPermission(userPermission: string, requiredAction: string): boolean {
    // Exact match
    if (userPermission === requiredAction) return true;

    // Global wildcard
    if (userPermission === '*') return true;

    // Namespace wildcard: 'admin:*' matches 'admin:users', 'admin:settings', etc.
    if (userPermission.endsWith(':*')) {
      const prefix = userPermission.slice(0, -1); // 'admin:'
      if (requiredAction.startsWith(prefix)) return true;
    }

    return false;
  }

  evaluateCondition(condition: PolicyCondition, context: Record<string, unknown>): boolean {
    const contextValue = context[condition.attribute];

    switch (condition.operator) {
      case 'eq':
        return contextValue === condition.value;
      case 'neq':
        return contextValue !== condition.value;
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(contextValue);
      case 'not_in':
        return Array.isArray(condition.value) && !condition.value.includes(contextValue);
      case 'gt':
        return typeof contextValue === 'number' && typeof condition.value === 'number' && contextValue > condition.value;
      case 'lt':
        return typeof contextValue === 'number' && typeof condition.value === 'number' && contextValue < condition.value;
      case 'contains':
        return typeof contextValue === 'string' && typeof condition.value === 'string' && contextValue.includes(condition.value);
      case 'matches':
        if (typeof contextValue === 'string' && typeof condition.value === 'string') {
          try {
            return new RegExp(condition.value).test(contextValue);
          } catch {
            return false;
          }
        }
        return false;
      default:
        return false;
    }
  }
}
