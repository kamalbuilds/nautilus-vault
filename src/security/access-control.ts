/**
 * Access Control - Role-based and attribute-based access control
 */

import { SecurityError } from '../types';

export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: Permission[];
  inherits?: string[];
}

export interface Permission {
  resource: string;
  action: string;
  conditions?: AccessCondition[];
}

export interface AccessCondition {
  attribute: string;
  operator: 'EQUALS' | 'NOT_EQUALS' | 'IN' | 'NOT_IN' | 'GREATER_THAN' | 'LESS_THAN';
  value: any;
}

export interface AccessRequest {
  subject: string;
  resource: string;
  action: string;
  context: Record<string, any>;
}

export interface AccessDecision {
  granted: boolean;
  reason: string;
  appliedPolicies: string[];
  obligations?: string[];
}

export class AccessControl {
  private roles: Map<string, Role> = new Map();
  private userRoles: Map<string, string[]> = new Map();
  private policies: Map<string, AccessPolicy> = new Map();

  constructor() {
    this.initializeDefaultRoles();
  }

  async grantRole(userId: string, roleId: string): Promise<void> {
    const role = this.roles.get(roleId);
    if (!role) {
      throw new SecurityError(`Role not found: ${roleId}`, 'ROLE_NOT_FOUND');
    }

    const userRoles = this.userRoles.get(userId) || [];
    if (!userRoles.includes(roleId)) {
      userRoles.push(roleId);
      this.userRoles.set(userId, userRoles);
    }
  }

  async revokeRole(userId: string, roleId: string): Promise<void> {
    const userRoles = this.userRoles.get(userId) || [];
    const index = userRoles.indexOf(roleId);
    if (index !== -1) {
      userRoles.splice(index, 1);
      this.userRoles.set(userId, userRoles);
    }
  }

  async checkAccess(request: AccessRequest): Promise<AccessDecision> {
    try {
      const userRoles = this.userRoles.get(request.subject) || [];
      const userPermissions = this.getUserPermissions(userRoles);

      // Check role-based permissions
      const roleDecision = this.checkRoleBasedAccess(userPermissions, request);
      if (roleDecision.granted) {
        return roleDecision;
      }

      // Check policy-based permissions
      const policyDecision = await this.checkPolicyBasedAccess(request);

      return {
        granted: policyDecision.granted,
        reason: policyDecision.reason || roleDecision.reason,
        appliedPolicies: policyDecision.appliedPolicies || [],
        obligations: policyDecision.obligations
      };
    } catch (error) {
      throw new SecurityError(`Access check failed: ${(error as Error).message}`, 'ACCESS_CHECK_ERROR');
    }
  }

  async defineRole(role: Role): Promise<void> {
    this.roles.set(role.id, role);
  }

  async definePolicy(policyId: string, policy: AccessPolicy): Promise<void> {
    this.policies.set(policyId, policy);
  }

  getUserRoles(userId: string): string[] {
    return this.userRoles.get(userId) || [];
  }

  private getUserPermissions(roleIds: string[]): Permission[] {
    const permissions: Permission[] = [];
    const processedRoles = new Set<string>();

    const collectPermissions = (roleId: string) => {
      if (processedRoles.has(roleId)) return;
      processedRoles.add(roleId);

      const role = this.roles.get(roleId);
      if (role) {
        permissions.push(...role.permissions);

        // Process inherited roles
        if (role.inherits) {
          role.inherits.forEach(inheritedRoleId => {
            collectPermissions(inheritedRoleId);
          });
        }
      }
    };

    roleIds.forEach(roleId => collectPermissions(roleId));
    return permissions;
  }

  private checkRoleBasedAccess(permissions: Permission[], request: AccessRequest): AccessDecision {
    for (const permission of permissions) {
      if (this.matchesPermission(permission, request)) {
        if (!permission.conditions || this.evaluateConditions(permission.conditions, request.context)) {
          return {
            granted: true,
            reason: `Access granted by permission: ${permission.resource}:${permission.action}`,
            appliedPolicies: []
          };
        }
      }
    }

    return {
      granted: false,
      reason: 'No matching permissions found',
      appliedPolicies: []
    };
  }

  private async checkPolicyBasedAccess(request: AccessRequest): Promise<AccessDecision> {
    for (const [policyId, policy] of this.policies) {
      if (policy.applies(request)) {
        const decision = await policy.evaluate(request);
        if (decision.granted) {
          return {
            ...decision,
            appliedPolicies: [policyId]
          };
        }
      }
    }

    return {
      granted: false,
      reason: 'No applicable policies grant access',
      appliedPolicies: []
    };
  }

  private matchesPermission(permission: Permission, request: AccessRequest): boolean {
    return this.matchesResource(permission.resource, request.resource) &&
           this.matchesAction(permission.action, request.action);
  }

  private matchesResource(permissionResource: string, requestResource: string): boolean {
    // Support wildcards
    if (permissionResource === '*') return true;
    if (permissionResource.endsWith('*')) {
      const prefix = permissionResource.slice(0, -1);
      return requestResource.startsWith(prefix);
    }
    return permissionResource === requestResource;
  }

  private matchesAction(permissionAction: string, requestAction: string): boolean {
    if (permissionAction === '*') return true;
    return permissionAction === requestAction;
  }

  private evaluateConditions(conditions: AccessCondition[], context: Record<string, any>): boolean {
    return conditions.every(condition => this.evaluateCondition(condition, context));
  }

  private evaluateCondition(condition: AccessCondition, context: Record<string, any>): boolean {
    const contextValue = context[condition.attribute];

    switch (condition.operator) {
      case 'EQUALS':
        return contextValue === condition.value;
      case 'NOT_EQUALS':
        return contextValue !== condition.value;
      case 'IN':
        return Array.isArray(condition.value) && condition.value.includes(contextValue);
      case 'NOT_IN':
        return Array.isArray(condition.value) && !condition.value.includes(contextValue);
      case 'GREATER_THAN':
        return contextValue > condition.value;
      case 'LESS_THAN':
        return contextValue < condition.value;
      default:
        return false;
    }
  }

  private initializeDefaultRoles(): void {
    // Admin role
    const adminRole: Role = {
      id: 'admin',
      name: 'Administrator',
      description: 'Full system access',
      permissions: [
        { resource: '*', action: '*' }
      ]
    };

    // User role
    const userRole: Role = {
      id: 'user',
      name: 'Standard User',
      description: 'Standard user access',
      permissions: [
        { resource: 'profile', action: 'read' },
        { resource: 'profile', action: 'update' },
        { resource: 'data', action: 'read' }
      ]
    };

    // Privacy Officer role
    const privacyOfficerRole: Role = {
      id: 'privacy-officer',
      name: 'Privacy Officer',
      description: 'Privacy management access',
      permissions: [
        { resource: 'privacy', action: '*' },
        { resource: 'consent', action: '*' },
        { resource: 'data-requests', action: '*' }
      ]
    };

    this.roles.set(adminRole.id, adminRole);
    this.roles.set(userRole.id, userRole);
    this.roles.set(privacyOfficerRole.id, privacyOfficerRole);
  }
}

export interface AccessPolicy {
  applies(request: AccessRequest): boolean;
  evaluate(request: AccessRequest): Promise<AccessDecision>;
}