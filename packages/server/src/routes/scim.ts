import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

/**
 * SCIM 2.0 Provisioning Endpoints (Stub Implementation)
 *
 * These endpoints implement the SCIM 2.0 protocol for automated user
 * provisioning from identity providers (Okta, Azure AD, OneLogin, etc.).
 *
 * In production, full SCIM compliance requires:
 * - Complete filter parsing (eq, co, sw, etc.)
 * - PATCH operations with RFC 7644 path expressions
 * - ETags for concurrency control
 * - Full schema validation
 *
 * Currently provides basic CRUD mapping to the Argus user/org model.
 */

// SCIM constants
const SCIM_SCHEMA_USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_SCHEMA_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const SCIM_SCHEMA_LIST = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const SCIM_SCHEMA_SP_CONFIG = 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig';
const SCIM_SCHEMA_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Schema';

/**
 * Bearer token auth for SCIM endpoints. Validates API key from Authorization header.
 */
async function requireScimAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = request.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    reply.status(401).send({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      detail: 'Missing or invalid authorization header',
      status: '401',
    });
    return;
  }

  const token = header.slice(7);
  const result = await request.server.argus.apiKeys.validate(token);
  if (!result) {
    reply.status(401).send({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      detail: 'Invalid API key',
      status: '401',
    });
    return;
  }

  // Check for SCIM permission
  if (!result.apiKey.permissions.includes('scim') && !result.apiKey.permissions.includes('admin')) {
    reply.status(403).send({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      detail: 'Insufficient permissions for SCIM operations',
      status: '403',
    });
    return;
  }
}

/** Convert an Argus User to SCIM User resource */
function toScimUser(user: any, baseUrl: string): any {
  return {
    schemas: [SCIM_SCHEMA_USER],
    id: user.id,
    externalId: user.metadata?.externalId ?? user.id,
    userName: user.email,
    name: {
      formatted: user.displayName,
      givenName: user.displayName?.split(' ')[0] ?? '',
      familyName: user.displayName?.split(' ').slice(1).join(' ') ?? '',
    },
    displayName: user.displayName,
    emails: [
      { value: user.email, primary: true, type: 'work' },
    ],
    active: user.deletedAt === null || user.deletedAt === undefined,
    meta: {
      resourceType: 'User',
      created: user.createdAt instanceof Date ? user.createdAt.toISOString() : user.createdAt,
      lastModified: user.updatedAt instanceof Date ? user.updatedAt.toISOString() : user.updatedAt,
      location: `${baseUrl}/scim/v2/Users/${user.id}`,
    },
  };
}

/** Convert an Argus Organization to SCIM Group resource */
function toScimGroup(org: any, members: any[], baseUrl: string): any {
  return {
    schemas: [SCIM_SCHEMA_GROUP],
    id: org.id,
    displayName: org.name,
    members: members.map((m: any) => ({
      value: m.userId,
      display: m.userId,
    })),
    meta: {
      resourceType: 'Group',
      created: org.createdAt instanceof Date ? org.createdAt.toISOString() : org.createdAt,
      lastModified: org.updatedAt instanceof Date ? org.updatedAt.toISOString() : org.updatedAt,
      location: `${baseUrl}/scim/v2/Groups/${org.id}`,
    },
  };
}

export async function scimRoutes(app: FastifyInstance): Promise<void> {
  const baseUrl = '';  // Will be relative; clients should use full URL

  // ─── Service Provider Config ────────────────────────────────────────

  app.get('/scim/v2/ServiceProviderConfig', { preHandler: [requireScimAuth] }, async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({
      schemas: [SCIM_SCHEMA_SP_CONFIG],
      documentationUri: 'https://argusjs.dev/docs/scim',
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 200 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          type: 'oauthbearertoken',
          name: 'OAuth Bearer Token',
          description: 'Authentication scheme using API key as Bearer token',
        },
      ],
    });
  });

  // ─── Schemas ────────────────────────────────────────────────────────

  app.get('/scim/v2/Schemas', { preHandler: [requireScimAuth] }, async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({
      schemas: [SCIM_SCHEMA_LIST],
      totalResults: 2,
      itemsPerPage: 2,
      startIndex: 1,
      Resources: [
        {
          schemas: [SCIM_SCHEMA_SCHEMA],
          id: SCIM_SCHEMA_USER,
          name: 'User',
          description: 'User Account',
        },
        {
          schemas: [SCIM_SCHEMA_SCHEMA],
          id: SCIM_SCHEMA_GROUP,
          name: 'Group',
          description: 'Group (Organization)',
        },
      ],
    });
  });

  // ─── Users ──────────────────────────────────────────────────────────

  // List users with pagination and filter
  app.get('/scim/v2/Users', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as { filter?: string; startIndex?: string; count?: string };
    const startIndex = parseInt(query.startIndex ?? '1', 10);
    const count = Math.min(parseInt(query.count ?? '100', 10), 200);

    // Basic filter parsing: filter=userName eq "user@example.com"
    let search: string | undefined;
    if (query.filter) {
      const match = query.filter.match(/userName\s+eq\s+"([^"]+)"/i);
      if (match) {
        search = match[1];
      }
    }

    const result = await (request.server.argus as any).db.listUsers({
      search,
      limit: count,
      offset: startIndex - 1,
    });

    return reply.status(200).send({
      schemas: [SCIM_SCHEMA_LIST],
      totalResults: result.total,
      itemsPerPage: count,
      startIndex,
      Resources: result.users.map((u: any) => toScimUser(u, baseUrl)),
    });
  });

  // Get user by ID
  app.get('/scim/v2/Users/:id', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const user = await (request.server.argus as any).db.findUserById(id);

    if (!user) {
      return reply.status(404).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User not found',
        status: '404',
      });
    }

    return reply.status(200).send(toScimUser(user, baseUrl));
  });

  // Create user
  app.post('/scim/v2/Users', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as any;

    const email = body.userName ?? body.emails?.[0]?.value;
    if (!email) {
      return reply.status(400).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'userName or emails[0].value is required',
        status: '400',
      });
    }

    // Check if user already exists
    const existing = await (request.server.argus as any).db.findUserByEmail(email.toLowerCase());
    if (existing) {
      return reply.status(409).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User already exists',
        status: '409',
      });
    }

    const displayName = body.displayName ?? body.name?.formatted ?? body.name?.givenName ?? email;

    const user = await (request.server.argus as any).db.createUser({
      email: email.toLowerCase(),
      passwordHash: null,  // SCIM-provisioned users don't get a password by default
      displayName,
      emailVerified: true, // Trust IdP email verification
      roles: ['user'],
      metadata: { externalId: body.externalId, provisionedBy: 'scim' },
    });

    return reply.status(201).send(toScimUser(user, baseUrl));
  });

  // Replace user (PUT)
  app.put('/scim/v2/Users/:id', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;

    const user = await (request.server.argus as any).db.findUserById(id);
    if (!user) {
      return reply.status(404).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User not found',
        status: '404',
      });
    }

    const displayName = body.displayName ?? body.name?.formatted ?? user.displayName;
    const email = body.userName ?? body.emails?.[0]?.value ?? user.email;
    const active = body.active !== undefined ? body.active : true;

    const updates: Record<string, any> = {
      displayName,
      email: email.toLowerCase(),
    };

    if (!active) {
      updates.deletedAt = new Date();
    } else if (user.deletedAt) {
      updates.deletedAt = null;
    }

    const updated = await (request.server.argus as any).db.updateUser(id, updates);
    return reply.status(200).send(toScimUser(updated, baseUrl));
  });

  // Patch user (PATCH)
  app.patch('/scim/v2/Users/:id', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;

    const user = await (request.server.argus as any).db.findUserById(id);
    if (!user) {
      return reply.status(404).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User not found',
        status: '404',
      });
    }

    const updates: Record<string, any> = {};

    // Process SCIM PATCH operations
    if (body.Operations) {
      for (const op of body.Operations) {
        const path = op.path?.toLowerCase();
        const value = op.value;

        if (path === 'active' || (!path && typeof value === 'object' && 'active' in value)) {
          const active = path === 'active' ? value : value.active;
          if (!active) {
            updates.deletedAt = new Date();
          } else if (user.deletedAt) {
            updates.deletedAt = null;
          }
        }
        if (path === 'displayname' || (!path && typeof value === 'object' && 'displayName' in value)) {
          updates.displayName = path === 'displayname' ? value : value.displayName;
        }
        if (path === 'username' || (!path && typeof value === 'object' && 'userName' in value)) {
          const email = path === 'username' ? value : value.userName;
          updates.email = email.toLowerCase();
        }
      }
    }

    const updated = Object.keys(updates).length > 0
      ? await (request.server.argus as any).db.updateUser(id, updates)
      : user;

    return reply.status(200).send(toScimUser(updated, baseUrl));
  });

  // Delete (deactivate) user
  app.delete('/scim/v2/Users/:id', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };

    const user = await (request.server.argus as any).db.findUserById(id);
    if (!user) {
      return reply.status(404).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User not found',
        status: '404',
      });
    }

    // Soft delete (deactivate)
    await (request.server.argus as any).db.softDeleteUser(id);

    return reply.status(204).send();
  });

  // ─── Groups (Organizations) ─────────────────────────────────────────

  // List groups
  app.get('/scim/v2/Groups', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as { filter?: string; startIndex?: string; count?: string };
    const startIndex = parseInt(query.startIndex ?? '1', 10);
    const count = Math.min(parseInt(query.count ?? '100', 10), 200);

    // Stub: list groups — in production, DbAdapter would have a listOrganizations method
    // For now, return empty list to satisfy SCIM compliance
    return reply.status(200).send({
      schemas: [SCIM_SCHEMA_LIST],
      totalResults: 0,
      itemsPerPage: count,
      startIndex,
      Resources: [],
    });
  });

  // Get group by ID
  app.get('/scim/v2/Groups/:id', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };

    try {
      const org = await request.server.argus.orgs.get(id);
      const members = await request.server.argus.orgs.listMembers(id);
      return reply.status(200).send(toScimGroup(org, members, baseUrl));
    } catch {
      return reply.status(404).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'Group not found',
        status: '404',
      });
    }
  });

  // Create group
  app.post('/scim/v2/Groups', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as any;
    const displayName = body.displayName;

    if (!displayName) {
      return reply.status(400).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'displayName is required',
        status: '400',
      });
    }

    // Generate slug from displayName
    const slug = displayName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

    // Use first member as owner, or a system placeholder
    const ownerId = body.members?.[0]?.value ?? 'system';

    const org = await request.server.argus.orgs.create({
      name: displayName,
      slug,
      ownerId,
    });

    // Add specified members
    if (body.members) {
      for (const member of body.members) {
        try {
          await request.server.argus.orgs.addMember({
            userId: member.value,
            orgId: org.id,
            role: 'member',
          });
        } catch {
          // Ignore member add failures (user might not exist)
        }
      }
    }

    const members = await request.server.argus.orgs.listMembers(org.id);
    return reply.status(201).send(toScimGroup(org, members, baseUrl));
  });

  // Replace group (PUT)
  app.put('/scim/v2/Groups/:id', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;

    try {
      const org = await request.server.argus.orgs.get(id);

      if (body.displayName) {
        await request.server.argus.orgs.update(id, { name: body.displayName });
      }

      // Stub: full member replacement would require removing all existing and adding new
      const members = await request.server.argus.orgs.listMembers(id);
      const updatedOrg = await request.server.argus.orgs.get(id);
      return reply.status(200).send(toScimGroup(updatedOrg, members, baseUrl));
    } catch {
      return reply.status(404).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'Group not found',
        status: '404',
      });
    }
  });

  // Patch group (PATCH)
  app.patch('/scim/v2/Groups/:id', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;

    try {
      const org = await request.server.argus.orgs.get(id);

      if (body.Operations) {
        for (const op of body.Operations) {
          if (op.path === 'displayName' && op.op === 'replace') {
            await request.server.argus.orgs.update(id, { name: op.value });
          }
          // Stub: member add/remove operations
          if (op.path === 'members' && op.op === 'add' && op.value) {
            for (const member of op.value) {
              try {
                await request.server.argus.orgs.addMember({
                  userId: member.value,
                  orgId: id,
                  role: 'member',
                });
              } catch { /* ignore */ }
            }
          }
          if (op.path?.startsWith('members[') && op.op === 'remove') {
            // Parse member ID from path like members[value eq "userId"]
            const match = op.path.match(/members\[value\s+eq\s+"([^"]+)"\]/);
            if (match) {
              try {
                await request.server.argus.orgs.removeMember(id, match[1]);
              } catch { /* ignore */ }
            }
          }
        }
      }

      const updatedOrg = await request.server.argus.orgs.get(id);
      const members = await request.server.argus.orgs.listMembers(id);
      return reply.status(200).send(toScimGroup(updatedOrg, members, baseUrl));
    } catch {
      return reply.status(404).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'Group not found',
        status: '404',
      });
    }
  });

  // Delete group
  app.delete('/scim/v2/Groups/:id', { preHandler: [requireScimAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };

    try {
      await request.server.argus.orgs.delete(id);
      return reply.status(204).send();
    } catch {
      return reply.status(404).send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'Group not found',
        status: '404',
      });
    }
  });
}
