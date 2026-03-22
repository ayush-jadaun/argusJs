import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createTestArgus } from './helpers.js';
import { WebhookDispatcher } from '../webhook-dispatcher.js';
import { ArgusEventEmitter } from '../event-emitter.js';
import { MemoryDbAdapter } from '@argusjs/db-memory';
import { createHmac } from 'node:crypto';

describe('Argus.webhooks', () => {
  it('should create a webhook with a secret', async () => {
    const { argus } = createTestArgus();
    await argus.init();

    const webhook = await argus.webhooks.create({
      url: 'https://example.com/hook',
      events: ['user.registered'],
    });

    expect(webhook.url).toBe('https://example.com/hook');
    expect(webhook.events).toContain('user.registered');
    expect(webhook.secret).toBeDefined();
    expect(webhook.secret.length).toBeGreaterThan(0);
    expect(webhook.active).toBe(true);
  });

  it('should list webhooks', async () => {
    const { argus } = createTestArgus();
    await argus.init();

    await argus.webhooks.create({
      url: 'https://example.com/hook1',
      events: ['user.registered'],
    });

    await argus.webhooks.create({
      url: 'https://example.com/hook2',
      events: ['user.login'],
    });

    const list = await argus.webhooks.list();
    expect(list.length).toBe(2);
  });

  it('should update a webhook', async () => {
    const { argus } = createTestArgus();
    await argus.init();

    const webhook = await argus.webhooks.create({
      url: 'https://example.com/hook',
      events: ['user.registered'],
    });

    const updated = await argus.webhooks.update(webhook.id, { active: false });
    expect(updated.active).toBe(false);
  });

  it('should delete a webhook', async () => {
    const { argus } = createTestArgus();
    await argus.init();

    const webhook = await argus.webhooks.create({
      url: 'https://example.com/hook',
      events: ['user.registered'],
    });

    await argus.webhooks.delete(webhook.id);
    const list = await argus.webhooks.list();
    expect(list.length).toBe(0);
  });
});

describe('WebhookDispatcher', () => {
  let db: MemoryDbAdapter;
  let emitter: ArgusEventEmitter;
  let dispatcher: WebhookDispatcher;

  beforeEach(async () => {
    db = new MemoryDbAdapter();
    await db.init();
    emitter = new ArgusEventEmitter();
    dispatcher = new WebhookDispatcher(db, emitter);
    dispatcher.init();
  });

  it('should dispatch matching webhooks on event', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', mockFetch);

    await db.createWebhook({
      url: 'https://example.com/hook',
      events: ['user.registered'],
      secret: 'testsecret',
    });

    await emitter.emit('user.registered', {
      type: 'user.registered',
      userId: 'user-1',
      timestamp: new Date(),
    });

    // Wait for fire-and-forget
    await new Promise(r => setTimeout(r, 50));

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch.mock.calls[0][0]).toBe('https://example.com/hook');

    const callOpts = mockFetch.mock.calls[0][1];
    expect(callOpts.method).toBe('POST');
    expect(callOpts.headers['Content-Type']).toBe('application/json');
    expect(callOpts.headers['X-Argus-Signature']).toMatch(/^sha256=/);
    expect(callOpts.headers['X-Argus-Event']).toBe('user.registered');

    vi.unstubAllGlobals();
  });

  it('should not trigger webhook for non-matching events', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', mockFetch);

    await db.createWebhook({
      url: 'https://example.com/hook',
      events: ['user.login'],
      secret: 'testsecret',
    });

    await emitter.emit('user.registered', {
      type: 'user.registered',
      userId: 'user-1',
      timestamp: new Date(),
    });

    await new Promise(r => setTimeout(r, 50));

    expect(mockFetch).not.toHaveBeenCalled();

    vi.unstubAllGlobals();
  });

  it('should dispatch for wildcard event subscriptions', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', mockFetch);

    await db.createWebhook({
      url: 'https://example.com/hook',
      events: ['*'],
      secret: 'testsecret',
    });

    await emitter.emit('user.registered', {
      type: 'user.registered',
      userId: 'user-1',
      timestamp: new Date(),
    });

    await new Promise(r => setTimeout(r, 50));

    expect(mockFetch).toHaveBeenCalledTimes(1);

    vi.unstubAllGlobals();
  });

  it('should produce correct HMAC signature', () => {
    const body = JSON.stringify({ type: 'user.registered', userId: 'user-1' });
    const secret = 'mysecret';

    const expected = createHmac('sha256', secret).update(body).digest('hex');
    const actual = dispatcher.sign(body, secret);

    expect(actual).toBe(expected);
  });

  it('should increment failure count on failed response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 500 });
    vi.stubGlobal('fetch', mockFetch);

    const webhook = await db.createWebhook({
      url: 'https://example.com/hook',
      events: ['user.registered'],
      secret: 'testsecret',
    });

    await emitter.emit('user.registered', {
      type: 'user.registered',
      userId: 'user-1',
      timestamp: new Date(),
    });

    await new Promise(r => setTimeout(r, 50));

    const webhooks = await db.listWebhooks();
    const updated = webhooks.find(w => w.id === webhook.id);
    expect(updated!.failureCount).toBe(1);

    vi.unstubAllGlobals();
  });

  it('should increment failure count on network error', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
    vi.stubGlobal('fetch', mockFetch);

    const webhook = await db.createWebhook({
      url: 'https://example.com/hook',
      events: ['user.registered'],
      secret: 'testsecret',
    });

    await emitter.emit('user.registered', {
      type: 'user.registered',
      userId: 'user-1',
      timestamp: new Date(),
    });

    await new Promise(r => setTimeout(r, 50));

    const webhooks = await db.listWebhooks();
    const updated = webhooks.find(w => w.id === webhook.id);
    expect(updated!.failureCount).toBe(1);

    vi.unstubAllGlobals();
  });

  it('should reset failure count on success', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', mockFetch);

    const webhook = await db.createWebhook({
      url: 'https://example.com/hook',
      events: ['user.registered'],
      secret: 'testsecret',
    });

    // Manually increment to simulate prior failures
    await db.incrementWebhookFailure(webhook.id);
    await db.incrementWebhookFailure(webhook.id);

    await emitter.emit('user.registered', {
      type: 'user.registered',
      userId: 'user-1',
      timestamp: new Date(),
    });

    await new Promise(r => setTimeout(r, 50));

    const webhooks = await db.listWebhooks();
    const updated = webhooks.find(w => w.id === webhook.id);
    expect(updated!.failureCount).toBe(0);

    vi.unstubAllGlobals();
  });

  it('should skip inactive webhooks', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', mockFetch);

    const webhook = await db.createWebhook({
      url: 'https://example.com/hook',
      events: ['user.registered'],
      secret: 'testsecret',
    });

    await db.updateWebhook(webhook.id, { active: false });

    await emitter.emit('user.registered', {
      type: 'user.registered',
      userId: 'user-1',
      timestamp: new Date(),
    });

    await new Promise(r => setTimeout(r, 50));

    expect(mockFetch).not.toHaveBeenCalled();

    vi.unstubAllGlobals();
  });
});
