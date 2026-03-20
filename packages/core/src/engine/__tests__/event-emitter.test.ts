import { describe, it, expect, vi } from 'vitest';
import { ArgusEventEmitter } from '../event-emitter.js';

describe('ArgusEventEmitter', () => {
  it('should register a listener and receive events', async () => {
    const emitter = new ArgusEventEmitter();
    const handler = vi.fn();
    emitter.on('user.login', handler);
    await emitter.emit('user.login', { userId: '123' });
    expect(handler).toHaveBeenCalledWith({ userId: '123' });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('should support wildcard listeners with *', async () => {
    const emitter = new ArgusEventEmitter();
    const handler = vi.fn();
    emitter.on('user.*', handler);
    await emitter.emit('user.login', { userId: '123' });
    await emitter.emit('user.registered', { userId: '456' });
    await emitter.emit('session.created', { sessionId: 'abc' });
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('should support global wildcard *', async () => {
    const emitter = new ArgusEventEmitter();
    const handler = vi.fn();
    emitter.on('*', handler);
    await emitter.emit('user.login', {});
    await emitter.emit('session.created', {});
    await emitter.emit('mfa.enabled', {});
    expect(handler).toHaveBeenCalledTimes(3);
  });

  it('should remove listeners with off()', async () => {
    const emitter = new ArgusEventEmitter();
    const handler = vi.fn();
    emitter.on('user.login', handler);
    emitter.off('user.login', handler);
    await emitter.emit('user.login', {});
    expect(handler).not.toHaveBeenCalled();
  });

  it('should support multiple listeners on same event', async () => {
    const emitter = new ArgusEventEmitter();
    const handler1 = vi.fn();
    const handler2 = vi.fn();
    emitter.on('user.login', handler1);
    emitter.on('user.login', handler2);
    await emitter.emit('user.login', {});
    expect(handler1).toHaveBeenCalledTimes(1);
    expect(handler2).toHaveBeenCalledTimes(1);
  });

  it('should support once() listener that fires once', async () => {
    const emitter = new ArgusEventEmitter();
    const handler = vi.fn();
    emitter.once('user.login', handler);
    await emitter.emit('user.login', { first: true });
    await emitter.emit('user.login', { second: true });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith({ first: true });
  });

  it('should await async listeners', async () => {
    const emitter = new ArgusEventEmitter();
    const order: number[] = [];
    emitter.on('user.login', async () => {
      await new Promise(resolve => setTimeout(resolve, 10));
      order.push(1);
    });
    emitter.on('user.login', async () => {
      order.push(2);
    });
    await emitter.emit('user.login', {});
    expect(order).toEqual([1, 2]);
  });

  it('should not throw when emitting with no listeners', async () => {
    const emitter = new ArgusEventEmitter();
    await expect(emitter.emit('user.login', {})).resolves.toBeUndefined();
  });

  it('should handle removing a listener that was never added', () => {
    const emitter = new ArgusEventEmitter();
    const handler = vi.fn();
    expect(() => emitter.off('user.login', handler)).not.toThrow();
  });

  it('should match nested wildcards correctly', async () => {
    const emitter = new ArgusEventEmitter();
    const handler = vi.fn();
    emitter.on('security.*', handler);
    await emitter.emit('security.suspicious_activity', {});
    await emitter.emit('security.brute_force_detected', {});
    await emitter.emit('user.login', {});
    expect(handler).toHaveBeenCalledTimes(2);
  });
});
