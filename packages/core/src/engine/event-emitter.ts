type EventHandler = (data: unknown) => void | Promise<void>;

export class ArgusEventEmitter {
  private listeners: Map<string, Set<EventHandler>> = new Map();

  on(event: string, handler: EventHandler): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler);
  }

  once(event: string, handler: EventHandler): void {
    const wrapper: EventHandler = async (data) => {
      this.off(event, wrapper);
      await handler(data);
    };
    this.on(event, wrapper);
  }

  off(event: string, handler: EventHandler): void {
    const handlers = this.listeners.get(event);
    if (handlers) {
      handlers.delete(handler);
      if (handlers.size === 0) {
        this.listeners.delete(event);
      }
    }
  }

  async emit(event: string, data: unknown): Promise<void> {
    for (const [pattern, handlers] of this.listeners) {
      if (this.matches(pattern, event)) {
        for (const handler of handlers) {
          await handler(data);
        }
      }
    }
  }

  private matches(pattern: string, event: string): boolean {
    if (pattern === '*') return true;
    if (pattern === event) return true;
    if (pattern.endsWith('.*')) {
      const prefix = pattern.slice(0, -2);
      return event.startsWith(prefix + '.');
    }
    return false;
  }
}
