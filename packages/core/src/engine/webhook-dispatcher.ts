import { createHmac, randomUUID } from 'node:crypto';
import type { DbAdapter } from '../interfaces/db-adapter.js';
import type { Webhook } from '../types/entities.js';
import type { ArgusEventEmitter } from './event-emitter.js';

export interface ArgusEvent {
  type: string;
  [key: string]: unknown;
}

export class WebhookDispatcher {
  constructor(private db: DbAdapter, private emitter: ArgusEventEmitter) {}

  init(): void {
    // Listen to ALL events on the emitter
    this.emitter.on('*', (data) => {
      const event = data as ArgusEvent;
      this.dispatch(event);
    });
  }

  private async dispatch(event: ArgusEvent): Promise<void> {
    const webhooks = await this.db.listWebhooks();
    for (const webhook of webhooks) {
      if (!webhook.active) continue;
      if (!webhook.events.includes(event.type) && !webhook.events.includes('*')) continue;
      this.send(webhook, event); // fire and forget
    }
  }

  private async send(webhook: Webhook, event: ArgusEvent): Promise<void> {
    const body = JSON.stringify(event);
    const signature = this.sign(body, webhook.secret);
    try {
      const res = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Argus-Signature': `sha256=${signature}`,
          'X-Argus-Event': event.type,
          'X-Argus-Delivery': randomUUID(),
        },
        body,
        signal: AbortSignal.timeout(10000),
      });
      if (res.ok) {
        await this.db.resetWebhookFailure(webhook.id);
      } else {
        await this.db.incrementWebhookFailure(webhook.id);
      }
    } catch {
      await this.db.incrementWebhookFailure(webhook.id);
    }
  }

  sign(body: string, secret: string): string {
    return createHmac('sha256', secret).update(body).digest('hex');
  }
}
