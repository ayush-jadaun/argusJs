import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

interface Task {
  resolve: (v: any) => void;
  reject: (e: Error) => void;
  msg: any;
}

export class HashWorkerPool {
  private workers: Worker[] = [];
  private free: Worker[] = [];
  private queue: Task[] = [];

  constructor(private size: number) {}

  init(): void {
    const workerPath = join(dirname(fileURLToPath(import.meta.url)), 'hash-worker.js');
    for (let i = 0; i < this.size; i++) {
      const w = new Worker(workerPath);
      this.workers.push(w);
      this.free.push(w);
    }
  }

  exec(msg: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const task: Task = { resolve, reject, msg };
      const w = this.free.pop();
      if (w) this.run(w, task);
      else this.queue.push(task);
    });
  }

  private run(w: Worker, task: Task) {
    const onMsg = (res: any) => {
      w.removeListener('message', onMsg);
      w.removeListener('error', onErr);
      if (res.ok) task.resolve(res.result);
      else task.reject(new Error(res.error));
      const next = this.queue.shift();
      if (next) this.run(w, next);
      else this.free.push(w);
    };
    const onErr = (err: Error) => {
      w.removeListener('message', onMsg);
      w.removeListener('error', onErr);
      task.reject(err);
      // Replace dead worker
      const idx = this.workers.indexOf(w);
      const workerPath = join(dirname(fileURLToPath(import.meta.url)), 'hash-worker.js');
      const nw = new Worker(workerPath);
      this.workers[idx] = nw;
      const next = this.queue.shift();
      if (next) this.run(nw, next);
      else this.free.push(nw);
    };
    w.on('message', onMsg);
    w.on('error', onErr);
    w.postMessage(task.msg);
  }

  async shutdown(): Promise<void> {
    await Promise.all(this.workers.map(w => w.terminate()));
    this.workers = [];
    this.free = [];
    this.queue = [];
  }
}
