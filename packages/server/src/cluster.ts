// Increase UV_THREADPOOL_SIZE before anything
import { cpus } from 'node:os';
process.env.UV_THREADPOOL_SIZE = String(Math.max(16, cpus().length * 2));

import cluster from 'node:cluster';

const numWorkers = parseInt(process.env.CLUSTER_WORKERS || String(cpus().length), 10);

if (cluster.isPrimary) {
  console.log(`ArgusJS primary ${process.pid} starting ${numWorkers} workers`);

  for (let i = 0; i < numWorkers; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.warn(`Worker ${worker.process.pid} died (${signal || code}). Restarting...`);
    cluster.fork();
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log('Primary shutting down workers...');
    for (const id in cluster.workers) {
      cluster.workers[id]?.process.kill('SIGTERM');
    }
    setTimeout(() => process.exit(0), 10000); // force exit after 10s
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
} else {
  // Worker process — import and run the regular server
  import('./server.js');
}
