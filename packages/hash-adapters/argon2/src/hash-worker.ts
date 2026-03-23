import { parentPort } from 'node:worker_threads';
import argon2 from 'argon2';

parentPort!.on('message', async (msg: any) => {
  try {
    if (msg.op === 'hash') {
      const hash = await argon2.hash(msg.password, {
        type: argon2.argon2id,
        memoryCost: msg.memoryCost,
        timeCost: msg.timeCost,
        parallelism: msg.parallelism,
      });
      parentPort!.postMessage({ ok: true, result: hash });
    } else if (msg.op === 'verify') {
      const valid = await argon2.verify(msg.hash, msg.password);
      parentPort!.postMessage({ ok: true, result: valid });
    }
  } catch (err: any) {
    parentPort!.postMessage({ ok: false, error: err.message });
  }
});
