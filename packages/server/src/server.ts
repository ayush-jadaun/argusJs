import { createApp } from './app.js';
import { Argus } from '@argus/core';

// This file is the entrypoint when running @argus/server as a standalone microservice.
// In production, you'd construct the Argus instance with real adapters here.
// For now, it's a placeholder that will be filled in when adapters are configured.

async function main() {
  // Placeholder — real configuration would go here
  console.log('ArgusJS Server - configure with real adapters to start');
  console.log('See docs for configuration examples');
}

main().catch(console.error);
