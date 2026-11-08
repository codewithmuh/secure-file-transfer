// The stack's ports on the container's own localhost, for `make web-e2e` on Docker Desktop (macOS), which has no host
// networking by default. Each port listens on 127.0.0.1 and ::1 inside the Playwright container and forwards to
// host.docker.internal, where Docker Desktop reaches the ports the stack publishes on the host's 127.0.0.1. The
// browser still sees http://localhost:3000, :8000, :8180, :8025 and :9090, exactly as a person does, so origins,
// cookies and the API's Origin check are what they are on a laptop. On Linux (CI) the container uses host networking
// instead and this isn't started (Makefile, web-e2e).
import net from 'node:net';

const target = process.env.E2E_FORWARD_HOST ?? 'host.docker.internal';
const ports = (process.env.E2E_FORWARD_PORTS ?? '3000,8000,8180,8025,9090').split(',').map(Number);

for (const port of ports) {
  for (const host of ['127.0.0.1', '::1']) {
    const server = net.createServer((client) => {
      const upstream = net.connect({ host: target, port });
      client.pipe(upstream).pipe(client);
      const close = () => {
        client.destroy();
        upstream.destroy();
      };
      client.on('error', close);
      upstream.on('error', close);
    });
    server.on('error', (error) => {
      // ::1 may not exist in the container; 127.0.0.1 is enough then.
      if (host === '::1') return;
      console.error(`forward ${host}:${port}: ${error.message}`);
      process.exit(1);
    });
    server.listen(port, host);
  }
}
console.log(`forwarding ${ports.join(', ')} on localhost to ${target}`);
