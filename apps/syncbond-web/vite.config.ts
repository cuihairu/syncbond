import { defineConfig } from "vite";
import type { ProxyOptions } from "vite";

// This one file runs in Node (the dev server), not the browser.
declare const process: { env: Record<string, string | undefined> };

// The relay address is the demo's one deployment knob: point
// SYNCBOND_RELAY_URL at wherever `syncbond-server` listens (default: the
// quick-start's local relay). The page itself only ever talks to this dev
// server, same-origin, so the browser never trips the relay's absence of
// CORS headers and the WS `Authorization` header — which a browser
// `WebSocket` cannot set — is injected here from the invite link's
// `cap` query parameter. The capability still never rides the URL that
// reaches the relay: the proxy strips the query before forwarding.
const relayTarget = process.env.SYNCBOND_RELAY_URL ?? "http://127.0.0.1:8080";

function relayApiProxy(): ProxyOptions {
  return {
    target: relayTarget,
    changeOrigin: false,
    rewrite: (path) => path.replace(/^\/relay\/api/, ""),
  };
}

function relayWsProxy(): ProxyOptions {
  return {
    target: relayTarget,
    ws: true,
    changeOrigin: false,
    rewrite: (path) => path.replace(/^\/relay\/ws/, ""),
    configure: (proxy) => {
      proxy.on("proxyReqWs", (proxyReq, req) => {
        const url = new URL(req.url ?? "/", "http://proxy.local");
        const capability = url.searchParams.get("cap");
        if (capability) {
          proxyReq.setHeader("authorization", `Bearer ${capability}`);
          proxyReq.url = url.pathname;
        }
      });
    },
  };
}

export default defineConfig({
  server: {
    proxy: {
      "/relay/api": relayApiProxy(),
      "/relay/ws": relayWsProxy(),
    },
  },
});
