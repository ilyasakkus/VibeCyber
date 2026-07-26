import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const token = randomBytes(32).toString("base64url");
const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "webcyber-smoke-"));
let control;
let capturedLogs = "";
let controlSpawnError;

function reserveLocalPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => {
        if (error) reject(error);
        else resolve(port);
      });
    });
  });
}

function appendLog(chunk) {
  capturedLogs += chunk.toString();
  if (capturedLogs.length > 16_384) {
    capturedLogs = capturedLogs.slice(-16_384);
  }
}

function signalControl(signal) {
  if (!control?.pid || control.exitCode !== null || control.signalCode !== null) {
    return;
  }
  try {
    if (process.platform === "win32") {
      control.kill(signal);
    } else {
      process.kill(-control.pid, signal);
    }
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

async function stopControl() {
  if (!control || control.exitCode !== null || control.signalCode !== null) return;
  signalControl("SIGTERM");
  await Promise.race([
    new Promise((resolve) => control.once("close", resolve)),
    new Promise((resolve) => setTimeout(resolve, 3_000)),
  ]);
  signalControl("SIGKILL");
}

async function request(baseURL, pathname, init = {}) {
  return fetch(new URL(pathname, baseURL), {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...init.headers,
    },
    signal: AbortSignal.timeout(5_000),
  });
}

async function waitForHealth(baseURL) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    if (controlSpawnError) {
      throw new Error(`Kontrol hizmeti başlatılamadı: ${controlSpawnError.message}`);
    }
    if (control.exitCode !== null || control.signalCode !== null) {
      throw new Error(`Kontrol hizmeti erken kapandı.\n${capturedLogs}`);
    }
    try {
      const response = await request(baseURL, "/api/v1/health");
      if (response.ok) return response.json();
    } catch {
      // `go run` ilk çalıştırmada derleme yapabilir; süre dolana kadar bekle.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Kontrol hizmeti hazır olmadı.\n${capturedLogs}`);
}

async function waitForTerminalJob(baseURL, id) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const response = await request(baseURL, `/api/v1/scans/${encodeURIComponent(id)}`);
    assert.equal(response.status, 200);
    const job = await response.json();
    if (["completed", "partial", "failed", "cancelled"].includes(job.status)) {
      return job;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Tarama zaman sınırı içinde terminal duruma geçmedi.");
}

try {
  const port = await reserveLocalPort();
  assert.ok(port > 0);
  const baseURL = `http://127.0.0.1:${port}`;
  await writeFile(
    path.join(fixtureRoot, "package.json"),
    '{"name":"webcyber-smoke-fixture","version":"1.0.0"}\n',
    { mode: 0o600 },
  );

  control = spawn("go", ["run", "./cmd/webcyberd"], {
    cwd: projectRoot,
    detached: process.platform !== "win32",
    env: {
      ...process.env,
      WEBCYBER_ALLOW_LOCAL: "true",
      WEBCYBER_CONTROL_ADDR: `127.0.0.1:${port}`,
      WEBCYBER_CONTROL_TOKEN: token,
      WEBCYBER_MAX_CONCURRENCY: "1",
      WEBCYBER_MAX_JOBS: "4",
      WEBCYBER_MAX_RETAINED: "4",
    },
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  control.once("error", (error) => {
    controlSpawnError = error;
    appendLog(error.message);
  });
  control.stdout.on("data", appendLog);
  control.stderr.on("data", appendLog);

  const health = await waitForHealth(baseURL);
  assert.equal(health.status, "ok");
  assert.equal(health.capabilities.localPaths, true);
  assert.equal(health.capabilities.maxConcurrency, 1);

  const unauthorized = await fetch(new URL("/api/v1/health", baseURL), {
    signal: AbortSignal.timeout(5_000),
  });
  assert.equal(unauthorized.status, 401);

  const createdResponse = await request(baseURL, "/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({
      type: "source",
      target: fixtureRoot,
      profile: "observe",
      authorized: true,
    }),
  });
  assert.equal(createdResponse.status, 202);
  const created = await createdResponse.json();
  assert.match(created.id, /^[A-Za-z0-9][A-Za-z0-9._-]+$/);

  const eventsResponse = await request(
    baseURL,
    `/api/v1/scans/${encodeURIComponent(created.id)}/events`,
    { headers: { accept: "text/event-stream" } },
  );
  assert.equal(eventsResponse.status, 200);
  assert.match(eventsResponse.headers.get("content-type") ?? "", /^text\/event-stream\b/);
  const eventStream = await eventsResponse.text();
  assert.match(eventStream, /event: (queued|running|completed|partial|failed)/);

  const terminal = await waitForTerminalJob(baseURL, created.id);
  assert.ok(["completed", "partial"].includes(terminal.status), terminal.error);
  assert.equal(terminal.report?.schema_version, "1.0");
  assert.equal(terminal.report?.scan?.type, "source");

  const listResponse = await request(baseURL, "/api/v1/scans");
  assert.equal(listResponse.status, 200);
  const list = await listResponse.json();
  assert.ok(list.scans.some((job) => job.id === created.id));

  const cancelAll = await request(baseURL, "/api/v1/scans", {
    method: "DELETE",
  });
  assert.equal(cancelAll.status, 200);
  console.log("WebCyber control API smoke testi geçti.");
} finally {
  await stopControl();
  await rm(fixtureRoot, { recursive: true, force: true });
}
