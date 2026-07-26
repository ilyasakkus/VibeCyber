import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const controlAddress =
  process.env.WEBCYBER_CONTROL_ADDR?.trim() || "127.0.0.1:7071";

function localAPIURL(address) {
  if (address.startsWith(":")) return `http://127.0.0.1${address}`;
  if (address.startsWith("0.0.0.0:")) {
    return `http://127.0.0.1:${address.slice("0.0.0.0:".length)}`;
  }
  if (address.startsWith("[::]:")) {
    return `http://[::1]:${address.slice("[::]:".length)}`;
  }
  return `http://${address}`;
}

const apiURL =
  process.env.WEBCYBER_API_URL?.trim() || localAPIURL(controlAddress);
const controlToken =
  process.env.WEBCYBER_CONTROL_TOKEN?.trim() ||
  randomBytes(32).toString("base64url");

const sharedEnvironment = {
  ...process.env,
  WEBCYBER_API_URL: apiURL,
  WEBCYBER_CONTROL_ADDR: controlAddress,
  WEBCYBER_CONTROL_TOKEN: controlToken,
  WEBCYBER_ALLOW_LOCAL: process.env.WEBCYBER_ALLOW_LOCAL?.trim() || "true",
};

const children = new Set();
let stopping = false;

function launch(command, args) {
  const child = spawn(command, args, {
    cwd: projectRoot,
    detached: process.platform !== "win32",
    env: sharedEnvironment,
    shell: false,
    stdio: "inherit",
  });
  children.add(child);
  child.once("close", () => children.delete(child));
  return child;
}

function signalChild(child, signal) {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) {
    return;
  }

  if (process.platform === "win32") {
    const args = ["/PID", String(child.pid), "/T"];
    if (signal === "SIGKILL") {
      args.push("/F");
    }
    const taskkill = spawn("taskkill.exe", args, {
      cwd: projectRoot,
      env: sharedEnvironment,
      shell: false,
      stdio: "ignore",
      windowsHide: true,
    });
    taskkill.once("error", (error) => {
      console.error(`Failed to stop child process tree: ${error.message}`);
    });
    return;
  }

  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") {
      console.error(`Failed to stop child process: ${error.message}`);
    }
  }
}

async function stop(exitCode = 0) {
  if (stopping) {
    return;
  }
  stopping = true;

  for (const child of children) {
    signalChild(child, "SIGTERM");
  }

  await new Promise((resolve) => {
    const timer = setTimeout(resolve, 3_000);
    timer.unref();
    if (children.size === 0) {
      clearTimeout(timer);
      resolve();
    }
    for (const child of children) {
      child.once("close", () => {
        if (children.size === 0) {
          clearTimeout(timer);
          resolve();
        }
      });
    }
  });

  for (const child of children) {
    signalChild(child, "SIGKILL");
  }
  process.exitCode = exitCode;
}

async function waitForControlPlane(child) {
  const deadline = Date.now() + 45_000;
  const healthURL = new URL("/api/v1/health", `${apiURL}/`);
  let lastError;

  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error("Go control plane exited before becoming ready.");
    }

    try {
      const response = await fetch(healthURL, {
        headers: { Authorization: `Bearer ${controlToken}` },
        signal: AbortSignal.timeout(1_500),
      });
      if (response.ok) {
        return;
      }
      lastError = new Error(`health response HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  throw new Error(
    `Go control plane did not become ready within 45 seconds${
      lastError ? `: ${lastError.message}` : "."
    }`,
  );
}

function npmInvocation() {
  const npmCLI = process.env.npm_execpath;
  if (npmCLI) {
    return { command: process.execPath, args: [npmCLI, "run", "dev"] };
  }
  return {
    command: process.platform === "win32" ? "npm.cmd" : "npm",
    args: ["run", "dev"],
  };
}

process.once("SIGINT", () => void stop(130));
process.once("SIGTERM", () => void stop(143));

const control = launch("go", ["run", "./cmd/webcyberd"]);
control.once("error", (error) => {
  console.error(`Failed to launch Go control plane: ${error.message}`);
  void stop(1);
});

try {
  await waitForControlPlane(control);
  console.log(`WebCyber control plane ready: ${apiURL}`);

  const npm = npmInvocation();
  const web = launch(npm.command, npm.args);
  web.once("error", (error) => {
    console.error(`Failed to launch web panel: ${error.message}`);
    void stop(1);
  });
  web.once("close", (code, signal) => {
    if (!stopping) {
      void stop(signal ? 1 : (code ?? 0));
    }
  });
  control.once("close", (code, signal) => {
    if (!stopping) {
      console.error("Go control plane exited unexpectedly.");
      void stop(signal ? 1 : (code ?? 1));
    }
  });
} catch (error) {
  console.error(error.message);
  await stop(1);
}
