import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  accessSync,
  constants as fsConstants,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { app, BrowserWindow, dialog, ipcMain, Menu, session } from "electron";

const APP_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const RENDERER_FILE = path.join(APP_DIRECTORY, "renderer", "index.html");
const RENDERER_URL = pathToFileURL(RENDERER_FILE).href;
const SESSION_PARTITION = "webcyber-desktop";

const SCAN_TYPES = new Set(["source", "mobile", "desktop"]);
const SCAN_PROFILES = new Set(["observe", "safe"]);
const PATH_KINDS = new Set(["file", "directory"]);
const MAX_SELECTED_TARGETS = 32;
const MAX_URL_LENGTH = 2_048;
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const MAX_STDERR_BYTES = 1024 * 1024;
const MAX_ERROR_TEXT_BYTES = 64 * 1024;
const SCAN_TIMEOUT_MS = 15 * 60 * 1_000;
const GRACEFUL_KILL_MS = 2_000;

const CHANNELS = Object.freeze({
  pickTarget: "target:pick",
  startScan: "scan:start",
  cancelScan: "scan:cancel",
  scanFinished: "scan:finished",
});

const selectedTargets = new Map();
const activeJobs = new Map();
let mainWindow = null;
let targetDialogOpen = false;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertOnlyKeys(value, allowedKeys, label) {
  if (!isRecord(value)) {
    throw new TypeError(`${label} bir nesne olmalidir.`);
  }

  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      throw new TypeError(`${label} beklenmeyen bir alan iceriyor.`);
    }
  }
}

function assertTrustedSender(event) {
  const trustedContents = mainWindow?.webContents;
  if (
    !trustedContents ||
    trustedContents.isDestroyed() ||
    event.sender.id !== trustedContents.id ||
    event.senderFrame?.url !== RENDERER_URL
  ) {
    throw new Error("Guvenilmeyen IPC istegi reddedildi.");
  }
}

function parseScanType(value) {
  if (typeof value !== "string" || !SCAN_TYPES.has(value)) {
    throw new TypeError("Gecersiz tarama turu.");
  }
  return value;
}

function parseProfile(value) {
  if (typeof value !== "string" || !SCAN_PROFILES.has(value)) {
    throw new TypeError("Gecersiz tarama profili.");
  }
  return value;
}

function parsePathKind(value) {
  if (typeof value !== "string" || !PATH_KINDS.has(value)) {
    throw new TypeError("Gecersiz hedef secim turu.");
  }
  return value;
}

function validateUrlTarget(rawValue) {
  if (typeof rawValue !== "string") {
    throw new TypeError("URL metin olmalidir.");
  }

  const value = rawValue.trim();
  if (value.length === 0 || value.length > MAX_URL_LENGTH) {
    throw new TypeError("URL uzunlugu gecersiz.");
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("Gecerli bir URL girin.");
  }

  if (!new Set(["http:", "https:"]).has(parsed.protocol)) {
    throw new TypeError("Yalnizca HTTP ve HTTPS hedefleri desteklenir.");
  }
  if (!parsed.hostname || parsed.username || parsed.password) {
    throw new TypeError("Kimlik bilgisi icermeyen bir ana makine URL'si girin.");
  }

  parsed.hash = "";
  return parsed.href;
}

function isRunnableFile(candidate) {
  if (!path.isAbsolute(candidate)) {
    return false;
  }

  try {
    if (!statSync(candidate).isFile()) {
      return false;
    }
    accessSync(
      candidate,
      process.platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK,
    );
    return true;
  } catch {
    return false;
  }
}

function scannerBinaryName() {
  return process.platform === "win32" ? "webcyber.exe" : "webcyber";
}

function resolveScannerBinary() {
  const developmentOverride = process.env.WEB_CYBER_SCANNER_BIN?.trim();

  if (!app.isPackaged && developmentOverride) {
    if (!isRunnableFile(developmentOverride)) {
      throw new Error(
        "WEB_CYBER_SCANNER_BIN mutlak, mevcut ve calistirilabilir bir dosya olmalidir.",
      );
    }
    return realpathSync.native(developmentOverride);
  }

  const resourcesRoot = app.isPackaged
    ? process.resourcesPath
    : path.join(APP_DIRECTORY, "resources");
  const bundledBinary = path.join(resourcesRoot, "bin", scannerBinaryName());

  if (!isRunnableFile(bundledBinary)) {
    throw new Error(`WebCyber tarama motoru bulunamadi: ${bundledBinary}`);
  }
  return realpathSync.native(bundledBinary);
}

function restrictedEnvironment() {
  const result = Object.create(null);
  const allowedVariables = [
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "WINDIR",
  ];

  for (const name of allowedVariables) {
    const value = process.env[name];
    if (typeof value === "string" && value.length <= 4_096 && !value.includes("\0")) {
      result[name] = value;
    }
  }
  result.NO_COLOR = "1";
  return result;
}

function fileFiltersFor(scanType) {
  if (scanType === "mobile") {
    return [
      { name: "Mobil uygulamalar", extensions: ["apk", "aab", "ipa"] },
      { name: "Tum dosyalar", extensions: ["*"] },
    ];
  }
  if (scanType === "desktop") {
    return [
      {
        name: "Masaustu paketleri",
        extensions: ["exe", "msi", "dmg", "pkg", "deb", "rpm", "AppImage"],
      },
      { name: "Tum dosyalar", extensions: ["*"] },
    ];
  }
  return [{ name: "Tum dosyalar", extensions: ["*"] }];
}

function rememberSelectedTarget(ownerId, scanType, pathKind, selectedPath) {
  const resolvedPath = realpathSync.native(selectedPath);
  const stats = statSync(resolvedPath);
  const matchesKind = pathKind === "file" ? stats.isFile() : stats.isDirectory();
  if (!matchesKind) {
    throw new Error("Secilen hedef beklenen dosya turunde degil.");
  }

  while (selectedTargets.size >= MAX_SELECTED_TARGETS) {
    const oldestId = selectedTargets.keys().next().value;
    selectedTargets.delete(oldestId);
  }

  const id = randomUUID();
  selectedTargets.set(id, {
    ownerId,
    scanType,
    pathKind,
    path: resolvedPath,
  });

  return {
    id,
    label: path.basename(resolvedPath) || resolvedPath,
    displayPath: resolvedPath,
    pathKind,
  };
}

function resolveScanTarget(payload, ownerId, scanType) {
  assertOnlyKeys(payload, new Set(["kind", "id", "value"]), "Hedef");

  if (payload.kind === "url") {
    if (scanType !== "source" || "id" in payload) {
      throw new TypeError("URL hedefi kaynak taramasi olarak calistirilmalidir.");
    }
    return validateUrlTarget(payload.value);
  }

  if (payload.kind === "local") {
    if ("value" in payload || typeof payload.id !== "string" || payload.id.length > 64) {
      throw new TypeError("Gecersiz yerel hedef kimligi.");
    }

    const selected = selectedTargets.get(payload.id);
    if (
      !selected ||
      selected.ownerId !== ownerId ||
      selected.scanType !== scanType ||
      !path.isAbsolute(selected.path)
    ) {
      throw new Error("Yerel hedef bulunamadi; hedefi yeniden secin.");
    }

    const currentPath = realpathSync.native(selected.path);
    if (currentPath !== selected.path) {
      throw new Error("Yerel hedef secimden sonra degisti; yeniden secin.");
    }
    return currentPath;
  }

  throw new TypeError("Gecersiz hedef turu.");
}

function safeErrorMessage(error) {
  const message = error instanceof Error ? error.message : "Bilinmeyen tarama hatasi.";
  return message.slice(0, 2_000);
}

function limitedText(buffer) {
  const limited = buffer.subarray(0, MAX_ERROR_TEXT_BYTES).toString("utf8");
  return buffer.length > MAX_ERROR_TEXT_BYTES ? `${limited}\n… (devami kisaltildi)` : limited;
}

function hasExited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

function requestJobTermination(job, failure) {
  if (job.finalized || job.failure) {
    return;
  }

  job.failure = failure;
  if (!hasExited(job.child)) {
    job.child.kill("SIGTERM");
    job.killTimer = setTimeout(() => {
      if (!hasExited(job.child)) {
        job.child.kill("SIGKILL");
      }
    }, GRACEFUL_KILL_MS);
    job.killTimer.unref();
  }
}

function appendJobOutput(job, streamName, chunk) {
  if (job.finalized || job.failure) {
    return;
  }

  const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  job.outputBytes += data.length;
  if (streamName === "stderr") {
    job.stderrBytes += data.length;
  }

  if (job.outputBytes > MAX_OUTPUT_BYTES || job.stderrBytes > MAX_STDERR_BYTES) {
    requestJobTermination(job, {
      kind: "limit",
      message: "Tarama ciktisi guvenlik sinirini asti.",
    });
    return;
  }

  job[`${streamName}Chunks`].push(Buffer.from(data));
}

function finishJob(job, processResult = {}) {
  if (job.finalized) {
    return;
  }
  job.finalized = true;
  clearTimeout(job.timeout);
  clearTimeout(job.killTimer);
  activeJobs.delete(job.id);

  const stdout = Buffer.concat(job.stdoutChunks);
  const stderr = Buffer.concat(job.stderrChunks);
  let status = "success";
  let report = null;
  let errorMessage = null;

  if (job.failure) {
    status = job.failure.kind === "cancelled" ? "cancelled" : "error";
    errorMessage = job.failure.message;
  } else if (processResult.error) {
    status = "error";
    errorMessage = safeErrorMessage(processResult.error);
  } else if (processResult.code !== 0) {
    status = "error";
    errorMessage = `Tarama motoru ${String(processResult.code)} cikis koduyla sonlandi.`;
  } else {
    try {
      report = JSON.parse(stdout.toString("utf8"));
    } catch {
      status = "error";
      errorMessage = "Tarama motoru gecerli JSON uretmedi.";
    }
  }

  if (!job.sender.isDestroyed()) {
    job.sender.send(CHANNELS.scanFinished, {
      jobId: job.id,
      status,
      report,
      error: errorMessage,
      stderr: limitedText(stderr),
      exitCode: Number.isInteger(processResult.code) ? processResult.code : null,
      signal: typeof processResult.signal === "string" ? processResult.signal : null,
      durationMs: Date.now() - job.startedAt,
    });
  }
}

function cancelJobsOwnedBy(ownerId, message = "Tarayici penceresi kapatildi.") {
  for (const job of activeJobs.values()) {
    if (job.ownerId === ownerId) {
      requestJobTermination(job, { kind: "cancelled", message });
    }
  }
  for (const [targetId, target] of selectedTargets) {
    if (target.ownerId === ownerId) {
      selectedTargets.delete(targetId);
    }
  }
}

function registerIpcHandlers() {
  ipcMain.handle(CHANNELS.pickTarget, async (event, payload) => {
    assertTrustedSender(event);
    assertOnlyKeys(payload, new Set(["scanType", "pathKind"]), "Secim istegi");
    const scanType = parseScanType(payload.scanType);
    const pathKind = parsePathKind(payload.pathKind);
    if (targetDialogOpen) {
      throw new Error("Hedef secim penceresi zaten acik.");
    }

    let result;
    targetDialogOpen = true;
    try {
      result = await dialog.showOpenDialog(mainWindow, {
        title:
          pathKind === "file" ? "Taranacak dosyayi secin" : "Taranacak klasoru secin",
        buttonLabel: "Hedefi sec",
        properties:
          pathKind === "file"
            ? ["openFile", "dontAddToRecent"]
            : ["openDirectory", "dontAddToRecent"],
        filters: pathKind === "file" ? fileFiltersFor(scanType) : undefined,
      });
    } finally {
      targetDialogOpen = false;
    }

    if (result.canceled || result.filePaths.length !== 1) {
      return { canceled: true };
    }

    return {
      canceled: false,
      target: rememberSelectedTarget(
        event.sender.id,
        scanType,
        pathKind,
        result.filePaths[0],
      ),
    };
  });

  ipcMain.handle(CHANNELS.startScan, (event, payload) => {
    assertTrustedSender(event);
    assertOnlyKeys(
      payload,
      new Set(["scanType", "profile", "target"]),
      "Tarama istegi",
    );

    const scanType = parseScanType(payload.scanType);
    const profile = parseProfile(payload.profile);
    const target = resolveScanTarget(payload.target, event.sender.id, scanType);

    if ([...activeJobs.values()].some((job) => job.ownerId === event.sender.id)) {
      throw new Error("Ayni anda yalnizca bir tarama calistirilabilir.");
    }

    const binary = resolveScannerBinary();
    const args = [
      "scan",
      "--type",
      scanType,
      "--target",
      target,
      "--profile",
      profile,
      "--format",
      "json",
    ];
    const child = spawn(binary, args, {
      cwd: app.getPath("temp"),
      env: restrictedEnvironment(),
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    const job = {
      id: randomUUID(),
      ownerId: event.sender.id,
      sender: event.sender,
      child,
      startedAt: Date.now(),
      finalized: false,
      failure: null,
      stdoutChunks: [],
      stderrChunks: [],
      outputBytes: 0,
      stderrBytes: 0,
      timeout: null,
      killTimer: null,
    };
    activeJobs.set(job.id, job);

    child.stdout.on("data", (chunk) => appendJobOutput(job, "stdout", chunk));
    child.stderr.on("data", (chunk) => appendJobOutput(job, "stderr", chunk));
    child.once("error", (error) => finishJob(job, { error }));
    child.once("close", (code, signal) => finishJob(job, { code, signal }));

    job.timeout = setTimeout(() => {
      requestJobTermination(job, {
        kind: "timeout",
        message: "Tarama 15 dakikalik sure sinirini asti.",
      });
    }, SCAN_TIMEOUT_MS);
    job.timeout.unref();

    return {
      jobId: job.id,
      startedAt: job.startedAt,
      timeoutMs: SCAN_TIMEOUT_MS,
    };
  });

  ipcMain.handle(CHANNELS.cancelScan, (event, jobId) => {
    assertTrustedSender(event);
    if (typeof jobId !== "string" || jobId.length > 64) {
      throw new TypeError("Gecersiz tarama kimligi.");
    }

    const job = activeJobs.get(jobId);
    if (!job || job.ownerId !== event.sender.id) {
      return { cancelRequested: false };
    }

    requestJobTermination(job, {
      kind: "cancelled",
      message: "Tarama kullanici tarafindan iptal edildi.",
    });
    return { cancelRequested: true };
  });
}

function hardenSession() {
  const desktopSession = session.fromPartition(SESSION_PARTITION);
  desktopSession.setPermissionCheckHandler(() => false);
  desktopSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });
  desktopSession.on("will-download", (event) => {
    event.preventDefault();
  });
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1_280,
    height: 820,
    minWidth: 960,
    minHeight: 680,
    show: false,
    backgroundColor: "#07110f",
    title: "WebCyber",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(APP_DIRECTORY, "preload.mjs"),
      partition: SESSION_PARTITION,
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      devTools: !app.isPackaged,
      navigateOnDragDrop: false,
      safeDialogs: true,
      spellcheck: false,
      webviewTag: false,
    },
  });

  const ownerId = mainWindow.webContents.id;
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  mainWindow.webContents.on("will-navigate", (event) => {
    event.preventDefault();
  });
  mainWindow.webContents.on("will-attach-webview", (event) => {
    event.preventDefault();
  });
  mainWindow.webContents.on("render-process-gone", () => {
    cancelJobsOwnedBy(ownerId, "Renderer islemi sonlandi.");
  });
  mainWindow.once("ready-to-show", () => mainWindow?.show());
  mainWindow.once("closed", () => {
    cancelJobsOwnedBy(ownerId);
    mainWindow = null;
  });

  void mainWindow.loadFile(RENDERER_FILE);
}

app.on("web-contents-created", (_event, contents) => {
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
  contents.on("will-attach-webview", (event) => event.preventDefault());
});

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  hardenSession();
  registerIpcHandlers();
  createMainWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on("before-quit", () => {
  for (const job of activeJobs.values()) {
    requestJobTermination(job, {
      kind: "cancelled",
      message: "Uygulama kapatiliyor.",
    });
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
