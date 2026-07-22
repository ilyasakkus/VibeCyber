import { contextBridge, ipcRenderer } from "electron";

const CHANNELS = Object.freeze({
  pickTarget: "target:pick",
  releaseTarget: "target:release",
  startScan: "scan:start",
  cancelScan: "scan:cancel",
  scanFinished: "scan:finished",
});

const SCAN_TYPES = new Set(["web", "source", "mobile", "desktop"]);
const LOCAL_SCAN_TYPES = new Set(["source", "mobile", "desktop"]);
const PROFILES = new Set(["observe", "safe"]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validatedPickRequest(request) {
  if (
    !isRecord(request) ||
    !LOCAL_SCAN_TYPES.has(request.scanType) ||
    !new Set(["file", "directory"]).has(request.pathKind)
  ) {
    throw new TypeError("Gecersiz yerel hedef secim istegi.");
  }
  return { scanType: request.scanType, pathKind: request.pathKind };
}

function validatedTargetId(targetId) {
  if (typeof targetId !== "string" || targetId.length === 0 || targetId.length > 64) {
    throw new TypeError("Gecersiz yerel hedef kimligi.");
  }
  return targetId;
}

function validatedScanRequest(request) {
  if (
    !isRecord(request) ||
    !SCAN_TYPES.has(request.scanType) ||
    !PROFILES.has(request.profile) ||
    !isRecord(request.target)
  ) {
    throw new TypeError("Gecersiz tarama istegi.");
  }

  if (
    request.target.kind === "url" &&
    request.scanType === "web" &&
    typeof request.target.value === "string" &&
    request.target.value.length <= 2_048
  ) {
    return {
      scanType: request.scanType,
      profile: request.profile,
      target: { kind: "url", value: request.target.value },
    };
  }
  if (request.target.kind === "local" && request.scanType !== "web") {
    return {
      scanType: request.scanType,
      profile: request.profile,
      target: { kind: "local", id: validatedTargetId(request.target.id) },
    };
  }
  throw new TypeError("Tarama hedefi ve turu uyusmuyor.");
}

const api = Object.freeze({
  pickLocalTarget(request) {
    return ipcRenderer.invoke(CHANNELS.pickTarget, validatedPickRequest(request));
  },

  releaseLocalTarget(targetId) {
    return ipcRenderer.invoke(CHANNELS.releaseTarget, validatedTargetId(targetId));
  },

  startScan(request) {
    return ipcRenderer.invoke(CHANNELS.startScan, validatedScanRequest(request));
  },

  cancelScan(jobId) {
    return ipcRenderer.invoke(CHANNELS.cancelScan, validatedTargetId(jobId));
  },

  onScanFinished(callback) {
    if (typeof callback !== "function") {
      throw new TypeError("Tarama dinleyicisi bir fonksiyon olmalidir.");
    }

    const listener = (_event, result) => callback(result);
    ipcRenderer.on(CHANNELS.scanFinished, listener);
    return () => ipcRenderer.removeListener(CHANNELS.scanFinished, listener);
  },
});

contextBridge.exposeInMainWorld("webcyber", api);
