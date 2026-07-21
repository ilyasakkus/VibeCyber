import { contextBridge, ipcRenderer } from "electron";

const CHANNELS = Object.freeze({
  pickTarget: "target:pick",
  startScan: "scan:start",
  cancelScan: "scan:cancel",
  scanFinished: "scan:finished",
});

const api = Object.freeze({
  pickLocalTarget(request) {
    return ipcRenderer.invoke(CHANNELS.pickTarget, request);
  },

  startScan(request) {
    return ipcRenderer.invoke(CHANNELS.startScan, request);
  },

  cancelScan(jobId) {
    return ipcRenderer.invoke(CHANNELS.cancelScan, jobId);
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
