const modes = Object.freeze({
  web: { scanType: "source", label: "Web" },
  source: { scanType: "source", label: "Kaynak kod" },
  mobile: { scanType: "mobile", label: "Mobil" },
  desktop: { scanType: "desktop", label: "Masaustu" },
});

const state = {
  mode: "web",
  selectedTarget: null,
  currentJobId: null,
  pendingResult: null,
  busy: false,
};

const elements = {
  tabs: [...document.querySelectorAll("[data-mode]")],
  form: document.querySelector("#scan-form"),
  webPanel: document.querySelector("#web-target-panel"),
  localPanel: document.querySelector("#local-target-panel"),
  urlInput: document.querySelector("#url-input"),
  urlError: document.querySelector("#url-error"),
  pickerError: document.querySelector("#picker-error"),
  pickFile: document.querySelector("#pick-file"),
  pickDirectory: document.querySelector("#pick-directory"),
  selectedTarget: document.querySelector("#selected-target"),
  selectedLabel: document.querySelector("#selected-label"),
  selectedPath: document.querySelector("#selected-path"),
  clearTarget: document.querySelector("#clear-target"),
  authorization: document.querySelector("#authorization"),
  startButton: document.querySelector("#start-scan"),
  scanStatus: document.querySelector("#scan-status"),
  statusSpinner: document.querySelector("#status-spinner"),
  statusTitle: document.querySelector("#status-title"),
  statusMessage: document.querySelector("#status-message"),
  cancelButton: document.querySelector("#cancel-scan"),
  resultPanel: document.querySelector("#result-panel"),
  resultTitle: document.querySelector("#result-title"),
  resultMeta: document.querySelector("#result-meta"),
  resultOutput: document.querySelector("#result-output"),
};

function validateUrl(rawValue, showError = false) {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    if (showError) elements.urlError.textContent = "Bir hedef URL girin.";
    return null;
  }

  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    const validProtocol = parsed.protocol === "http:" || parsed.protocol === "https:";
    if (!validProtocol || !parsed.hostname || parsed.username || parsed.password) {
      throw new Error("invalid URL");
    }
    parsed.hash = "";
    elements.urlError.textContent = "";
    return parsed.href;
  } catch {
    if (showError) {
      elements.urlError.textContent =
        "Kimlik bilgisi icermeyen gecerli bir HTTP veya HTTPS adresi girin.";
    }
    return null;
  }
}

function canStart() {
  const hasTarget =
    state.mode === "web"
      ? Boolean(validateUrl(elements.urlInput.value))
      : Boolean(state.selectedTarget);
  return hasTarget && elements.authorization.checked && !state.busy;
}

function updateStartState() {
  elements.startButton.disabled = !canStart();
}

function clearSelectedTarget() {
  state.selectedTarget = null;
  elements.selectedTarget.hidden = true;
  elements.selectedLabel.textContent = "";
  elements.selectedPath.textContent = "";
  elements.pickerError.textContent = "";
  updateStartState();
}

function setMode(mode) {
  if (!(mode in modes) || state.busy) return;
  state.mode = mode;
  clearSelectedTarget();

  for (const tab of elements.tabs) {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  }
  elements.webPanel.hidden = mode !== "web";
  elements.localPanel.hidden = mode === "web";
  elements.resultPanel.hidden = true;
  updateStartState();
}

function setBusy(busy) {
  state.busy = busy;
  for (const tab of elements.tabs) tab.disabled = busy;
  elements.pickFile.disabled = busy;
  elements.pickDirectory.disabled = busy;
  elements.urlInput.disabled = busy;
  elements.authorization.disabled = busy;
  for (const radio of elements.form.elements.profile) radio.disabled = busy;
  elements.scanStatus.hidden = !busy;
  elements.cancelButton.disabled = !busy;
  updateStartState();
}

function showStatus(title, message, spinning = true) {
  elements.scanStatus.hidden = false;
  elements.statusTitle.textContent = title;
  elements.statusMessage.textContent = message;
  elements.statusSpinner.hidden = !spinning;
}

function formatDuration(durationMs) {
  if (!Number.isFinite(durationMs)) return "";
  const seconds = Math.max(0, Math.round(durationMs / 1_000));
  return seconds < 60 ? `${seconds} sn` : `${Math.floor(seconds / 60)} dk ${seconds % 60} sn`;
}

function showResult(result) {
  elements.resultPanel.hidden = false;
  elements.resultPanel.classList.toggle("is-error", result.status !== "success");
  elements.resultTitle.textContent =
    result.status === "success"
      ? "Tarama raporu"
      : result.status === "cancelled"
        ? "Tarama iptal edildi"
        : "Tarama tamamlanamadi";
  elements.resultMeta.textContent = formatDuration(result.durationMs);

  if (result.status === "success") {
    elements.resultOutput.textContent = JSON.stringify(result.report, null, 2);
  } else {
    const details = [result.error, result.stderr].filter(Boolean).join("\n\n");
    elements.resultOutput.textContent = details || "Ayrintili hata bilgisi bulunmuyor.";
  }
  elements.resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function finishRendererJob(result) {
  state.currentJobId = null;
  state.pendingResult = null;
  setBusy(false);
  elements.scanStatus.hidden = true;
  showResult(result);
}

async function pickTarget(pathKind) {
  elements.pickerError.textContent = "";
  try {
    const response = await window.webcyber.pickLocalTarget({
      scanType: modes[state.mode].scanType,
      pathKind,
    });
    if (response.canceled) return;

    state.selectedTarget = response.target;
    elements.selectedLabel.textContent = response.target.label;
    elements.selectedPath.textContent = response.target.displayPath;
    elements.selectedTarget.hidden = false;
    updateStartState();
  } catch (error) {
    elements.pickerError.textContent =
      error instanceof Error ? error.message : "Hedef secilemedi.";
  }
}

async function startScan() {
  if (!canStart()) return;

  const normalizedUrl =
    state.mode === "web" ? validateUrl(elements.urlInput.value, true) : null;
  if (state.mode === "web" && !normalizedUrl) {
    updateStartState();
    return;
  }

  const profile = new FormData(elements.form).get("profile");
  const target =
    state.mode === "web"
      ? { kind: "url", value: normalizedUrl }
      : { kind: "local", id: state.selectedTarget.id };

  elements.resultPanel.hidden = true;
  state.pendingResult = null;
  setBusy(true);
  showStatus("Tarama baslatiliyor", `${modes[state.mode].label} hedefi hazirlaniyor…`);

  try {
    const response = await window.webcyber.startScan({
      scanType: modes[state.mode].scanType,
      profile,
      target,
    });
    state.currentJobId = response.jobId;
    if (state.pendingResult?.jobId === response.jobId) {
      finishRendererJob(state.pendingResult);
    } else {
      showStatus("Tarama calisiyor", "Katmanlar kontrollu bicimde analiz ediliyor…");
    }
  } catch (error) {
    state.currentJobId = null;
    state.pendingResult = null;
    setBusy(false);
    elements.scanStatus.hidden = true;
    showResult({
      status: "error",
      error: error instanceof Error ? error.message : "Tarama baslatilamadi.",
      stderr: "",
      durationMs: 0,
    });
  }
}

elements.tabs.forEach((tab) => {
  tab.addEventListener("click", () => setMode(tab.dataset.mode));
});
elements.urlInput.addEventListener("input", () => {
  elements.urlError.textContent = "";
  updateStartState();
});
elements.urlInput.addEventListener("blur", () => {
  if (elements.urlInput.value.trim()) validateUrl(elements.urlInput.value, true);
});
elements.authorization.addEventListener("change", updateStartState);
elements.pickFile.addEventListener("click", () => void pickTarget("file"));
elements.pickDirectory.addEventListener("click", () => void pickTarget("directory"));
elements.clearTarget.addEventListener("click", clearSelectedTarget);
elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  void startScan();
});
elements.cancelButton.addEventListener("click", async () => {
  if (!state.currentJobId) return;
  elements.cancelButton.disabled = true;
  showStatus("Tarama durduruluyor", "Tarama motorunun guvenli bicimde kapanmasi bekleniyor…");
  try {
    await window.webcyber.cancelScan(state.currentJobId);
  } catch (error) {
    showStatus(
      "Iptal istegi gonderilemedi",
      error instanceof Error ? error.message : "Bilinmeyen hata",
      false,
    );
    elements.cancelButton.disabled = false;
  }
});

window.webcyber.onScanFinished((result) => {
  if (state.busy && !state.currentJobId) {
    state.pendingResult = result;
    return;
  }
  if (state.currentJobId && result.jobId !== state.currentJobId) return;
  finishRendererJob(result);
});

updateStartState();
