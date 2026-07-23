import { Buffer } from "node:buffer";
import path from "node:path";

export const DESKTOP_SCAN_TIMEOUT_MS = 135_000;

const SCAN_STATUSES = new Set(["completed", "partial", "failed"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const MODULE_STATUSES = new Set(["complete", "partial", "skipped", "error"]);
const SUMMARY_KEYS = ["total", "critical", "high", "medium", "low", "info"];
const MAX_REPORT_DEPTH = 64;
const MAX_REPORT_NODES = 100_000;
const MAX_REPORT_STRING_BYTES = 1024 * 1024;
const MAX_REPORT_MODULES = 1_000;
const MAX_REPORT_FINDINGS = 2_000;
const MAX_REPORT_LIST_ITEMS = 10_000;
const MAX_TIMESTAMP_DRIFT_MS = 5_000;
const RFC3339_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const FINGERPRINT_PATTERN = /^sha256:[a-f0-9]{64}$/;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertNonEmptyString(value, label, maxBytes = MAX_REPORT_STRING_BYTES) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    Buffer.byteLength(value, "utf8") > maxBytes
  ) {
    throw new TypeError(`${label} gecersiz bir metin iceriyor.`);
  }
}

function assertOptionalString(value, label, maxBytes = MAX_REPORT_STRING_BYTES) {
  if (value === undefined) return;
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new TypeError(`${label} gecersiz bir metin iceriyor.`);
  }
}

function assertStringArray(value, label, maxItems = MAX_REPORT_LIST_ITEMS) {
  if (value === undefined) return;
  if (!Array.isArray(value) || value.length > maxItems) {
    throw new TypeError(`${label} gecersiz bir liste iceriyor.`);
  }
  for (const item of value) {
    if (typeof item !== "string") {
      throw new TypeError(`${label} yalnizca metin degerleri icermelidir.`);
    }
  }
}

function parseTimestamp(value, label) {
  if (typeof value !== "string" || !RFC3339_PATTERN.test(value)) {
    throw new TypeError(`${label} RFC3339 biciminde olmalidir.`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new TypeError(`${label} gecerli bir tarih olmalidir.`);
  }
  return milliseconds;
}

function redactedWebTarget(rawTarget) {
  let parsed;
  try {
    parsed = new URL(rawTarget);
  } catch {
    throw new TypeError("Beklenen web hedefi gecerli bir URL degil.");
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password
  ) {
    throw new TypeError("Beklenen web hedefi guvenli URL semantigiyle uyusmuyor.");
  }
  parsed.username = "";
  parsed.password = "";
  parsed.search = "";
  parsed.hash = "";
  return parsed.href;
}

function assertRedactedWebUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${label} gecerli bir URL degil.`);
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    Buffer.byteLength(value, "utf8") > 2_048
  ) {
    throw new TypeError(`${label} redakte edilmis web URL semantigiyle uyusmuyor.`);
  }
}

function validateReportTarget(reportTarget, expectedScanType, expectedTarget) {
  assertNonEmptyString(reportTarget, "Tarama hedefi", 4_096);
  assertNonEmptyString(expectedTarget, "Beklenen tarama hedefi", 4_096);

  if (expectedScanType === "web") {
    assertRedactedWebUrl(reportTarget, "Tarama raporundaki hedef");
    if (reportTarget !== redactedWebTarget(expectedTarget)) {
      throw new TypeError("Tarama raporundaki web hedefi istenen hedefle uyusmuyor.");
    }
    return;
  }

  if (!path.isAbsolute(expectedTarget) || reportTarget !== expectedTarget) {
    throw new TypeError("Tarama raporundaki yerel hedef istenen hedefle uyusmuyor.");
  }
}

function validateModuleResult(moduleResult) {
  if (!isRecord(moduleResult)) {
    throw new TypeError("Tarama raporu gecersiz bir modul sonucu iceriyor.");
  }
  assertNonEmptyString(moduleResult.name, "Modul adi", 512);
  assertNonEmptyString(moduleResult.summary, "Modul ozeti");
  if (!MODULE_STATUSES.has(moduleResult.status)) {
    throw new TypeError("Tarama raporu gecersiz bir modul durumu iceriyor.");
  }
  if (
    moduleResult.items_seen !== undefined &&
    (!Number.isSafeInteger(moduleResult.items_seen) || moduleResult.items_seen < 0)
  ) {
    throw new TypeError("Tarama raporu gecersiz bir modul oge sayisi iceriyor.");
  }
  if (moduleResult.metadata !== undefined) {
    if (!isRecord(moduleResult.metadata)) {
      throw new TypeError("Tarama raporu gecersiz modul metadatasi iceriyor.");
    }
    for (const metadataValue of Object.values(moduleResult.metadata)) {
      if (typeof metadataValue !== "string") {
        throw new TypeError("Tarama raporu modul metadatasinda metin olmayan deger iceriyor.");
      }
    }
  }
  assertStringArray(moduleResult.limitations, "Modul sinirlamalari", 1_000);
  assertStringArray(moduleResult.errors, "Modul hatalari", 1_000);
}

function validateFinding(finding, expectedScanType, fingerprints) {
  if (!isRecord(finding)) {
    throw new TypeError("Tarama raporu gecersiz bir bulgu iceriyor.");
  }
  assertNonEmptyString(finding.rule_id, "Bulgu kural kimligi", 512);
  assertNonEmptyString(finding.module, "Bulgu modulu", 512);
  assertNonEmptyString(finding.title, "Bulgu basligi");
  assertNonEmptyString(finding.description, "Bulgu aciklamasi");
  if (!SEVERITIES.has(finding.severity)) {
    throw new TypeError("Tarama raporu gecersiz bir bulgu siddeti iceriyor.");
  }
  if (typeof finding.fingerprint !== "string" || !FINGERPRINT_PATTERN.test(finding.fingerprint)) {
    throw new TypeError("Tarama raporu gecersiz bir bulgu fingerprint'i iceriyor.");
  }
  if (fingerprints.has(finding.fingerprint)) {
    throw new TypeError("Tarama raporu yinelenen bir bulgu fingerprint'i iceriyor.");
  }
  fingerprints.add(finding.fingerprint);

  for (const key of ["confidence", "cwe", "cve", "remediation"]) {
    assertOptionalString(finding[key], `Bulgu ${key} alani`);
  }
  assertStringArray(finding.references, "Bulgu referanslari", 1_000);

  if (finding.evidence !== undefined) {
    if (!isRecord(finding.evidence)) {
      throw new TypeError("Tarama raporu gecersiz bulgu kaniti iceriyor.");
    }
    assertOptionalString(finding.evidence.location, "Bulgu konumu", 4_096);
    assertOptionalString(finding.evidence.url, "Bulgu URL'si", 2_048);
    assertOptionalString(finding.evidence.snippet, "Bulgu ornegi");
    if (
      finding.evidence.line !== undefined &&
      (!Number.isSafeInteger(finding.evidence.line) || finding.evidence.line < 0)
    ) {
      throw new TypeError("Tarama raporu gecersiz bulgu satir numarasi iceriyor.");
    }
    if (expectedScanType === "web" && finding.evidence.url) {
      assertRedactedWebUrl(finding.evidence.url, "Bulgu kanit URL'si");
    }
    if (finding.evidence.details !== undefined) {
      if (!isRecord(finding.evidence.details)) {
        throw new TypeError("Tarama raporu gecersiz bulgu ayrintilari iceriyor.");
      }
      for (const detailValue of Object.values(finding.evidence.details)) {
        if (typeof detailValue !== "string") {
          throw new TypeError("Tarama raporu bulgu ayrintilarinda metin olmayan deger iceriyor.");
        }
      }
    }
  }
}

export function validateReportValue(report) {
  if (!isRecord(report)) {
    throw new TypeError("Tarama raporunun kok degeri bir nesne olmalidir.");
  }

  const pending = [{ value: report, depth: 0 }];
  let visitedNodes = 0;
  while (pending.length > 0) {
    const { value, depth } = pending.pop();
    visitedNodes += 1;
    if (visitedNodes > MAX_REPORT_NODES || depth > MAX_REPORT_DEPTH) {
      throw new TypeError("Tarama raporu yapi sinirini asti.");
    }

    if (typeof value === "string") {
      if (Buffer.byteLength(value, "utf8") > MAX_REPORT_STRING_BYTES) {
        throw new TypeError("Tarama raporundaki bir metin siniri asti.");
      }
      continue;
    }
    if (value === null || typeof value === "boolean") continue;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new TypeError("Tarama raporu sonlu olmayan bir sayi iceriyor.");
      }
      continue;
    }
    if (!Array.isArray(value) && !isRecord(value)) {
      throw new TypeError("Tarama raporu desteklenmeyen bir deger iceriyor.");
    }

    const entries = Array.isArray(value) ? value.entries() : Object.entries(value);
    for (const [key, child] of entries) {
      if (typeof key === "string" && key.length > 512) {
        throw new TypeError("Tarama raporundaki bir alan adi siniri asti.");
      }
      pending.push({ value: child, depth: depth + 1 });
    }
  }
}

export function validateReportSchema(report, expectedScanType, expectedProfile, expectedTarget) {
  if (
    report.schema_version !== "1.0" ||
    !isRecord(report.tool) ||
    report.tool.name !== "WebCyber" ||
    !isRecord(report.scan) ||
    report.scan.type !== expectedScanType ||
    report.scan.profile !== expectedProfile ||
    !SCAN_STATUSES.has(report.scan.status) ||
    !isRecord(report.summary) ||
    !Array.isArray(report.modules) ||
    report.modules.length > MAX_REPORT_MODULES ||
    !Array.isArray(report.findings) ||
    report.findings.length > MAX_REPORT_FINDINGS
  ) {
    throw new TypeError("Tarama raporu beklenen WebCyber 1.0 semasiyla uyusmuyor.");
  }

  assertNonEmptyString(report.tool.version, "Tarama motoru surumu", 256);
  assertNonEmptyString(report.scan.id, "Tarama kimligi", 256);
  validateReportTarget(report.scan.target, expectedScanType, expectedTarget);
  const startedAt = parseTimestamp(report.scan.started_at, "Tarama baslangic zamani");
  const finishedAt = parseTimestamp(report.scan.finished_at, "Tarama bitis zamani");
  if (
    finishedAt < startedAt ||
    !Number.isSafeInteger(report.scan.duration_ms) ||
    report.scan.duration_ms < 0 ||
    report.scan.duration_ms > DESKTOP_SCAN_TIMEOUT_MS ||
    Math.abs(finishedAt - startedAt - report.scan.duration_ms) > MAX_TIMESTAMP_DRIFT_MS
  ) {
    throw new TypeError("Tarama raporu tutarsiz tarih veya sure bilgisi iceriyor.");
  }

  for (const key of SUMMARY_KEYS) {
    if (!Number.isSafeInteger(report.summary[key]) || report.summary[key] < 0) {
      throw new TypeError("Tarama raporu gecersiz bir ozet iceriyor.");
    }
  }

  for (const moduleResult of report.modules) validateModuleResult(moduleResult);
  assertStringArray(report.limitations, "Rapor sinirlamalari", 2_000);

  const counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const fingerprints = new Set();
  for (const finding of report.findings) {
    validateFinding(finding, expectedScanType, fingerprints);
    counts.total += 1;
    counts[finding.severity] += 1;
  }
  for (const key of SUMMARY_KEYS) {
    if (report.summary[key] !== counts[key]) {
      throw new TypeError("Tarama raporu ozeti bulgu sayilariyla tutarli degil.");
    }
  }
}

export function parseValidatedReport(stdout, expected) {
  const bytes = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout ?? "");
  const report = JSON.parse(bytes.toString("utf8"));
  validateReportValue(report);
  validateReportSchema(report, expected.scanType, expected.profile, expected.target);
  return report;
}

function safeErrorMessage(error) {
  const message =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "Bilinmeyen tarama hatasi.";
  return message.slice(0, 2_000);
}

export function interpretScannerCompletion({
  stdout,
  expected,
  processResult = {},
  failure = null,
}) {
  let report = null;
  let reportIsValid = false;
  try {
    report = parseValidatedReport(stdout, expected);
    reportIsValid = true;
  } catch {
    report = null;
  }

  if (failure) {
    return {
      status: failure.kind === "cancelled" ? "cancelled" : "error",
      report,
      error: safeErrorMessage(failure.message),
    };
  }
  if (processResult.error) {
    return {
      status: "error",
      report: null,
      error: safeErrorMessage(processResult.error),
    };
  }

  const exitCode = processResult.code;
  if (exitCode !== 0) {
    if (
      reportIsValid &&
      (report.scan.status === "failed" || report.scan.status === "partial")
    ) {
      return {
        status: "error",
        report,
        error: `Tarama motoru ${String(exitCode)} cikis koduyla sonlandi; dogrulanmis ${report.scan.status} raporu asagida gosteriliyor.`,
      };
    }
    return {
      status: "error",
      report: null,
      error: `Tarama motoru ${String(exitCode)} cikis koduyla sonlandi ve gecerli bir failed/partial rapor uretmedi.`,
    };
  }

  if (!reportIsValid) {
    return {
      status: "error",
      report: null,
      error: "Tarama motoru guvenli ve gecerli bir JSON raporu uretmedi.",
    };
  }
  if (report.scan.status === "failed") {
    return {
      status: "error",
      report,
      error: "Tarama motoru basarisiz durumlu dogrulanmis bir rapor uretti.",
    };
  }
  return { status: "success", report, error: null };
}
