import assert from "node:assert/strict";

import {
  interpretScannerCompletion,
  parseValidatedReport,
  validateReportSchema,
} from "../report-validation.mjs";

const expected = {
  scanType: "web",
  profile: "safe",
  target: "https://example.com/path?access_token=redacted-by-report",
};

const failedReport = {
  schema_version: "1.0",
  tool: { name: "WebCyber", version: "0.1.0" },
  scan: {
    id: "00000000-0000-4000-8000-000000000001",
    type: "web",
    target: "https://example.com/path",
    profile: "safe",
    status: "failed",
    started_at: "2026-07-22T10:00:00Z",
    finished_at: "2026-07-22T10:00:00.850Z",
    duration_ms: 850,
  },
  summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  modules: [
    {
      name: "http-observation",
      status: "error",
      summary: "The read-only observation failed before a response was available.",
      limitations: ["No response headers were available for inspection."],
      errors: ["connection refused"],
    },
  ],
  findings: [],
  limitations: [
    "The web MVP performs one read-only GET and does not crawl or execute payloads.",
  ],
};

const completion = interpretScannerCompletion({
  stdout: Buffer.from(JSON.stringify(failedReport)),
  expected,
  processResult: { code: 1, signal: null },
});
assert.equal(completion.status, "error");
assert.equal(completion.report?.scan.status, "failed");
assert.match(completion.error, /1 cikis koduyla/);
assert.match(JSON.stringify(completion.report), /read-only GET/);

const partialReport = structuredClone(failedReport);
partialReport.scan.status = "partial";
partialReport.modules[0].status = "partial";
const partialCompletion = interpretScannerCompletion({
  stdout: JSON.stringify(partialReport),
  expected,
  processResult: { code: 1, signal: null },
});
assert.equal(partialCompletion.status, "error");
assert.equal(partialCompletion.report?.scan.status, "partial");

const oneFindingReport = structuredClone(partialReport);
oneFindingReport.summary = { total: 1, critical: 0, high: 0, medium: 1, low: 0, info: 0 };
oneFindingReport.findings = [
  {
    rule_id: "web.header.csp.missing",
    fingerprint: `sha256:${"a".repeat(64)}`,
    module: "security-headers",
    title: "Content Security Policy is missing",
    severity: "medium",
    description: "The observed response did not include the header.",
    evidence: { url: "https://example.com/path" },
  },
];
assert.equal(
  parseValidatedReport(JSON.stringify(oneFindingReport), expected).summary.total,
  1,
);

const invalidFingerprint = structuredClone(oneFindingReport);
invalidFingerprint.findings[0].fingerprint = "sha256:not-a-digest";
assert.throws(
  () => parseValidatedReport(JSON.stringify(invalidFingerprint), expected),
  /fingerprint/,
);

const invalidDuration = structuredClone(failedReport);
invalidDuration.scan.duration_ms = 10_000;
assert.throws(
  () => parseValidatedReport(JSON.stringify(invalidDuration), expected),
  /tutarsiz tarih veya sure/,
);

const inconsistentSummary = structuredClone(oneFindingReport);
inconsistentSummary.summary.total = 2;
assert.throws(
  () => parseValidatedReport(JSON.stringify(inconsistentSummary), expected),
  /ozeti bulgu sayilariyla/,
);

const leakedTarget = structuredClone(failedReport);
leakedTarget.scan.target = expected.target;
assert.throws(
  () => parseValidatedReport(JSON.stringify(leakedTarget), expected),
  /redakte edilmis web URL/,
);

const overCap = structuredClone(oneFindingReport);
overCap.findings = new Array(2_001).fill(oneFindingReport.findings[0]);
assert.throws(
  () => validateReportSchema(overCap, expected.scanType, expected.profile, expected.target),
  /WebCyber 1.0 semasiyla/,
);

console.log("Non-zero failed/partial rapor smoke testi basarili.");
