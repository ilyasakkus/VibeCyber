"use client";

import {
  FormEvent,
  type CSSProperties,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

type TargetType = "web" | "source" | "mobile" | "desktop";
type Profile = "observe" | "safe";
type JobStatus =
  | "queued"
  | "running"
  | "cancelling"
  | "completed"
  | "partial"
  | "failed"
  | "cancelled";
type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
type ConfidenceLevel = "high" | "medium" | "low" | "unspecified";
type APIState = "loading" | "online" | "offline";

type Capabilities = {
  web: boolean;
  source: boolean;
  mobile: boolean;
  desktop: boolean;
  localPaths: boolean;
  maxConcurrency: number;
};

type HealthResponse = {
  status: string;
  version: string;
  capabilities: Capabilities;
};

type ReportFinding = {
  rule_id: string;
  fingerprint: string;
  module: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence?: string;
  cwe?: string;
  cve?: string;
  description: string;
  remediation?: string;
  evidence?: {
    location?: string;
    line?: number;
    url?: string;
    snippet?: string;
    details?: Record<string, string>;
  };
};

type ScanReport = {
  schema_version: string;
  scan?: {
    id: string;
    type: TargetType;
    target: string;
    profile: Profile;
    status: string;
    started_at?: string;
    finished_at?: string;
    duration_ms?: number;
  };
  summary?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings?: ReportFinding[];
  limitations?: string[];
};

type ScanJob = {
  id: string;
  type: TargetType;
  target: string;
  profile: Profile;
  status: JobStatus;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  report?: ScanReport;
};

type UIFinding = {
  key: string;
  id: string;
  title: string;
  detail: string;
  description: string;
  remediation?: string;
  target: string;
  severity: Severity;
  severityKey: string;
  confidence: ConfidenceLevel;
  age: string;
};

type FindingSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

const REPORT_HYDRATION_LIMIT = 10;
const FINDING_CACHE_LIMIT = 1000;
const FINDING_PAGE_SIZE = 50;

const targetOptions: Array<{
  id: TargetType;
  label: string;
  eyebrow: string;
  icon: string;
}> = [
  { id: "web", label: "Web / API", eyebrow: "URL", icon: "◎" },
  { id: "source", label: "Source code", eyebrow: "SAST + SCA", icon: "〈〉" },
  { id: "mobile", label: "Mobile app", eyebrow: "APK / IPA", icon: "▣" },
  { id: "desktop", label: "Desktop", eyebrow: "Binary / App", icon: "◈" },
];

const targetConfig: Record<
  TargetType,
  { label: string; placeholder: string; hint: string }
> = {
  web: {
    label: "Target address",
    placeholder: "https://app.example.com",
    hint: "Scope is limited to this URL; redirects and private network targets are validated securely.",
  },
  source: {
    label: "Repository or project path",
    placeholder: "/projects/api",
    hint: "Path is analyzed read-only on the machine running the Go control service.",
  },
  mobile: {
    label: "Mobile package path",
    placeholder: "/builds/app-release.apk or app.ipa",
    hint: "APK and IPA packages are analyzed in a local, sandboxed workflow.",
  },
  desktop: {
    label: "App or binary path",
    placeholder: "/Applications/App.app or app.exe",
    hint: "App or binary path must be within the local access range of the Go scanner engine.",
  },
};

const terminalStatuses = new Set<JobStatus>([
  "completed",
  "partial",
  "failed",
  "cancelled",
]);

const severityLabels: Record<ReportFinding["severity"], Severity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const statusLabels: Record<JobStatus, string> = {
  queued: "Queued",
  running: "Scanning",
  cancelling: "Cancelling",
  completed: "Completed",
  partial: "Partial",
  failed: "Failed",
  cancelled: "Cancelled",
};

const secondaryNavItems = [
  { label: "Integrations", icon: "∞" },
  { label: "Reports", icon: "≡" },
  { label: "Settings", icon: "⚙" },
];

function isTargetType(value: unknown): value is TargetType {
  return (
    value === "web" ||
    value === "source" ||
    value === "mobile" ||
    value === "desktop"
  );
}

function isProfile(value: unknown): value is Profile {
  return value === "observe" || value === "safe";
}

function isJobStatus(value: unknown): value is JobStatus {
  return (
    value === "queued" ||
    value === "running" ||
    value === "cancelling" ||
    value === "completed" ||
    value === "partial" ||
    value === "failed" ||
    value === "cancelled"
  );
}

function normalizeJob(value: unknown): ScanJob | null {
  if (!value || typeof value !== "object") return null;
  const job = value as Partial<ScanJob>;
  if (
    typeof job.id !== "string" ||
    !isTargetType(job.type) ||
    typeof job.target !== "string" ||
    !isProfile(job.profile) ||
    !isJobStatus(job.status) ||
    typeof job.createdAt !== "string"
  ) {
    return null;
  }
  return job as ScanJob;
}

function extractJob(value: unknown) {
  if (value && typeof value === "object") {
    const envelope = value as { scan?: unknown; job?: unknown };
    return (
      normalizeJob(envelope.scan) ??
      normalizeJob(envelope.job) ??
      normalizeJob(value)
    );
  }
  return null;
}

async function responseError(response: Response) {
  try {
    const payload = (await response.json()) as {
      error?: string | { message?: string };
      message?: string;
    };
    if (typeof payload.error === "string") return payload.error;
    if (payload.error?.message) return payload.error.message;
    return payload.message || `Request failed (${response.status}).`;
  } catch {
    return `Request failed (${response.status}).`;
  }
}

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    cache: "no-store",
    headers: {
      accept: "application/json",
      ...init?.headers,
    },
  });
  if (!response.ok) throw new Error(await responseError(response));
  return (await response.json()) as T;
}

function targetKindLabel(kind: TargetType) {
  return targetOptions.find((item) => item.id === kind)?.label ?? "Target";
}

function validateTarget(type: TargetType, value: string) {
  const cleanTarget = value.trim();
  if (!cleanTarget) return { valid: false, error: "Enter a target to scan." };
  if (type !== "web") return { valid: true, error: "" };

  try {
    const parsedTarget = new URL(cleanTarget);
    if (parsedTarget.protocol !== "http:" && parsedTarget.protocol !== "https:") {
      return { valid: false, error: "Web target must start with http:// or https://." };
    }
    if (!parsedTarget.hostname) {
      return { valid: false, error: "Web target must contain a valid hostname." };
    }
    if (parsedTarget.username || parsedTarget.password) {
      return {
        valid: false,
        error: "User credentials cannot be included in the URL.",
      };
    }
    return { valid: true, error: "" };
  } catch {
    return {
      valid: false,
      error: "Enter a valid web URL (e.g., https://app.example.com).",
    };
  }
}

function relativeTime(value?: string) {
  if (!value) return "—";
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function normalizeConfidence(confidence?: string): ConfidenceLevel {
  switch (confidence?.toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "unspecified";
  }
}

const confidenceLabels: Record<ConfidenceLevel, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  unspecified: "Unspecified",
};

function newestJobsPerTarget(scans: ScanJob[]) {
  const seenTargets = new Set<string>();
  const newestFirst = [...scans].sort(
    (a, b) =>
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );

  return newestFirst.filter((job) => {
    const key = `${job.type}\u0000${job.target}`;
    if (seenTargets.has(key)) return false;
    seenTargets.add(key);
    return true;
  });
}

function findingsFromScans(
  scans: ScanJob[],
  limit = FINDING_CACHE_LIMIT,
): UIFinding[] {
  const buckets: Record<ReportFinding["severity"], UIFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };
  const seenOccurrences = new Set<string>();

  for (const job of scans) {
    for (const [index, finding] of (job.report?.findings ?? []).entries()) {
      const location =
        finding.evidence?.location || finding.evidence?.url || job.target;
      const occurrence =
        finding.fingerprint ||
        `${finding.rule_id}\u0000${location}\u0000${finding.evidence?.line ?? 0}`;
      const occurrenceKey = `${job.target}\u0000${occurrence}`;
      if (seenOccurrences.has(occurrenceKey)) continue;
      seenOccurrences.add(occurrenceKey);
      const bucket = buckets[finding.severity] ?? buckets.info;
      if (bucket.length >= limit) continue;

      const classifiers = [finding.cve, finding.cwe, finding.module]
        .filter(Boolean)
        .join(" · ");
      bucket.push({
        key: `${job.id}:${finding.fingerprint || finding.rule_id}:${index}`,
        id: finding.rule_id,
        title: finding.title,
        detail: classifiers || "No classification metadata",
        description: finding.description,
        remediation: finding.remediation,
        target: location,
        severity: severityLabels[finding.severity] ?? "Info",
        severityKey: finding.severity,
        confidence: normalizeConfidence(finding.confidence),
        age: relativeTime(job.finishedAt || job.report?.scan?.finished_at),
      });
    }
  }

  return [
    ...buckets.critical,
    ...buckets.high,
    ...buckets.medium,
    ...buckets.low,
    ...buckets.info,
  ].slice(0, limit);
}

function aggregateReportSummary(scans: ScanJob[]): FindingSummary {
  return scans.reduce<FindingSummary>(
    (summary, job) => {
      const reportSummary = job.report?.summary;
      if (reportSummary) {
        summary.total += reportSummary.total;
        summary.critical += reportSummary.critical;
        summary.high += reportSummary.high;
        summary.medium += reportSummary.medium;
        summary.low += reportSummary.low;
        summary.info += reportSummary.info;
        return summary;
      }

      for (const finding of job.report?.findings ?? []) {
        summary.total += 1;
        summary[finding.severity] += 1;
      }
      return summary;
    },
    { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );
}

function riskIndexFromSummary(
  summary: FindingSummary,
  reportCount: number,
) {
  if (reportCount === 0) return null;
  return Math.min(
    100,
    summary.critical * 22 +
      summary.high * 12 +
      summary.medium * 6 +
      summary.low * 2,
  );
}

export default function Home() {
  const [targetType, setTargetType] = useState<TargetType>("web");
  const [target, setTarget] = useState("");
  const [targetTouched, setTargetTouched] = useState(false);
  const [profile, setProfile] = useState<Profile>("safe");
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [activeNotice, setActiveNotice] = useState(false);
  const [notice, setNotice] = useState("");
  const [apiState, setAPIState] = useState<APIState>("loading");
  const [apiError, setAPIError] = useState("");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isCancellingAll, setIsCancellingAll] = useState(false);
  const [cancellingIDs, setCancellingIDs] = useState<Set<string>>(new Set());
  const [showAllScans, setShowAllScans] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<"All" | Severity>(
    "All",
  );
  const [highConfidenceOnly, setHighConfidenceOnly] = useState(false);
  const [visibleFindingLimit, setVisibleFindingLimit] =
    useState(FINDING_PAGE_SIZE);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [isMobileViewport, setIsMobileViewport] = useState(false);
  const targetTypeRef = useRef<TargetType>("web");
  const reportCacheRef = useRef<Map<string, ScanReport>>(new Map());
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const navCloseButtonRef = useRef<HTMLButtonElement>(null);

  const localPathsEnabled = Boolean(health?.capabilities.localPaths);
  const isLocalTarget = targetType !== "web";
  const targetCapabilityEnabled = useCallback(
    (type: TargetType) => {
      if (apiState !== "online" || !health) return false;
      if (type === "web") return health.capabilities.web;
      return (
        health.capabilities.localPaths &&
        Boolean(health.capabilities[type])
      );
    },
    [apiState, health],
  );
  const targetValidation = useMemo(
    () => validateTarget(targetType, target),
    [target, targetType],
  );
  const showTargetError = targetTouched && !targetValidation.valid;
  const scanCanStart =
    apiState === "online" &&
    targetValidation.valid &&
    scopeConfirmed &&
    !isSubmitting &&
    targetCapabilityEnabled(targetType);
  const activeScans = useMemo(
    () => scans.filter((scan) => !terminalStatuses.has(scan.status)),
    [scans],
  );
  const activeScanIDs = activeScans.map((scan) => scan.id).sort().join("|");
  const cancellableScans = useMemo(
    () =>
      scans.filter(
        (scan) => scan.status === "queued" || scan.status === "running",
      ),
    [scans],
  );
  const cancellingScanCount = useMemo(() => {
    const ids = new Set(cancellingIDs);
    for (const scan of scans) {
      if (scan.status === "cancelling") ids.add(scan.id);
    }
    return ids.size;
  }, [cancellingIDs, scans]);
  const cancellationInProgress =
    isCancellingAll || cancellingScanCount > 0;
  const streamingScanIDs = useMemo(
    () =>
      [...scans]
        .filter(
          (scan) =>
            scan.status === "running" || scan.status === "cancelling",
        )
        .sort((a, b) => {
          if (a.status === "cancelling" && b.status !== "cancelling") return -1;
          if (b.status === "cancelling" && a.status !== "cancelling") return 1;
          return (
            new Date(b.createdAt).getTime() -
            new Date(a.createdAt).getTime()
          );
        })
        .slice(0, 3)
        .map((scan) => scan.id)
        .join("|"),
    [scans],
  );
  const allAssessmentCandidates = useMemo(
    () =>
      newestJobsPerTarget(
        scans.filter(
          (scan) =>
            scan.status === "completed" || scan.status === "partial",
        ),
      ),
    [scans],
  );
  const assessmentCandidates = useMemo(
    () => allAssessmentCandidates.slice(0, REPORT_HYDRATION_LIMIT),
    [allAssessmentCandidates],
  );
  const assessmentScans = useMemo(
    () => assessmentCandidates.filter((scan) => Boolean(scan.report)),
    [assessmentCandidates],
  );
  const allFindings = useMemo(
    () => findingsFromScans(assessmentScans),
    [assessmentScans],
  );
  const aggregateSummary = useMemo(
    () => aggregateReportSummary(assessmentScans),
    [assessmentScans],
  );
  const filteredFindings = useMemo(
    () =>
      allFindings.filter((finding) => {
        const severityMatches =
          severityFilter === "All" || finding.severity === severityFilter;
        const confidenceMatches =
          !highConfidenceOnly || finding.confidence === "high";
        return severityMatches && confidenceMatches;
      }),
    [allFindings, highConfidenceOnly, severityFilter],
  );
  const displayedFindings = filteredFindings.slice(0, visibleFindingLimit);
  const technicalRiskIndex = useMemo(
    () => riskIndexFromSummary(aggregateSummary, assessmentScans.length),
    [aggregateSummary, assessmentScans.length],
  );
  const completedReportCount = assessmentScans.filter(
    (scan) => scan.status === "completed",
  ).length;
  const partialReportCount = assessmentScans.filter(
    (scan) => scan.status === "partial",
  ).length;
  const exportableReportCount = scans.filter((scan) => scan.report).length;
  const missingAssessmentReportCount = assessmentCandidates.filter(
    (scan) => !scan.report,
  ).length;
  const omittedAssessmentTargetCount = Math.max(
    0,
    allAssessmentCandidates.length - assessmentCandidates.length,
  );
  const findingsTruncated = aggregateSummary.total > allFindings.length;
  const reportCoverage =
    assessmentCandidates.length === 0
      ? null
      : Math.round(
          (assessmentScans.length / assessmentCandidates.length) * 100,
        );

  const updateJob = useCallback((job: ScanJob) => {
    const cachedReport = reportCacheRef.current.get(job.id);
    const nextJob =
      job.report || !cachedReport ? job : { ...job, report: cachedReport };
    if (nextJob.report) {
      reportCacheRef.current.set(nextJob.id, nextJob.report);
    }
    setScans((current) => {
      const exists = current.some((item) => item.id === nextJob.id);
      const next = exists
        ? current.map((item) => (item.id === nextJob.id ? nextJob : item))
        : [nextJob, ...current];
      return next.sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
    });
  }, []);

  const fetchJob = useCallback(
    async (id: string) => {
      try {
        const payload = await fetchJSON<unknown>(
          `/api/control/scans/${encodeURIComponent(id)}`,
        );
        const job = extractJob(payload);
        if (job) updateJob(job);
      } catch {
        // The list poll remains the authoritative fallback for transient SSE errors.
      }
    },
    [updateJob],
  );

  const loadScans = useCallback(async (hydrateReports = false) => {
    const payload = await fetchJSON<{ scans?: unknown[] }>("/api/control/scans");
    const metadataJobs = (payload.scans ?? [])
      .map(normalizeJob)
      .filter((job): job is ScanJob => job !== null)
      .sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
    const hydrationCandidates = newestJobsPerTarget(
      metadataJobs.filter(
        (job) => job.status === "completed" || job.status === "partial",
      ),
    ).slice(0, REPORT_HYDRATION_LIMIT);
    const retainedReportIDs = new Set(
      hydrationCandidates.map((job) => job.id),
    );
    for (const id of reportCacheRef.current.keys()) {
      if (!retainedReportIDs.has(id)) reportCacheRef.current.delete(id);
    }
    const jobs = metadataJobs.map((job) => {
      const report = reportCacheRef.current.get(job.id);
      return report && !job.report ? { ...job, report } : job;
    });
    setScans(jobs);

    if (hydrateReports) {
      const jobsByID = new Map(jobs.map((job) => [job.id, job]));
      const missingReports = hydrationCandidates
        .map((job) => jobsByID.get(job.id) ?? job)
        .filter((job) => !job.report);
      await Promise.all(
        missingReports.map(async (job) => {
          try {
            const detail = await fetchJSON<unknown>(
              `/api/control/scans/${encodeURIComponent(job.id)}`,
            );
            const hydrated = extractJob(detail);
            if (hydrated) updateJob(hydrated);
          } catch {
            // A missing historical report must not take the live control plane offline.
          }
        }),
      );
    }
  }, [updateJob]);

  const connectControlPlane = useCallback(async (showLoading = true) => {
    if (showLoading) {
      setAPIState("loading");
    }
    setAPIError("");
    try {
      const nextHealth = await fetchJSON<HealthResponse>("/api/control/health");
      setHealth(nextHealth);
      const currentTargetType = targetTypeRef.current;
      const currentTargetEnabled =
        currentTargetType === "web"
          ? nextHealth.capabilities.web
          : nextHealth.capabilities.localPaths &&
            nextHealth.capabilities[currentTargetType];
      if (
        !currentTargetEnabled &&
        currentTargetType !== "web"
      ) {
        targetTypeRef.current = "web";
        setTargetType("web");
        setTarget("");
        setTargetTouched(false);
        setScopeConfirmed(false);
      }
      await loadScans(true);
      setAPIState("online");
    } catch (error) {
      setHealth(null);
      setAPIState("offline");
      if (targetTypeRef.current !== "web") {
        targetTypeRef.current = "web";
        setTargetType("web");
        setTarget("");
        setTargetTouched(false);
        setScopeConfirmed(false);
      }
      setAPIError(
        error instanceof Error
          ? error.message
          : "Control service is unreachable.",
      );
    }
  }, [loadScans]);

  useEffect(() => {
    const connectTimer = window.setTimeout(() => {
      void connectControlPlane();
    }, 0);
    return () => window.clearTimeout(connectTimer);
  }, [connectControlPlane]);

  useEffect(() => {
    const probe = () => {
      if (document.visibilityState === "visible") {
        void connectControlPlane(false);
      }
    };
    const healthTimer = window.setInterval(probe, 20_000);
    document.addEventListener("visibilitychange", probe);
    return () => {
      window.clearInterval(healthTimer);
      document.removeEventListener("visibilitychange", probe);
    };
  }, [connectControlPlane]);

  useEffect(() => {
    if (!notice) return;
    const noticeTimer = window.setTimeout(() => setNotice(""), 6000);
    return () => window.clearTimeout(noticeTimer);
  }, [notice]);

  useEffect(() => {
    const mobileQuery = window.matchMedia("(max-width: 780px)");
    const updateViewport = () => {
      setIsMobileViewport(mobileQuery.matches);
      if (!mobileQuery.matches) setMobileNavOpen(false);
    };
    updateViewport();
    mobileQuery.addEventListener("change", updateViewport);
    return () => mobileQuery.removeEventListener("change", updateViewport);
  }, []);

  useEffect(() => {
    if (!isMobileViewport || !mobileNavOpen) return;
    const focusFrame = window.requestAnimationFrame(() => {
      navCloseButtonRef.current?.focus();
    });
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setMobileNavOpen(false);
      window.requestAnimationFrame(() => mobileMenuButtonRef.current?.focus());
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [isMobileViewport, mobileNavOpen]);

  useEffect(() => {
    if (apiState !== "online" || !streamingScanIDs) return;
    const ids = streamingScanIDs.split("|");
    const sources = ids.map((id) => {
      const source = new EventSource(
        `/api/control/scans/${encodeURIComponent(id)}/events`,
      );
      const refresh = () => void fetchJob(id);
      source.onmessage = refresh;
      for (const eventName of [
        "running",
        "cancelling",
        "completed",
        "partial",
        "failed",
        "cancelled",
        "scan",
      ]) {
        source.addEventListener(eventName, refresh);
      }
      return source;
    });

    return () => sources.forEach((source) => source.close());
  }, [apiState, fetchJob, streamingScanIDs]);

  useEffect(() => {
    if (apiState !== "online" || !activeScanIDs) return;
    const poll = window.setInterval(() => {
      void loadScans(true).catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(poll);
  }, [activeScanIDs, apiState, loadScans]);

  function changeTargetType(nextType: TargetType) {
    if (!targetCapabilityEnabled(nextType)) {
      setNotice("This target type is not enabled in control service capabilities.");
      return;
    }
    targetTypeRef.current = nextType;
    setTargetType(nextType);
    setTarget("");
    setTargetTouched(false);
    setScopeConfirmed(false);
    setActiveNotice(false);
  }

  function closeMobileNav(restoreFocus = true) {
    setMobileNavOpen(false);
    if (restoreFocus && isMobileViewport) {
      window.requestAnimationFrame(() => mobileMenuButtonRef.current?.focus());
    }
  }

  async function submitScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!targetValidation.valid) {
      setTargetTouched(true);
      setNotice(targetValidation.error);
      return;
    }
    if (!scopeConfirmed) {
      setNotice("Confirm authorization before starting a scan.");
      return;
    }
    if (!targetCapabilityEnabled(targetType)) {
      setNotice("This target type is not enabled in control service capabilities.");
      return;
    }

    setIsSubmitting(true);
    try {
      const payload = await fetchJSON<unknown>("/api/control/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          type: targetType,
          target: target.trim(),
          profile,
          authorized: true,
        }),
      });
      const job = extractJob(payload);
      if (!job) throw new Error("Control service did not return a valid scan job.");
      updateJob(job);
      setScopeConfirmed(false);
      setNotice(`${job.id} scan queued.`);
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : "Failed to start scan.",
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  async function cancelAllScans() {
    if (cancellableScans.length === 0 || isCancellingAll) return;
    setIsCancellingAll(true);
    try {
      await fetchJSON<unknown>("/api/control/scans", { method: "DELETE" });
      await loadScans(true);
      setNotice(
        `Cancellation signal sent for ${cancellableScans.length} queued or running jobs.`,
      );
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : "Failed to cancel jobs.",
      );
    } finally {
      setIsCancellingAll(false);
    }
  }

  async function cancelScan(scan: ScanJob) {
    if (
      (scan.status !== "queued" && scan.status !== "running") ||
      cancellingIDs.has(scan.id)
    ) {
      return;
    }
    setCancellingIDs((current) => new Set(current).add(scan.id));
    try {
      const payload = await fetchJSON<unknown>(
        `/api/control/scans/${encodeURIComponent(scan.id)}`,
        { method: "DELETE" },
      );
      const job = extractJob(payload);
      if (job) updateJob(job);
      else await fetchJob(scan.id);
      setNotice(`Cancellation signal sent for job ${scan.id}.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Failed to cancel job.");
    } finally {
      setCancellingIDs((current) => {
        const next = new Set(current);
        next.delete(scan.id);
        return next;
      });
    }
  }

  function exportReports() {
    const reports = scans.flatMap((scan) => (scan.report ? [scan.report] : []));
    if (reports.length === 0) {
      setNotice("No loaded reports available for export.");
      return;
    }
    const blob = new Blob([JSON.stringify(reports, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `vibe-cyber-reports-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    setNotice(`Downloaded ${reports.length} loaded JSON report(s).`);
  }

  const navItems = [
    { label: "Overview", icon: "▦", badge: "", href: "#overview" },
    {
      label: "Scans",
      icon: "◎",
      badge: scans.length ? String(scans.length) : "",
      href: "#scans",
    },
    {
      label: "Findings",
      icon: "◇",
      badge: aggregateSummary.total ? String(aggregateSummary.total) : "",
      href: "#findings",
    },
    { label: "Assets", icon: "⌘", badge: "", href: null },
    { label: "Policies", icon: "⊡", badge: "", href: null },
  ];
  const displayedScans = showAllScans ? scans : scans.slice(0, 4);
  const scoreStyle = {
    "--score": `${technicalRiskIndex ?? 0}%`,
  } as CSSProperties;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>

      <aside
        className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}
        id="mobile-navigation"
        aria-hidden={isMobileViewport && !mobileNavOpen ? true : undefined}
        inert={isMobileViewport && !mobileNavOpen}
      >
        <div className="brand-row">
          <div className="brand-mark" aria-hidden="true">
            V<span>C</span>
          </div>
          <div className="brand-copy">
            <strong>Vibe Cyber</strong>
            <span>V.1.0</span>
          </div>
          <button
            className="nav-close"
            type="button"
            aria-label="Close menu"
            ref={navCloseButtonRef}
            onClick={() => closeMobileNav()}
          >
            ×
          </button>
        </div>

        <div className="workspace-switcher">
          <span className="workspace-avatar">VC</span>
          <span>
            <small>Workspace</small>
            <strong>Local control plane</strong>
          </span>
          <span className="workspace-chevron" aria-hidden="true">
            ⌄
          </span>
        </div>

        <nav className="primary-nav" aria-label="Main menu">
          <span className="nav-heading">OPERATIONS</span>
          {navItems.map((item, index) =>
            item.href ? (
              <a
                className={`nav-item ${index === 0 ? "active" : ""}`}
                href={item.href}
                aria-current={index === 0 ? "page" : undefined}
                key={item.label}
                onClick={() => closeMobileNav()}
              >
                <span className="nav-icon" aria-hidden="true">
                  {item.icon}
                </span>
                <span>{item.label}</span>
                {item.badge && <span className="nav-badge">{item.badge}</span>}
              </a>
            ) : (
              <button
                className="nav-item nav-item-disabled"
                type="button"
                disabled
                key={item.label}
              >
                <span className="nav-icon" aria-hidden="true">
                  {item.icon}
                </span>
                <span>{item.label}</span>
                <span className="nav-soon">Soon</span>
              </button>
            ),
          )}

          <span className="nav-heading secondary-heading">MANAGEMENT</span>
          {secondaryNavItems.map((item) => (
            <button
              className="nav-item nav-item-disabled"
              type="button"
              disabled
              key={item.label}
            >
              <span className="nav-icon" aria-hidden="true">
                {item.icon}
              </span>
              <span>{item.label}</span>
              <span className="nav-soon">Soon</span>
            </button>
          ))}
        </nav>

        <div className="agent-mini-card">
          <div className="agent-mini-head">
            <span className={`status-dot ${apiState === "online" ? "online" : ""}`} />
            <strong>Go scanner engine</strong>
          </div>
          <p>
            {apiState === "online"
              ? `v${health?.version || "—"} · ${localPathsEnabled ? "Local paths enabled" : "Web targets only"}`
              : apiState === "loading"
                ? "Checking connection..."
                : "Control service offline"}
          </p>
          <button
            type="button"
            onClick={() => void connectControlPlane()}
            disabled={apiState === "loading"}
          >
            {apiState === "loading" ? "Checking…" : "Refresh connection"}
          </button>
        </div>

        <div className="sidebar-footer">
          <span className="user-avatar">VC</span>
          <span>
            <strong>Vibe Cyber V.1.0</strong>
            <small>Vibe Coders Security Hand Tool</small>
          </span>
        </div>
      </aside>

      {mobileNavOpen && (
        <button
          className="nav-backdrop"
          type="button"
          aria-label="Close menu"
          onClick={() => closeMobileNav()}
        />
      )}

      <div className="main-column">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu-button"
              type="button"
              aria-label="Open menu"
              aria-expanded={mobileNavOpen}
              aria-controls="mobile-navigation"
              ref={mobileMenuButtonRef}
              onClick={() => setMobileNavOpen(true)}
            >
              ☰
            </button>
            <div className="breadcrumb">
              <span>Operations Center</span>
              <b>/</b>
              <strong>Overview</strong>
            </div>
          </div>
          <div className="topbar-actions">
            <div
              className={`environment-chip ${apiState === "offline" ? "offline" : ""}`}
              role="status"
            >
              <span />{" "}
              {apiState === "online"
                ? "Go engine connected"
                : apiState === "loading"
                  ? "Connecting"
                  : "Engine offline"}
            </div>
          </div>
        </header>

        <main id="main-content">
          <div
            className={`demo-banner ${apiState === "offline" ? "api-offline" : apiState === "online" ? "api-online" : ""}`}
            role={apiState === "offline" ? "alert" : "status"}
          >
            <span className="demo-banner-label">
              {apiState === "online"
                ? "LIVE"
                : apiState === "loading"
                  ? "CONNECT"
                  : "OFFLINE"}
            </span>
            <p>
              <strong>
                {apiState === "online"
                  ? "Real Go control plane connected"
                  : apiState === "loading"
                    ? "Connecting to control service"
                    : "Scanner engine unreachable"}
              </strong>
              <span>
                {apiState === "online"
                  ? `${health?.capabilities.maxConcurrency ?? 0} concurrent jobs · results generated from live scan reports.`
                  : apiState === "loading"
                    ? "Reading health and capability specs."
                    : `${apiError || "Launch Go control service and refresh connection."} Fake data is not displayed.`}
              </span>
            </p>
            {apiState === "offline" && (
              <button
                className="banner-action"
                type="button"
                onClick={() => void connectControlPlane()}
              >
                Retry
              </button>
            )}
          </div>

          <div
            className={`safety-strip ${cancellationInProgress ? "safety-strip-paused" : ""}`}
            id="kill-switch-state"
          >
            <div>
              <span className="safety-icon" aria-hidden="true">
                {cancellationInProgress ? "■" : "✓"}
              </span>
              <p>
                <strong>
                  {isCancellingAll
                    ? "Sending cancellation signal"
                    : cancellingScanCount > 0
                      ? `${cancellingScanCount} job(s) completing cancellation`
                      : "Security boundaries active"}
                </strong>
                <span>
                  Observe & Safe profiles · Authorization required · {activeScans.length} active job(s)
                </span>
              </p>
            </div>
            <button
              type="button"
              onClick={() => void cancelAllScans()}
              disabled={
                apiState !== "online" ||
                cancellableScans.length === 0 ||
                isCancellingAll
              }
            >
              <span aria-hidden="true">■</span>
              {isCancellingAll
                ? "Cancelling…"
                : cancellingScanCount > 0 && cancellableScans.length === 0
                  ? "Completing cancellation…"
                  : "Cancel all active jobs"}
            </button>
          </div>

          <section className="page-heading" id="overview">
            <div>
              <span className="eyebrow">LIVE CONTROL PLANE</span>
              <h1>Vibe Cyber V.1.0</h1>
              <p>Vibe Coders Security Hand Tool</p>
            </div>
            <a className="primary-action" href="#new-scan">
              <span aria-hidden="true">+</span> New scan
            </a>
          </section>

          <section className="overview-grid" aria-label="Security summary">
            <article className="score-card panel">
              <div className="card-heading">
                <div>
                  <span className="section-kicker">OVERALL STATUS</span>
                  <h2>Technical risk index of recent reports</h2>
                </div>
                <button
                  className="text-button"
                  type="button"
                  onClick={() =>
                    setNotice(
                      "Index is derived from severity weights of each target's latest completed or partial report. 0 indicates lower, 100 indicates higher observed technical risk load; not a security guarantee.",
                    )
                  }
                >
                  How is it calculated?
                </button>
              </div>

              <div className="score-content">
                <div
                  className={`score-ring risk-index ${technicalRiskIndex === null ? "score-empty" : ""}`}
                  style={scoreStyle}
                  aria-label={
                    technicalRiskIndex === null
                      ? "Technical risk index not yet calculated"
                      : `Technical risk index ${technicalRiskIndex} out of 100`
                  }
                >
                  <div>
                    <strong>{technicalRiskIndex ?? "—"}</strong>
                    <span>/100</span>
                  </div>
                </div>
                <div className="score-summary">
                  <div className="score-grade">
                    <span className="grade-pill risk">RISK</span>
                    <p>
                      <strong>
                        {technicalRiskIndex === null
                          ? "Awaiting report"
                          : "Severity-weighted technical metric"}
                      </strong>
                      <span>
                        {assessmentScans.length} target report(s) processed
                      </span>
                    </p>
                  </div>
                  <p className="score-note">
                    {technicalRiskIndex === null
                      ? "Index is calculated when the first completed or partial report arrives."
                      : `${aggregateSummary.critical} critical, ${aggregateSummary.high} high severity findings. This index is not a security guarantee.`}
                  </p>
                  <div className="score-bar" aria-hidden="true">
                    <span
                      className="risk"
                      style={{ width: `${technicalRiskIndex ?? 0}%` }}
                    />
                  </div>
                  <div className="score-meta">
                    <span>{aggregateSummary.total} recent report findings</span>
                    <span>{assessmentScans.length} unique targets</span>
                  </div>
                </div>
              </div>
            </article>

            <div className="metric-grid">
              <article className="metric-card panel">
                <div className="metric-icon critical" aria-hidden="true">!</div>
                <div>
                  <span>Critical findings</span>
                  <strong>{aggregateSummary.critical}</strong>
                  <small>Latest target reports</small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon high" aria-hidden="true">↑</div>
                <div>
                  <span>High risk</span>
                  <strong>{aggregateSummary.high}</strong>
                  <small>Latest target reports</small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon verified" aria-hidden="true">✓</div>
                <div>
                  <span>Evaluated targets</span>
                  <strong>{assessmentScans.length}</strong>
                  <small>
                    {completedReportCount} completed · {partialReportCount} partial
                  </small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon coverage" aria-hidden="true">◎</div>
                <div>
                  <span>Report coverage</span>
                  <strong>{reportCoverage === null ? "—" : `%${reportCoverage}`}</strong>
                  <small>
                    {assessmentScans.length} / {assessmentCandidates.length} selected target reports loaded
                  </small>
                </div>
              </article>
            </div>
          </section>

          <section className="operations-grid">
            <article className="new-scan-card panel" id="new-scan">
              <div className="card-heading scan-heading">
                <div>
                  <span className="section-kicker">ORCHESTRATOR</span>
                  <h2>Create new scan</h2>
                  <p>Launch a real scan job with target, profile, and explicit authorization declaration.</p>
                </div>
                <span className="safe-badge">
                  <span /> Observe / Safe
                </span>
              </div>

              <form onSubmit={submitScan} noValidate>
                <div className="target-tabs" role="group" aria-label="Target type">
                  {targetOptions.map((option) => {
                    const disabled = !targetCapabilityEnabled(option.id);
                    return (
                      <button
                        type="button"
                        aria-pressed={targetType === option.id}
                        aria-describedby={disabled ? "local-capability-help" : undefined}
                        className={targetType === option.id ? "selected" : ""}
                        disabled={disabled}
                        key={option.id}
                        onClick={() => changeTargetType(option.id)}
                      >
                        <span className="target-icon" aria-hidden="true">
                          {option.icon}
                        </span>
                        <span>
                          <strong>{option.label}</strong>
                          <small>{disabled ? "Local path disabled" : option.eyebrow}</small>
                        </span>
                      </button>
                    );
                  })}
                </div>
                <p className="sr-only" id="local-capability-help">
                  Local path access must be enabled in the Go control service for this target type.
                </p>

                <div className="field-group">
                  <label htmlFor="scan-target">{targetConfig[targetType].label}</label>
                  <div className={`input-shell ${showTargetError ? "invalid" : ""}`}>
                    <span className="input-prefix" aria-hidden="true">
                      {targetOptions.find((option) => option.id === targetType)?.icon}
                    </span>
                    <input
                      id="scan-target"
                      type={targetType === "web" ? "url" : "text"}
                      value={target}
                      onChange={(event) => {
                        setTarget(event.target.value);
                        setTargetTouched(true);
                        setScopeConfirmed(false);
                      }}
                      onBlur={() => setTargetTouched(true)}
                      placeholder={targetConfig[targetType].placeholder}
                      autoComplete="off"
                      spellCheck="false"
                      aria-invalid={showTargetError}
                      aria-describedby="scan-target-help"
                      disabled={apiState !== "online"}
                    />
                    <span className={`input-status ${showTargetError ? "invalid" : ""}`}>
                      {showTargetError
                        ? "Invalid"
                        : targetValidation.valid
                          ? "Format valid"
                          : "Awaiting target"}
                    </span>
                  </div>
                  <p
                    className={`field-hint ${showTargetError ? "field-error" : ""}`}
                    id="scan-target-help"
                    role={showTargetError ? "alert" : undefined}
                  >
                    {showTargetError
                      ? targetValidation.error
                      : targetConfig[targetType].hint}
                  </p>
                </div>

                {isLocalTarget && (
                  <div className="agent-requirement connected">
                    <span className="agent-requirement-icon" aria-hidden="true">✓</span>
                    <div>
                      <strong>Local path scanning enabled</strong>
                      <p>
                        Target is analyzed read-only on the machine running the Go control service using process permissions.
                      </p>
                    </div>
                  </div>
                )}

                <fieldset className="profile-fieldset">
                  <legend>Scan profile</legend>
                  <div className="profile-grid">
                    <button
                      className={`profile-card ${profile === "observe" ? "selected" : ""}`}
                      type="button"
                      aria-pressed={profile === "observe"}
                      onClick={() => {
                        setProfile("observe");
                        setActiveNotice(false);
                      }}
                    >
                      <span className="profile-radio" />
                      <span>
                        <strong>Observe</strong>
                        <small>Passive discovery</small>
                      </span>
                      <em>Read-only</em>
                    </button>
                    <button
                      className={`profile-card ${profile === "safe" ? "selected" : ""}`}
                      type="button"
                      aria-pressed={profile === "safe"}
                      onClick={() => {
                        setProfile("safe");
                        setActiveNotice(false);
                      }}
                    >
                      <span className="profile-radio" />
                      <span>
                        <strong>Safe</strong>
                        <small>Safe observation / static analysis</small>
                      </span>
                      <em>Recommended</em>
                    </button>
                    <button
                      className="profile-card locked"
                      type="button"
                      aria-disabled="true"
                      aria-describedby="active-profile-help"
                      onClick={() => setActiveNotice(true)}
                    >
                      <span className="profile-lock" aria-hidden="true">⌑</span>
                      <span>
                        <strong>Active</strong>
                        <small>Verification tests</small>
                      </span>
                      <em>Locked</em>
                    </button>
                  </div>
                  <p
                    className={`active-profile-help ${activeNotice ? "visible" : ""}`}
                    id="active-profile-help"
                  >
                    <span aria-hidden="true">!</span>
                    Active profile is not available in this build. Only Observe and Safe jobs are accepted.
                  </p>
                </fieldset>

                <div className="scope-row">
                  <label className="scope-check">
                    <input
                      type="checkbox"
                      checked={scopeConfirmed}
                      onChange={(event) => setScopeConfirmed(event.target.checked)}
                      disabled={apiState !== "online"}
                    />
                    <span aria-hidden="true" />
                    <span>
                      <strong>I am authorized to test this target</strong>
                      <small>This declaration resets whenever target changes and is sent with the API request.</small>
                    </span>
                  </label>
                  <button
                    type="submit"
                    className="start-scan-button"
                    disabled={!scanCanStart}
                  >
                    <span aria-hidden="true">▷</span>
                    {isSubmitting ? "Queueing…" : "Start scan"}
                  </button>
                </div>
              </form>
            </article>

            <article className="running-card panel" id="scans">
              <div className="card-heading">
                <div>
                  <span className="section-kicker">LIVE JOB QUEUE</span>
                  <h2>Scan jobs</h2>
                </div>
                <span className="live-indicator">
                  <span /> {activeScans.length} active
                </span>
              </div>

              <div className="scan-list" aria-live="polite">
                {displayedScans.map((scan) => {
                  const active = !terminalStatuses.has(scan.status);
                  const cancelling =
                    scan.status === "cancelling" ||
                    cancellingIDs.has(scan.id);
                  const canCancel =
                    scan.status === "queued" || scan.status === "running";
                  return (
                    <div className="scan-item" key={scan.id}>
                      <div className="scan-item-top">
                        <div className={`scan-kind ${scan.type}`} aria-hidden="true">
                          {targetOptions.find((option) => option.id === scan.type)?.icon}
                        </div>
                        <div className="scan-name">
                          <strong>{targetKindLabel(scan.type)}</strong>
                          <span>{scan.target}</span>
                        </div>
                        <button
                          type="button"
                          aria-label={
                            canCancel
                              ? `Cancel job ${scan.id}`
                              : `${scan.id}: ${statusLabels[scan.status]}`
                          }
                          title={
                            canCancel
                              ? "Cancel job"
                              : statusLabels[scan.status]
                          }
                          onClick={() => void cancelScan(scan)}
                          disabled={!canCancel || cancelling}
                        >
                          {cancelling ? "…" : canCancel ? "■" : active ? "…" : "✓"}
                        </button>
                      </div>
                      <div className="scan-progress-meta">
                        <span>{scan.error || statusLabels[scan.status]}</span>
                        <strong>{scan.profile}</strong>
                      </div>
                      <div
                        className={`progress-track ${scan.status}`}
                        aria-label={`${scan.id}: ${statusLabels[scan.status]}`}
                      >
                        <span />
                      </div>
                      <div className="scan-foot">
                        <span>{scan.id}</span>
                        <span>{relativeTime(scan.startedAt || scan.createdAt)}</span>
                      </div>
                    </div>
                  );
                })}
                {scans.length === 0 && (
                  <div className="empty-state compact">
                    {apiState === "online"
                      ? "No scan jobs yet. Queue your first target above."
                      : "Job queue unavailable because control service is disconnected."}
                  </div>
                )}
              </div>

              {scans.length > 4 && (
                <button
                  type="button"
                  className="view-all-button"
                  aria-expanded={showAllScans}
                  onClick={() => setShowAllScans((current) => !current)}
                >
                  {showAllScans ? "Show last four jobs" : `Show all ${scans.length} jobs`}
                  <span aria-hidden="true">{showAllScans ? "↑" : "↓"}</span>
                </button>
              )}
            </article>
          </section>

          <section className="findings-card panel" id="findings">
            <div className="findings-header">
              <div>
                <span className="section-kicker">RISK VIEW</span>
                <h2>Report findings</h2>
                <p>
                  Uses the latest completed or partial Go report for each target.
                </p>
              </div>
              <button
                type="button"
                className="export-button"
                onClick={exportReports}
                disabled={exportableReportCount === 0}
              >
                <span aria-hidden="true">⇩</span> Download loaded JSON reports
              </button>
            </div>

            <div className="report-scope-note" role="note">
              <span aria-hidden="true">!</span>
              <p>
                <strong>Report and view limits</strong>
                <span>
                  Loads up to {REPORT_HYDRATION_LIMIT} unique targets' latest
                  completed or partial reports; findings view deduplicates by target +
                  fingerprint keeping at most {FINDING_CACHE_LIMIT} rows and shows{" "}
                  {FINDING_PAGE_SIZE}-row pages.
                  {partialReportCount > 0 &&
                    ` ${partialReportCount} partial report(s) may omit full scope; inspect report limitations.`}
                  {missingAssessmentReportCount > 0 &&
                    ` Details for ${missingAssessmentReportCount} selected report(s) could not be loaded; omitted from index and findings.`}
                  {omittedAssessmentTargetCount > 0 &&
                    ` ${omittedAssessmentTargetCount} older unique target report(s) omitted due to resource limits.`}
                  {findingsTruncated &&
                    " Displayed rows may differ from totals due to deduplication or row limits."}
                </span>
              </p>
            </div>

            <div className="findings-toolbar">
              <div className="filter-tabs" aria-label="Filter by severity">
                {(["All", "Critical", "High", "Medium", "Low", "Info"] as const).map(
                  (filter) => (
                    <button
                      type="button"
                      className={severityFilter === filter ? "active" : ""}
                      aria-pressed={severityFilter === filter}
                      key={filter}
                      onClick={() => {
                        setSeverityFilter(filter);
                        setVisibleFindingLimit(FINDING_PAGE_SIZE);
                      }}
                    >
                      {filter}
                      {filter === "All" && (
                        <span>
                          {findingsTruncated
                            ? `${allFindings.length}+`
                            : allFindings.length}
                        </span>
                      )}
                    </button>
                  ),
                )}
              </div>
              <label className="verified-toggle">
                <input
                  type="checkbox"
                  checked={highConfidenceOnly}
                  onChange={(event) => {
                    setHighConfidenceOnly(event.target.checked);
                    setVisibleFindingLimit(FINDING_PAGE_SIZE);
                  }}
                />
                <span aria-hidden="true" />
                High confidence only
              </label>
            </div>

            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Finding</th>
                    <th scope="col">Target</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Confidence</th>
                    <th scope="col">Found</th>
                    <th scope="col">Review</th>
                  </tr>
                </thead>
                <tbody>
                  {displayedFindings.map((finding) => (
                    <tr key={finding.key}>
                      <td>
                        <div className="finding-title">
                          <span className={`severity-marker ${finding.severityKey}`} />
                          <div>
                            <strong>{finding.title}</strong>
                            <small>{finding.id} · {finding.detail}</small>
                          </div>
                        </div>
                      </td>
                      <td><span className="target-cell">{finding.target}</span></td>
                      <td>
                        <span className={`severity-pill ${finding.severityKey}`}>
                          {finding.severity}
                        </span>
                      </td>
                      <td>
                        <span className={`confidence-pill ${finding.confidence}`}>
                          {confidenceLabels[finding.confidence]}
                        </span>
                      </td>
                      <td><span className="age-cell">{finding.age}</span></td>
                      <td>
                        <button
                          type="button"
                          className="review-required-button"
                          aria-label={`Show summary for finding ${finding.id}`}
                          onClick={() =>
                            setNotice(
                              `${finding.description}${finding.remediation ? ` Remediation: ${finding.remediation}` : ""}`,
                            )
                          }
                        >
                          <span aria-hidden="true">!</span>
                          Human review required
                          <b aria-hidden="true">→</b>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredFindings.length === 0 && (
                <div className="empty-state">
                  {allFindings.length === 0
                    ? apiState === "online"
                      ? "No reported findings yet. Results of completed scans will appear here."
                      : "Control service offline; fake findings are not displayed."
                    : "No findings match these filters."}
                </div>
              )}
              {filteredFindings.length > displayedFindings.length && (
                <button
                  type="button"
                  className="load-more-findings"
                  onClick={() =>
                    setVisibleFindingLimit((current) =>
                      Math.min(
                        current + FINDING_PAGE_SIZE,
                        filteredFindings.length,
                      ),
                    )
                  }
                >
                  Show next{" "}
                  {Math.min(
                    FINDING_PAGE_SIZE,
                    filteredFindings.length - displayedFindings.length,
                  )}{" "}
                  findings
                  <span aria-hidden="true">↓</span>
                </button>
              )}
            </div>

            <div className="findings-footer">
              <p>
                <span aria-hidden="true">◉</span>
                {assessmentScans.length} latest target reports ·{" "}
                {aggregateSummary.total} total findings · {allFindings.length} rows
              </p>
              <button
                type="button"
                onClick={() => {
                  setSeverityFilter("All");
                  setHighConfidenceOnly(false);
                  setVisibleFindingLimit(FINDING_PAGE_SIZE);
                }}
              >
                Clear filters <span aria-hidden="true">→</span>
              </button>
            </div>
          </section>

          <footer className="product-footer">
            <span>Vibe Cyber V.1.0 · Vibe Coders Security Hand Tool</span>
            <span>Open Source · Apache-2.0 · Your data stays with you</span>
          </footer>
        </main>
      </div>

      <div
        className={`toast ${notice ? "toast-visible" : ""}`}
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        <span aria-hidden="true">✓</span>
        <p>{notice}</p>
        <button type="button" aria-label="Close notification" onClick={() => setNotice("")}>
          ×
        </button>
      </div>
    </div>
  );
}
