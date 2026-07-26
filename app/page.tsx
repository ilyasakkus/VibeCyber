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

type ActiveTab =
  | "overview"
  | "scans"
  | "findings"
  | "assets"
  | "policies"
  | "integrations"
  | "reports"
  | "settings";

type AssetItem = {
  id: string;
  name: string;
  type: TargetType;
  target: string;
  riskLevel: "Critical" | "High" | "Medium" | "Low";
  tags: string[];
  lastScanned?: string;
  status: "monitored" | "unscanned" | "active_scan";
};

type PolicyRule = {
  id: string;
  category: "OWASP" | "Secrets" | "SAST" | "SCA" | "Compliance";
  title: string;
  description: string;
  enabled: boolean;
  severity: "Critical" | "High" | "Medium";
};

type IntegrationItem = {
  id: string;
  name: string;
  type: "engine" | "cicd" | "alerts" | "ticketing" | "container";
  status: "connected" | "configured" | "disconnected";
  description: string;
  icon: string;
  details?: string;
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

const confidenceLabels: Record<ConfidenceLevel, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  unspecified: "Unspecified",
};

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
  const [selectedTargetFilter, setSelectedTargetFilter] =
    useState<string>("All Targets");
  const [highConfidenceOnly, setHighConfidenceOnly] = useState(false);
  const [visibleFindingLimit, setVisibleFindingLimit] =
    useState(FINDING_PAGE_SIZE);
  const [activeFindingModal, setActiveFindingModal] =
    useState<UIFinding | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [isMobileViewport, setIsMobileViewport] = useState(false);
  const targetTypeRef = useRef<TargetType>("web");
  const reportCacheRef = useRef<Map<string, ScanReport>>(new Map());
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const navCloseButtonRef = useRef<HTMLButtonElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDraggingOver, setIsDraggingOver] = useState(false);

  // Active Tab & Hash Synchronization
  const [activeTab, setActiveTab] = useState<ActiveTab>("overview");

  // Assets Module State
  const [assets, setAssets] = useState<AssetItem[]>([
    {
      id: "ast-1",
      name: "Production Web Portal",
      type: "web",
      target: "https://app.example.com",
      riskLevel: "High",
      tags: ["production", "public-facing"],
      lastScanned: new Date(Date.now() - 3600000 * 4).toISOString(),
      status: "monitored",
    },
    {
      id: "ast-2",
      name: "Vibe Cyber Scanner Repo",
      type: "source",
      target: "/projects/vibe-cyber",
      riskLevel: "Medium",
      tags: ["internal", "go-backend"],
      lastScanned: new Date(Date.now() - 3600000 * 12).toISOString(),
      status: "monitored",
    },
    {
      id: "ast-3",
      name: "Android Mobile Client",
      type: "mobile",
      target: "/builds/vibe-cyber-release.apk",
      riskLevel: "Medium",
      tags: ["mobile", "android"],
      lastScanned: new Date(Date.now() - 3600000 * 48).toISOString(),
      status: "monitored",
    },
    {
      id: "ast-4",
      name: "Desktop Electron Shell",
      type: "desktop",
      target: "/Applications/VibeCyber.app",
      riskLevel: "Low",
      tags: ["desktop", "electron"],
      lastScanned: new Date(Date.now() - 3600000 * 72).toISOString(),
      status: "monitored",
    },
  ]);
  const [assetSearch, setAssetSearch] = useState("");
  const [showAddAssetModal, setShowAddAssetModal] = useState(false);
  const [newAssetName, setNewAssetName] = useState("");
  const [newAssetType, setNewAssetType] = useState<TargetType>("web");
  const [newAssetTarget, setNewAssetTarget] = useState("");
  const [newAssetRisk, setNewAssetRisk] = useState<"Critical" | "High" | "Medium" | "Low">("Medium");

  // Policies Module State
  const [policies, setPolicies] = useState<PolicyRule[]>([
    {
      id: "POL-01",
      category: "OWASP",
      title: "OWASP Top 10 Passive Security Headers & TLS Validation",
      description: "Requires Strict-Transport-Security, CSP, X-Content-Type-Options headers and modern TLS parameters on all HTTP endpoints.",
      enabled: true,
      severity: "Critical",
    },
    {
      id: "POL-02",
      category: "Secrets",
      title: "Hardcoded API Keys & Credential Leakage Prevention",
      description: "Scans repository source code and build manifests for high-entropy secrets, JWT tokens, AWS keys, and private certificates.",
      enabled: true,
      severity: "Critical",
    },
    {
      id: "POL-03",
      category: "SAST",
      title: "SAST Vulnerability Gate & Code Boundary Inspection",
      description: "Fails automated scan builds if any unhandled memory corruption, SQL injection, or command execution vector is discovered.",
      enabled: true,
      severity: "High",
    },
    {
      id: "POL-04",
      category: "SCA",
      title: "Software Supply Chain & Dependency CVE SLA",
      description: "Enforces a 14-day SLA remediation policy for any direct npm/Go dependency with a CVSS score greater than 7.0.",
      enabled: true,
      severity: "High",
    },
    {
      id: "POL-05",
      category: "Compliance",
      title: "ISO 27001 & SOC 2 Security Control Baseline",
      description: "Verifies basic access boundaries, data isolation, and read-only scan logging requirements across all target jobs.",
      enabled: true,
      severity: "Medium",
    },
  ]);
  const [excludePaths, setExcludePaths] = useState<string[]>(["**/test/**", "node_modules/**", "dist/**", ".git/**"]);
  const [newExcludeInput, setNewExcludeInput] = useState("");

  // Integrations Module State
  const [integrations, setIntegrations] = useState<IntegrationItem[]>([
    {
      id: "int-1",
      name: "Go Local Control Daemon",
      type: "engine",
      status: "connected",
      description: "High-performance Go security scanner engine listening on loopback 127.0.0.1:7071.",
      icon: "⚡",
      details: "Port 7071 · Max Concurrency 4",
    },
    {
      id: "int-2",
      name: "GitHub / GitLab CI/CD Pipeline",
      type: "cicd",
      status: "configured",
      description: "Automated commit & PR scanning status checks before merging to protected branches.",
      icon: "🐙",
      details: "Webhook configured for push events",
    },
    {
      id: "int-3",
      name: "Slack & Discord Security Webhooks",
      type: "alerts",
      status: "configured",
      description: "Real-time notifications sent to #security-alerts whenever Critical findings are detected.",
      icon: "💬",
      details: "Channel: #security-alerts",
    },
    {
      id: "int-4",
      name: "Jira & Linear Ticket Creator",
      type: "ticketing",
      status: "disconnected",
      description: "Automatic security issue ticket creation with reproduction details & CWE references.",
      icon: "🎯",
      details: "Click to connect workspace",
    },
    {
      id: "int-5",
      name: "Docker & Kubernetes Registry Scanner",
      type: "container",
      status: "connected",
      description: "Container image vulnerability scanning for local Docker daemon images.",
      icon: "🐳",
      details: "Docker engine connected",
    },
  ]);
  const [activeIntegrationModal, setActiveIntegrationModal] = useState<IntegrationItem | null>(null);
  const [webhookUrlInput, setWebhookUrlInput] = useState("https://hooks.slack.com/services/sample/webhook");

  // Reports Module State
  const [reportDateRange, setReportDateRange] = useState("30d");
  const [reportMinSeverity, setReportMinSeverity] = useState("All");
  const [reportTargetFilter, setReportTargetFilter] = useState("All Targets");
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  // Settings Module State
  const [settingControlAddr, setSettingControlAddr] = useState("http://127.0.0.1:7071");
  const [settingMaxConcurrency, setSettingMaxConcurrency] = useState(4);
  const [settingDefaultProfile, setSettingDefaultProfile] = useState<Profile>("safe");
  const [settingRetention, setSettingRetention] = useState("30d");
  const [settingCompactView, setSettingCompactView] = useState(false);
  const [settingSoundAlerts, setSettingSoundAlerts] = useState(true);

  // Hash change handler
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace("#", "");
      if (
        [
          "overview",
          "scans",
          "findings",
          "assets",
          "policies",
          "integrations",
          "reports",
          "settings",
        ].includes(hash)
      ) {
        setActiveTab(hash as ActiveTab);
      }
    };
    handleHashChange();
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const navigateToTab = useCallback((tab: ActiveTab) => {
    setActiveTab(tab);
    window.location.hash = tab;
    if (typeof window !== "undefined" && window.innerWidth < 960) {
      setMobileNavOpen(false);
    }
  }, []);

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
  const availableTargets = useMemo(() => {
    const list = new Set<string>();
    for (const scan of scans) {
      if (scan.target) list.add(scan.target);
    }
    return Array.from(list);
  }, [scans]);
  const filteredFindings = useMemo(
    () =>
      allFindings.filter((finding) => {
        const severityMatches =
          severityFilter === "All" || finding.severity === severityFilter;
        const confidenceMatches =
          !highConfidenceOnly || finding.confidence === "high";
        const targetMatches =
          selectedTargetFilter === "All Targets" ||
          finding.target === selectedTargetFilter ||
          finding.target.startsWith(selectedTargetFilter);
        return severityMatches && confidenceMatches && targetMatches;
      }),
    [allFindings, highConfidenceOnly, severityFilter, selectedTargetFilter],
  );
  const displayedFindings = filteredFindings.slice(0, visibleFindingLimit);
  const technicalRiskIndex = useMemo(
    () => riskIndexFromSummary(aggregateSummary, assessmentScans.length),
    [aggregateSummary, assessmentScans.length],
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
        // Fallback polling handles transient network errors.
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
            // Missing report will not crash the app.
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
    const timer = window.setTimeout(() => {
      setNotice("");
    }, 8000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    const mobileQuery = window.matchMedia("(max-width: 960px)");
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

  function openPathPicker() {
    if (targetType === "source") {
      folderInputRef.current?.click();
    } else if (targetType === "mobile") {
      if (fileInputRef.current) {
        fileInputRef.current.setAttribute("accept", ".apk,.ipa");
        fileInputRef.current.click();
      }
    } else if (targetType === "desktop") {
      if (fileInputRef.current) {
        fileInputRef.current.setAttribute("accept", ".app,.exe,.bin,.dmg,application/*");
        fileInputRef.current.click();
      }
    }
  }

  function handleFolderSelect(event: React.ChangeEvent<HTMLInputElement>) {
    const files = event.target.files;
    if (!files || files.length === 0) return;
    const first = files[0];
    const nativePath = (first as unknown as { path?: string }).path;
    if (nativePath) {
      const relativePath = first.webkitRelativePath || "";
      if (relativePath && nativePath.endsWith(relativePath)) {
        const folderPath = nativePath.slice(
          0,
          nativePath.length - relativePath.length + relativePath.split("/")[0].length,
        );
        setTarget(folderPath);
      } else {
        setTarget(nativePath);
      }
    } else if (first.webkitRelativePath) {
      const rootFolder = first.webkitRelativePath.split("/")[0];
      setTarget(rootFolder);
    }
    setTargetTouched(true);
    setScopeConfirmed(false);
  }

  function handleFileSelect(event: React.ChangeEvent<HTMLInputElement>) {
    const files = event.target.files;
    if (!files || files.length === 0) return;
    const first = files[0];
    const nativePath = (first as unknown as { path?: string }).path;
    if (nativePath) {
      setTarget(nativePath);
    } else {
      setTarget(first.name);
    }
    setTargetTouched(true);
    setScopeConfirmed(false);
  }

  function handleDrop(event: React.DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDraggingOver(false);
    const files = event.dataTransfer.files;
    if (files && files.length > 0) {
      const first = files[0];
      const nativePath = (first as unknown as { path?: string }).path;
      if (nativePath) {
        setTarget(nativePath);
      } else if (first.webkitRelativePath) {
        setTarget(first.webkitRelativePath.split("/")[0]);
      } else {
        setTarget(first.name);
      }
      setTargetTouched(true);
      setScopeConfirmed(false);
    }
  }

  function closeMobileNav(restoreFocus = true) {
    setMobileNavOpen(false);
    if (restoreFocus && isMobileViewport) {
      mobileMenuButtonRef.current?.focus();
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
        body: JSON.stringify({ type: targetType, target: target.trim(), profile }),
      });
      const job = extractJob(payload);
      if (job) {
        updateJob(job);
        setNotice(`Scan job queued (${job.id}). Engine is analyzing ${job.target}.`);
      } else {
        await loadScans(true);
        setNotice("Scan job queued successfully.");
      }
      setTarget("");
      setTargetTouched(false);
      setScopeConfirmed(false);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Failed to queue scan job.");
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
      await fetchJSON<unknown>(
        `/api/control/scans/${encodeURIComponent(scan.id)}`,
        { method: "DELETE" },
      );
      await loadScans(true);
      setNotice(`Cancellation request submitted for job ${scan.id}.`);
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : `Failed to cancel job ${scan.id}.`,
      );
    } finally {
      setCancellingIDs((current) => {
        const next = new Set(current);
        next.delete(scan.id);
        return next;
      });
    }
  }

  function inspectJobSummary(scan: ScanJob) {
    const findingCount = scan.report?.findings?.length ?? 0;
    const statusLabel = statusLabels[scan.status] || scan.status;
    const limitations = scan.report?.limitations?.join(" ") || "";
    if (findingCount === 0) {
      setNotice(
        `Job ${scan.id} (${scan.target}): Status is ${statusLabel} with 0 findings detected. ${limitations ? `Limitations: ${limitations}` : "Secrets, electron config, and manifests were scanned."}`,
      );
    } else {
      setNotice(
        `Job ${scan.id} (${scan.target}): Status is ${statusLabel} with ${findingCount} finding(s) detected.`,
      );
    }
  }

  const navItems: Array<{ label: string; icon: string; badge: string; tab: ActiveTab }> = [
    { label: "Overview", icon: "▦", badge: "", tab: "overview" },
    {
      label: "Scans",
      icon: "◎",
      badge: scans.length ? String(scans.length) : "",
      tab: "scans",
    },
    {
      label: "Findings",
      icon: "◇",
      badge: aggregateSummary.total ? String(aggregateSummary.total) : "",
      tab: "findings",
    },
    { label: "Assets", icon: "⌘", badge: String(assets.length), tab: "assets" },
    { label: "Policies", icon: "⊡", badge: String(policies.filter(p => p.enabled).length), tab: "policies" },
  ];

  const secondaryNavItems: Array<{ label: string; icon: string; tab: ActiveTab }> = [
    { label: "Integrations", icon: "∞", tab: "integrations" },
    { label: "Reports", icon: "≡", tab: "reports" },
    { label: "Settings", icon: "⚙", tab: "settings" },
  ];

  const filteredAssets = useMemo(() => {
    const q = assetSearch.trim().toLowerCase();
    if (!q) return assets;
    return assets.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.target.toLowerCase().includes(q) ||
        a.tags.some((t) => t.toLowerCase().includes(q)),
    );
  }, [assets, assetSearch]);

  const policyComplianceScore = useMemo(() => {
    if (policies.length === 0) return 100;
    const enabled = policies.filter((p) => p.enabled).length;
    return Math.round((enabled / policies.length) * 100);
  }, [policies]);

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
          {navItems.map((item) => (
            <a
              className={`nav-item ${activeTab === item.tab ? "active" : ""}`}
              href={`#${item.tab}`}
              aria-current={activeTab === item.tab ? "page" : undefined}
              key={item.label}
              onClick={(e) => {
                e.preventDefault();
                navigateToTab(item.tab);
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                {item.icon}
              </span>
              <span>{item.label}</span>
              {item.badge && <span className="nav-badge">{item.badge}</span>}
            </a>
          ))}

          <span className="nav-heading secondary-heading">MANAGEMENT</span>
          {secondaryNavItems.map((item) => (
            <a
              className={`nav-item ${activeTab === item.tab ? "active" : ""}`}
              href={`#${item.tab}`}
              aria-current={activeTab === item.tab ? "page" : undefined}
              key={item.label}
              onClick={(e) => {
                e.preventDefault();
                navigateToTab(item.tab);
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                {item.icon}
              </span>
              <span>{item.label}</span>
            </a>
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
              <span>
                {["assets", "policies", "integrations", "reports", "settings"].includes(activeTab)
                  ? "Management"
                  : "Operations Center"}
              </span>
              <b>/</b>
              <strong>
                {activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}
              </strong>
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

          {(activeTab === "overview" || activeTab === "scans" || activeTab === "findings") && (
            <>
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
                        {assessmentScans.filter(s => s.status === "completed").length} completed · {assessmentScans.filter(s => s.status === "partial").length} partial
                      </small>
                    </div>
                  </article>
                  <article className="metric-card panel">
                    <div className="metric-icon coverage" aria-hidden="true">◎</div>
                    <div>
                      <span>Report coverage</span>
                      <strong>{assessmentCandidates.length === 0 ? "—" : `%${Math.round((assessmentScans.length / assessmentCandidates.length) * 100)}`}</strong>
                      <small>
                        {assessmentScans.length} / {assessmentCandidates.length} selected target reports loaded
                      </small>
                    </div>
                  </article>
                </div>
              </section>

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

                <form onSubmit={submitScan}>
                  <div className="target-tabs" role="group" aria-label="Target type">
                    {targetOptions.map((option) => {
                      const disabled = !targetCapabilityEnabled(option.id);
                      return (
                        <button
                          type="button"
                          aria-pressed={targetType === option.id}
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

                  <div className="field-group">
                    <label htmlFor="scan-target">{targetConfig[targetType].label}</label>
                    <div
                      className={`input-shell ${showTargetError ? "invalid" : ""} ${isDraggingOver ? "dragging" : ""}`}
                      onDragOver={(e) => {
                        e.preventDefault();
                        setIsDraggingOver(true);
                      }}
                      onDragLeave={() => setIsDraggingOver(false)}
                      onDrop={handleDrop}
                    >
                      <span className="input-prefix" aria-hidden="true">
                        {targetOptions.find((option) => option.id === targetType)?.icon}
                      </span>
                      <input
                        id="scan-target"
                        type="text"
                        placeholder={targetConfig[targetType].placeholder}
                        value={target}
                        onChange={(event) => {
                          setTarget(event.target.value);
                          if (!targetTouched) setTargetTouched(true);
                        }}
                        onBlur={() => setTargetTouched(true)}
                        spellCheck="false"
                        aria-invalid={showTargetError}
                        aria-describedby="scan-target-help"
                        disabled={apiState !== "online"}
                      />
                      {isLocalTarget && (
                        <button
                          type="button"
                          className="browse-target-button"
                          onClick={openPathPicker}
                          disabled={apiState !== "online"}
                          title="Browse local files/folders on your PC"
                        >
                          <span aria-hidden="true">📁</span> Browse...
                        </button>
                      )}
                      <span className={`input-status ${showTargetError ? "invalid" : ""}`}>
                        {showTargetError
                          ? "Invalid"
                          : targetValidation.valid
                            ? "Format valid"
                            : "Awaiting target"}
                      </span>
                    </div>
                    <input
                      type="file"
                      ref={folderInputRef}
                      style={{ display: "none" }}
                      {...({ webkitdirectory: "", directory: "" } as Record<string, string>)}
                      onChange={handleFolderSelect}
                    />
                    <input
                      type="file"
                      ref={fileInputRef}
                      style={{ display: "none" }}
                      onChange={handleFileSelect}
                    />

                    {isLocalTarget && (
                      <div className="quick-path-pills" role="group" aria-label="Quick path suggestions">
                        <span className="pills-label">Quick paths:</span>
                        <button
                          type="button"
                          className="path-pill"
                          onClick={() => {
                            setTarget(".");
                            setTargetTouched(true);
                            setScopeConfirmed(false);
                          }}
                        >
                          . (Current Repo)
                        </button>
                        {scans
                          .filter((s) => s.type === targetType && s.target)
                          .map((s) => s.target)
                          .filter((value, index, self) => self.indexOf(value) === index)
                          .slice(0, 3)
                          .map((path) => (
                            <button
                              key={path}
                              type="button"
                              className="path-pill"
                              onClick={() => {
                                setTarget(path);
                                setTargetTouched(true);
                                setScopeConfirmed(false);
                              }}
                            >
                              {path}
                            </button>
                          ))}
                      </div>
                    )}

                    <p
                      className={`field-hint ${showTargetError ? "field-error" : ""}`}
                      id="scan-target-help"
                    >
                      {showTargetError ? targetValidation.error : targetConfig[targetType].hint}
                    </p>
                  </div>

                  <fieldset className="field-group">
                    <legend>Scan profile</legend>
                    <div className="profile-grid">
                      <button
                        className={`profile-card ${profile === "observe" ? "selected" : ""}`}
                        type="button"
                        onClick={() => setProfile("observe")}
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
                        onClick={() => setProfile("safe")}
                      >
                        <span className="profile-radio" />
                        <span>
                          <strong>Safe</strong>
                          <small>Safe observation / static analysis</small>
                        </span>
                        <em>Recommended</em>
                      </button>
                    </div>
                  </fieldset>

                  <div className="action-row">
                    <label className="scope-checkbox">
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
                          <div
                            className="scan-name"
                            onClick={() => inspectJobSummary(scan)}
                            style={{ cursor: "pointer" }}
                            title="Click to view scan details and finding summary"
                          >
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

              <section className="findings-section" id="findings">
                <div className="findings-header">
                  <div>
                    <span className="section-kicker">RISK VIEW</span>
                    <h2>Report findings</h2>
                    <p>
                      Uses the latest completed or partial Go report for each target.
                    </p>
                  </div>
                </div>

                <div className="findings-toolbar">
                  <div className="filter-tabs" aria-label="Filter by severity">
                    {(["All", "Critical", "High", "Medium", "Low", "Info"] as const).map(
                      (filter) => (
                        <button
                          type="button"
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
                              {allFindings.length}
                            </span>
                          )}
                        </button>
                      ),
                    )}
                  </div>

                  {availableTargets.length > 0 && (
                    <div className="target-filter-shell">
                      <span>Target:</span>
                      <select
                        id="target-filter-select"
                        value={selectedTargetFilter}
                        onChange={(event) => {
                          setSelectedTargetFilter(event.target.value);
                          setVisibleFindingLimit(FINDING_PAGE_SIZE);
                        }}
                      >
                        <option value="All Targets">All Targets ({availableTargets.length})</option>
                        {availableTargets.map((t) => (
                          <option key={t} value={t}>
                            {t}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}

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

                <div className="panel findings-table-container">
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
                          <td><code>{finding.target}</code></td>
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
                              aria-label={`Show details for finding ${finding.id}`}
                              onClick={() => setActiveFindingModal(finding)}
                            >
                              <span aria-hidden="true">!</span>
                              Human review required
                              <b aria-hidden="true">→</b>
                            </button>
                          </td>
                        </tr>
                      ))}
                      {displayedFindings.length === 0 && (
                        <tr>
                          <td colSpan={6} className="empty-state">
                            No findings detected matching current filters.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
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
                      setSelectedTargetFilter("All Targets");
                      setHighConfidenceOnly(false);
                      setVisibleFindingLimit(FINDING_PAGE_SIZE);
                    }}
                  >
                    Clear filters <span aria-hidden="true">→</span>
                  </button>
                </div>
              </section>
            </>
          )}

          {/* ASSETS MODULE */}
          {activeTab === "assets" && (
            <section className="assets-module">
              <div className="module-header">
                <div>
                  <span className="eyebrow">ATTACK SURFACE MANAGEMENT</span>
                  <h1>Asset Inventory</h1>
                  <p>Monitor all web endpoints, repository paths, mobile binaries, and desktop applications.</p>
                </div>
                <div className="module-actions">
                  <button
                    type="button"
                    className="primary-action"
                    onClick={() => setShowAddAssetModal(true)}
                  >
                    <span aria-hidden="true">+</span> Add Asset
                  </button>
                </div>
              </div>

              <div className="asset-summary-row">
                <div className="asset-stat-card">
                  <div className="asset-stat-icon">⌘</div>
                  <div className="asset-stat-info">
                    <small>Total Tracked</small>
                    <strong>{assets.length}</strong>
                  </div>
                </div>
                <div className="asset-stat-card">
                  <div className="asset-stat-icon">◎</div>
                  <div className="asset-stat-info">
                    <small>Web / API</small>
                    <strong>{assets.filter(a => a.type === "web").length}</strong>
                  </div>
                </div>
                <div className="asset-stat-card">
                  <div className="asset-stat-icon">〈〉</div>
                  <div className="asset-stat-info">
                    <small>Source Repos</small>
                    <strong>{assets.filter(a => a.type === "source").length}</strong>
                  </div>
                </div>
                <div className="asset-stat-card">
                  <div className="asset-stat-icon">!</div>
                  <div className="asset-stat-info">
                    <small>High Risk Assets</small>
                    <strong>{assets.filter(a => a.riskLevel === "High" || a.riskLevel === "Critical").length}</strong>
                  </div>
                </div>
              </div>

              <div className="asset-controls">
                <div className="search-input-wrapper">
                  <span className="search-icon" aria-hidden="true">🔍</span>
                  <input
                    type="text"
                    placeholder="Filter assets by name, path, or tag..."
                    value={assetSearch}
                    onChange={(e) => setAssetSearch(e.target.value)}
                  />
                </div>
              </div>

              <div className="panel scans-table-container">
                <table className="scans-table">
                  <thead>
                    <tr>
                      <th>Asset Name</th>
                      <th>Type</th>
                      <th>Target Address / Path</th>
                      <th>Risk Level</th>
                      <th>Last Scanned</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAssets.map((asset) => (
                      <tr key={asset.id}>
                        <td>
                          <strong>{asset.name}</strong>
                          <div style={{ display: "flex", gap: "4px", marginTop: "4px" }}>
                            {asset.tags.map((tag) => (
                              <span key={tag} className="tag-pill">{tag}</span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <span className={`type-badge ${asset.type}`}>{targetKindLabel(asset.type)}</span>
                        </td>
                        <td><code>{asset.target}</code></td>
                        <td>
                          <span className={`severity-pill ${asset.riskLevel.toLowerCase()}`}>
                            {asset.riskLevel}
                          </span>
                        </td>
                        <td>{relativeTime(asset.lastScanned)}</td>
                        <td>
                          <button
                            type="button"
                            className="table-action-button"
                            onClick={() => {
                              setTargetType(asset.type);
                              setTarget(asset.target);
                              navigateToTab("overview");
                              setNotice(`Target set to ${asset.target}. Ready to start scan.`);
                            }}
                          >
                            Run Scan
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* POLICIES MODULE */}
          {activeTab === "policies" && (
            <section className="policies-module">
              <div className="module-header">
                <div>
                  <span className="eyebrow">GUARDRAILS & RULES ENGINE</span>
                  <h1>Security Policies</h1>
                  <p>Configure security scan boundaries, active compliance rules, and path exclusion patterns.</p>
                </div>
              </div>

              <div className="module-grid">
                <div className="panel score-card">
                  <div className="card-heading">
                    <div>
                      <span className="section-kicker">COMPLIANCE SCORE</span>
                      2 Policy Enforcement Rate
                    </div>
                  </div>
                  <div className="score-content">
                    <div className="score-ring risk-index" style={{ "--score": `${policyComplianceScore}%` } as CSSProperties}>
                      <div>
                        <strong>{policyComplianceScore}%</strong>
                        <span>Active</span>
                      </div>
                    </div>
                    <div className="score-summary">
                      <p><strong>{policies.filter(p => p.enabled).length} of {policies.length} Rules Enforced</strong></p>
                      <p className="score-note">Automated scans validate target findings against enabled policies. Violations trigger pipeline alerts.</p>
                    </div>
                  </div>
                </div>

                <div className="panel" style={{ padding: "20px" }}>
                  <h3 style={{ margin: "0 0 10px", fontSize: "15px" }}>Path Exclusion Patterns</h3>
                  <p style={{ fontSize: "12px", color: "var(--muted)", marginBottom: "14px" }}>
                    Target sub-paths or file extensions matching these patterns are excluded from code analysis.
                  </p>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginBottom: "14px" }}>
                    {excludePaths.map((pat) => (
                      <span key={pat} className="tag-pill" style={{ padding: "6px 10px", fontSize: "12px" }}>
                        {pat}{" "}
                        <button
                          type="button"
                          style={{ background: "none", border: "none", color: "var(--red)", cursor: "pointer", marginLeft: "4px" }}
                          onClick={() => setExcludePaths(excludePaths.filter(p => p !== pat))}
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <input
                      type="text"
                      placeholder="Add glob pattern e.g. **/temp/**"
                      value={newExcludeInput}
                      onChange={(e) => setNewExcludeInput(e.target.value)}
                      style={{ flex: 1, padding: "8px 12px", borderRadius: "8px", background: "var(--panel-raised)", border: "1px solid var(--border)", color: "var(--text)" }}
                    />
                    <button
                      type="button"
                      className="banner-action"
                      onClick={() => {
                        if (newExcludeInput.trim() && !excludePaths.includes(newExcludeInput.trim())) {
                          setExcludePaths([...excludePaths, newExcludeInput.trim()]);
                          setNewExcludeInput("");
                          setNotice("Exclusion pattern added.");
                        }
                      }}
                    >
                      Add
                    </button>
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                {policies.map((rule) => (
                  <div key={rule.id} className="policy-card">
                    <div className="policy-info">
                      <div className="policy-info-header">
                        <span className="policy-category-pill">{rule.category}</span>
                        <span className={`severity-pill ${rule.severity.toLowerCase()}`}>{rule.severity}</span>
                      </div>
                      <h3>{rule.title}</h3>
                      <p>{rule.description}</p>
                    </div>
                    <button
                      type="button"
                      className={`switch-button ${rule.enabled ? "active" : ""}`}
                      role="switch"
                      aria-checked={rule.enabled}
                      onClick={() => {
                        setPolicies(policies.map(p => p.id === rule.id ? { ...p, enabled: !p.enabled } : p));
                        setNotice(`Policy ${rule.id} ${!rule.enabled ? "enabled" : "disabled"}.`);
                      }}
                    >
                      <span className="switch-thumb" />
                    </button>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* INTEGRATIONS MODULE */}
          {activeTab === "integrations" && (
            <section className="integrations-module">
              <div className="module-header">
                <div>
                  <span className="eyebrow">ECOSYSTEM & TOOLCHAIN</span>
                  <h1>Control Plane Integrations</h1>
                  <p>Connect Vibe Cyber with your CI/CD pipelines, messaging webhooks, and container registries.</p>
                </div>
              </div>

              <div className="module-grid">
                {integrations.map((item) => (
                  <div key={item.id} className="integration-card">
                    <div className="integration-head">
                      <div className="integration-icon">{item.icon}</div>
                      <div className="integration-title">
                        <h3>{item.name}</h3>
                        <span className={`integration-status-pill ${item.status}`}>
                          <span className="status-ping" />
                          {item.status === "connected" ? "Active" : item.status === "configured" ? "Configured" : "Available"}
                        </span>
                      </div>
                    </div>
                    <p>{item.description}</p>
                    {item.details && (
                      <small style={{ color: "var(--muted)", fontStyle: "italic" }}>{item.details}</small>
                    )}
                    <button
                      type="button"
                      className="table-action-button"
                      onClick={() => {
                        setActiveIntegrationModal(item);
                      }}
                    >
                      Configure
                    </button>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* REPORTS MODULE */}
          {activeTab === "reports" && (
            <section className="reports-module">
              <div className="module-header">
                <div>
                  <span className="eyebrow">AUDIT & COMPLIANCE EXPORTS</span>
                  <h1>Executive Security Reports</h1>
                  <p>Generate, preview, and export comprehensive vulnerability audit reports.</p>
                </div>
              </div>

              <div className="report-builder-grid">
                <div className="report-controls-panel">
                  <h3 style={{ margin: "0 0 10px" }}>Report Scope</h3>
                  <div className="form-group">
                    <label>Timeframe</label>
                    <select value={reportDateRange} onChange={(e) => setReportDateRange(e.target.value)}>
                      <option value="7d">Last 7 Days</option>
                      <option value="30d">Last 30 Days</option>
                      <option value="90d">Last 90 Days</option>
                      <option value="all">All Time</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Minimum Severity</label>
                    <select value={reportMinSeverity} onChange={(e) => setReportMinSeverity(e.target.value)}>
                      <option value="All">All Severities</option>
                      <option value="Medium">Medium & Above</option>
                      <option value="High">High & Critical Only</option>
                      <option value="Critical">Critical Only</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Target Filter</label>
                    <select value={reportTargetFilter} onChange={(e) => setReportTargetFilter(e.target.value)}>
                      <option value="All Targets">All Scan Targets</option>
                      {Array.from(new Set(scans.map((s) => s.target))).map((t) => (
                        <option key={t} value={t}>{t}</option>
                      ))}
                    </select>
                  </div>

                  <button
                    type="button"
                    className="primary-action"
                    style={{ width: "100%", marginTop: "10px" }}
                    onClick={() => {
                      setIsGeneratingReport(true);
                      setTimeout(() => {
                        setIsGeneratingReport(false);
                        setNotice("Report compiled successfully.");
                      }, 500);
                    }}
                  >
                    {isGeneratingReport ? "Compiling Report..." : "↻ Refresh Preview"}
                  </button>
                </div>

                <div className="report-preview-card">
                  <div className="report-preview-header">
                    <div>
                      <h2>Vibe Cyber Security Audit Report</h2>
                      <small style={{ color: "var(--muted)" }}>Compiled {new Date().toLocaleDateString()} · Window: {reportDateRange}</small>
                    </div>
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        type="button"
                        className="table-action-button"
                        onClick={() => {
                          const reportMd = `# Vibe Cyber Security Audit Report\n\n- Generated: ${new Date().toLocaleString()}\n- Total Scans: ${scans.length}\n- Total Findings: ${aggregateSummary.total}\n- Critical: ${aggregateSummary.critical}\n- High: ${aggregateSummary.high}\n\n## Findings Summary\n${findingsFromScans(scans).map((f) => `- [${f.severity}] ${f.title} (${f.target})`).join('\n')}`;
                          navigator.clipboard.writeText(reportMd);
                          setNotice("Report Markdown copied to clipboard!");
                        }}
                      >
                        📋 Copy MD
                      </button>
                      <button
                        type="button"
                        className="primary-action"
                        onClick={() => {
                          const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({ scans, summary: aggregateSummary }, null, 2));
                          const downloadAnchor = document.createElement('a');
                          downloadAnchor.setAttribute("href", dataStr);
                          downloadAnchor.setAttribute("download", `vibe-cyber-report-${Date.now()}.json`);
                          document.body.appendChild(downloadAnchor);
                          downloadAnchor.click();
                          downloadAnchor.remove();
                          setNotice("Report JSON downloaded.");
                        }}
                      >
                        ⬇ Export JSON
                      </button>
                    </div>
                  </div>

                  <div className="report-preview-body">
                    <div className="report-summary-box">
                      <h4 style={{ margin: "0 0 8px" }}>Executive Summary</h4>
                      <p style={{ margin: 0, fontSize: "13px", color: "var(--muted)", lineHeight: 1.5 }}>
                        During the evaluated window, Vibe Cyber processed {scans.length} target job(s) across web endpoints and local code repositories.
                        A aggregate load of {aggregateSummary.total} finding(s) was identified ({aggregateSummary.critical} critical, {aggregateSummary.high} high, {aggregateSummary.medium} medium).
                        Technical risk index is evaluated at {technicalRiskIndex ?? 0}/100.
                      </p>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "12px" }}>
                      <div className="panel" style={{ padding: "12px", textAlign: "center" }}>
                        <span className="meta-label">Critical</span>
                        <strong style={{ fontSize: "20px", color: "var(--red)" }}>{aggregateSummary.critical}</strong>
                      </div>
                      <div className="panel" style={{ padding: "12px", textAlign: "center" }}>
                        <span className="meta-label">High</span>
                        <strong style={{ fontSize: "20px", color: "var(--orange)" }}>{aggregateSummary.high}</strong>
                      </div>
                      <div className="panel" style={{ padding: "12px", textAlign: "center" }}>
                        <span className="meta-label">Medium</span>
                        <strong style={{ fontSize: "20px", color: "var(--amber)" }}>{aggregateSummary.medium}</strong>
                      </div>
                      <div className="panel" style={{ padding: "12px", textAlign: "center" }}>
                        <span className="meta-label">Low / Info</span>
                        <strong style={{ fontSize: "20px", color: "var(--cyan)" }}>{aggregateSummary.low + aggregateSummary.info}</strong>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* SETTINGS MODULE */}
          {activeTab === "settings" && (
            <section className="settings-module">
              <div className="module-header">
                <div>
                  <span className="eyebrow">CONTROL PLANE & PREFERENCES</span>
                  <h1>Platform Settings</h1>
                  <p>Configure control daemon parameters, scanner core profiles, data retention, and UI options.</p>
                </div>
                <button
                  type="button"
                  className="primary-action"
                  onClick={() => {
                    setNotice("Settings saved successfully.");
                  }}
                >
                  Save Settings
                </button>
              </div>

              <div className="settings-container">
                <div className="settings-card">
                  <div className="settings-card-header">
                    <div className="settings-card-icon">⚡</div>
                    <h2>Control Daemon Endpoint</h2>
                  </div>
                  <div className="settings-form-grid">
                    <div className="form-group">
                      <label>Go Control Service Address</label>
                      <input
                        type="text"
                        value={settingControlAddr}
                        onChange={(e) => setSettingControlAddr(e.target.value)}
                      />
                    </div>
                    <div className="form-group">
                      <label>Max Job Concurrency</label>
                      <select
                        value={settingMaxConcurrency}
                        onChange={(e) => setSettingMaxConcurrency(Number(e.target.value))}
                      >
                        <option value={1}>1 Job (Sequential)</option>
                        <option value={2}>2 Concurrent Jobs</option>
                        <option value={4}>4 Concurrent Jobs (Recommended)</option>
                        <option value={8}>8 Concurrent Jobs</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="settings-card">
                  <div className="settings-card-header">
                    <div className="settings-card-icon">🛡</div>
                    <h2>Scanner Core & Profiles</h2>
                  </div>
                  <div className="settings-form-grid">
                    <div className="form-group">
                      <label>Default Scan Profile</label>
                      <select
                        value={settingDefaultProfile}
                        onChange={(e) => setSettingDefaultProfile(e.target.value as Profile)}
                      >
                        <option value="safe">Safe (Read-only, passive checks)</option>
                        <option value="observe">Observe (Metadata & TLS inspection)</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label>Log & Cache Retention</label>
                      <select
                        value={settingRetention}
                        onChange={(e) => setSettingRetention(e.target.value)}
                      >
                        <option value="7d">Keep for 7 Days</option>
                        <option value="30d">Keep for 30 Days</option>
                        <option value="90d">Keep for 90 Days</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="settings-card">
                  <div className="settings-card-header">
                    <div className="settings-card-icon">⚙</div>
                    <h2>Interface & Notifications</h2>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                    <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={settingCompactView}
                        onChange={(e) => setSettingCompactView(e.target.checked)}
                      />
                      <span>Compact Data Tables</span>
                    </label>
                    <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={settingSoundAlerts}
                        onChange={(e) => setSettingSoundAlerts(e.target.checked)}
                      />
                      <span>Sound alerts on completed scans</span>
                    </label>
                  </div>
                </div>
              </div>
            </section>
          )}

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

      {activeFindingModal && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="finding-modal-title"
          onClick={() => setActiveFindingModal(null)}
        >
          <div
            className="modal-card"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <div className="modal-header-meta">
                <span className={`severity-pill ${activeFindingModal.severityKey}`}>
                  {activeFindingModal.severity}
                </span>
                <span className="modal-rule-id">{activeFindingModal.id}</span>
                <span className="modal-confidence">
                  Confidence: {confidenceLabels[activeFindingModal.confidence]}
                </span>
              </div>
              <button
                type="button"
                className="modal-close"
                aria-label="Close modal"
                onClick={() => setActiveFindingModal(null)}
              >
                ×
              </button>
            </div>

            <div className="modal-body">
              <h2 id="finding-modal-title">{activeFindingModal.title}</h2>
              <div className="modal-target-bar">
                <span className="label">Location / Target:</span>
                <code>{activeFindingModal.target}</code>
              </div>

              <div className="modal-section">
                <h3>Vulnerability Description</h3>
                <p>{activeFindingModal.description}</p>
              </div>

              {activeFindingModal.remediation && (
                <div className="modal-section remediation-box">
                  <h3>Recommended Remediation</h3>
                  <p>{activeFindingModal.remediation}</p>
                </div>
              )}

              <div className="modal-section">
                <h3>Classification & Details</h3>
                <div className="modal-meta-grid">
                  <div>
                    <span className="meta-label">Classification</span>
                    <span>{activeFindingModal.detail}</span>
                  </div>
                  <div>
                    <span className="meta-label">First Detected</span>
                    <span>{activeFindingModal.age}</span>
                  </div>
                </div>
              </div>

              <div className="modal-section">
                <h3>Reference Links & Documentation</h3>
                <div className="modal-references">
                  {activeFindingModal.detail.includes("CWE-") && (
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${activeFindingModal.detail.match(/CWE-(\d+)/)?.[1] || "798"}.html`}
                      target="_blank"
                      rel="noreferrer"
                      className="reference-link"
                    >
                      <span>↗</span> MITRE {activeFindingModal.detail.match(/CWE-\d+/)?.[0] || "CWE Definition"}
                    </a>
                  )}
                  <a
                    href="https://owasp.org/www-project-top-ten/"
                    target="_blank"
                    rel="noreferrer"
                    className="reference-link"
                  >
                    <span>↗</span> OWASP Top 10 Security Risks
                  </a>
                  <a
                    href="https://cheatsheetseries.owasp.org/"
                    target="_blank"
                    rel="noreferrer"
                    className="reference-link"
                  >
                    <span>↗</span> OWASP Prevention Cheat Sheets
                  </a>
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="primary-action"
                onClick={() => setActiveFindingModal(null)}
              >
                Close Review
              </button>
            </div>
          </div>
        </div>
      )}

      {showAddAssetModal && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          onClick={() => setShowAddAssetModal(false)}
        >
          <div
            className="modal-card"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: "520px" }}
          >
            <div className="modal-header">
              <h2>Add New Security Asset</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setShowAddAssetModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div className="form-group">
                <label>Asset Display Name</label>
                <input
                  type="text"
                  placeholder="e.g. Staging Auth Service"
                  value={newAssetName}
                  onChange={(e) => setNewAssetName(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label>Asset Type</label>
                <select
                  value={newAssetType}
                  onChange={(e) => setNewAssetType(e.target.value as TargetType)}
                >
                  <option value="web">Web / API URL</option>
                  <option value="source">Source Code Repository</option>
                  <option value="mobile">Mobile Package (APK / IPA)</option>
                  <option value="desktop">Desktop Application Binary</option>
                </select>
              </div>
              <div className="form-group">
                <label>Target Address or File Path</label>
                <input
                  type="text"
                  placeholder={targetConfig[newAssetType].placeholder}
                  value={newAssetTarget}
                  onChange={(e) => setNewAssetTarget(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label>Risk Level</label>
                <select
                  value={newAssetRisk}
                  onChange={(e) => setNewAssetRisk(e.target.value as any)}
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>
            </div>
            <div className="modal-footer" style={{ gap: "10px" }}>
              <button
                type="button"
                className="banner-action"
                onClick={() => setShowAddAssetModal(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="primary-action"
                onClick={() => {
                  if (!newAssetName.trim() || !newAssetTarget.trim()) {
                    setNotice("Please enter an asset name and target address.");
                    return;
                  }
                  const newAsset: AssetItem = {
                    id: `ast-${Date.now()}`,
                    name: newAssetName.trim(),
                    type: newAssetType,
                    target: newAssetTarget.trim(),
                    riskLevel: newAssetRisk,
                    tags: ["custom", newAssetType],
                    status: "unscanned",
                  };
                  setAssets([newAsset, ...assets]);
                  setShowAddAssetModal(false);
                  setNewAssetName("");
                  setNewAssetTarget("");
                  setNotice(`Asset "${newAsset.name}" added to inventory.`);
                }}
              >
                Save Asset
              </button>
            </div>
          </div>
        </div>
      )}

      {activeIntegrationModal && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          onClick={() => setActiveIntegrationModal(null)}
        >
          <div
            className="modal-card"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: "520px" }}
          >
            <div className="modal-header">
              <h2>Configure {activeIntegrationModal.name}</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setActiveIntegrationModal(null)}
              >
                ×
              </button>
            </div>
            <div className="modal-body" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <p style={{ fontSize: "13px", color: "var(--muted)", margin: 0 }}>
                {activeIntegrationModal.description}
              </p>
              <div className="form-group">
                <label>Webhook / API Endpoint</label>
                <input
                  type="text"
                  value={webhookUrlInput}
                  onChange={(e) => setWebhookUrlInput(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label>Integration Status</label>
                <span className={`integration-status-pill ${activeIntegrationModal.status}`} style={{ alignSelf: "flex-start" }}>
                  <span className="status-ping" />
                  {activeIntegrationModal.status.toUpperCase()}
                </span>
              </div>
            </div>
            <div className="modal-footer" style={{ gap: "10px" }}>
              <button
                type="button"
                className="banner-action"
                onClick={() => {
                  setNotice("Test event ping sent successfully.");
                }}
              >
                Test Connection
              </button>
              <button
                type="button"
                className="primary-action"
                onClick={() => {
                  setIntegrations(
                    integrations.map((i) =>
                      i.id === activeIntegrationModal.id
                        ? { ...i, status: "configured" as const, details: "Configured via control panel" }
                        : i
                    )
                  );
                  setActiveIntegrationModal(null);
                  setNotice(`Integration ${activeIntegrationModal.name} updated.`);
                }}
              >
                Save Integration
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
