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
type Severity = "Kritik" | "Yüksek" | "Orta" | "Düşük" | "Bilgi";
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
  { id: "source", label: "Kaynak kod", eyebrow: "SAST + SCA", icon: "〈〉" },
  { id: "mobile", label: "Mobil uygulama", eyebrow: "APK / IPA", icon: "▣" },
  { id: "desktop", label: "Masaüstü", eyebrow: "Binary / App", icon: "◈" },
];

const targetConfig: Record<
  TargetType,
  { label: string; placeholder: string; hint: string }
> = {
  web: {
    label: "Hedef adresi",
    placeholder: "https://uygulama.ornek.com",
    hint: "Kapsam bu URL ile sınırlanır; yönlendirmeler ve özel ağ hedefleri güvenli biçimde doğrulanır.",
  },
  source: {
    label: "Depo veya proje yolu",
    placeholder: "/projeler/api",
    hint: "Yol, Go kontrol hizmetinin çalıştığı makinede salt okunur analiz edilir.",
  },
  mobile: {
    label: "Mobil paket yolu",
    placeholder: "/builds/app-release.apk veya uygulama.ipa",
    hint: "APK ve IPA paketleri yerel, sınırlı analiz akışında incelenir.",
  },
  desktop: {
    label: "Uygulama veya binary yolu",
    placeholder: "/Applications/Uygulama.app veya uygulama.exe",
    hint: "Uygulama ya da binary yolu Go tarama motorunun yerel erişim alanında olmalıdır.",
  },
};

const terminalStatuses = new Set<JobStatus>([
  "completed",
  "partial",
  "failed",
  "cancelled",
]);

const severityLabels: Record<ReportFinding["severity"], Severity> = {
  critical: "Kritik",
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
  info: "Bilgi",
};

const statusLabels: Record<JobStatus, string> = {
  queued: "Kuyrukta",
  running: "Taranıyor",
  cancelling: "İptal tamamlanıyor",
  completed: "Tamamlandı",
  partial: "Kısmi tamamlandı",
  failed: "Başarısız",
  cancelled: "İptal edildi",
};

const secondaryNavItems = [
  { label: "Entegrasyonlar", icon: "∞" },
  { label: "Raporlar", icon: "≡" },
  { label: "Ayarlar", icon: "⚙" },
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
    return payload.message || `İstek başarısız (${response.status}).`;
  } catch {
    return `İstek başarısız (${response.status}).`;
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
  return targetOptions.find((item) => item.id === kind)?.label ?? "Hedef";
}

function validateTarget(type: TargetType, value: string) {
  const cleanTarget = value.trim();
  if (!cleanTarget) return { valid: false, error: "Taranacak hedefi girin." };
  if (type !== "web") return { valid: true, error: "" };

  try {
    const parsedTarget = new URL(cleanTarget);
    if (parsedTarget.protocol !== "http:" && parsedTarget.protocol !== "https:") {
      return { valid: false, error: "Web hedefi http:// veya https:// ile başlamalı." };
    }
    if (!parsedTarget.hostname) {
      return { valid: false, error: "Web hedefinde geçerli bir ana makine adı olmalı." };
    }
    if (parsedTarget.username || parsedTarget.password) {
      return {
        valid: false,
        error: "URL içinde kullanıcı adı veya parola bilgisi kullanılamaz.",
      };
    }
    return { valid: true, error: "" };
  } catch {
    return {
      valid: false,
      error: "Geçerli bir web adresi girin (örn. https://uygulama.example).",
    };
  }
}

function relativeTime(value?: string) {
  if (!value) return "—";
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) return "az önce";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} dk önce`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} sa önce`;
  return `${Math.floor(hours / 24)} gün önce`;
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
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
  unspecified: "Belirtilmedi",
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
        detail: classifiers || "Sınıflandırma bilgisi yok",
        description: finding.description,
        remediation: finding.remediation,
        target: location,
        severity: severityLabels[finding.severity] ?? "Bilgi",
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
  const [severityFilter, setSeverityFilter] = useState<"Tümü" | Severity>(
    "Tümü",
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
          severityFilter === "Tümü" || finding.severity === severityFilter;
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
          : "Kontrol hizmetine ulaşılamıyor.",
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
      setNotice("Bu hedef türü kontrol hizmetinin yeteneklerinde etkin değil.");
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
      setNotice("Tarama başlatmak için kapsam yetkisini doğrulayın.");
      return;
    }
    if (!targetCapabilityEnabled(targetType)) {
      setNotice("Bu hedef türü kontrol hizmetinin yeteneklerinde etkin değil.");
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
      if (!job) throw new Error("Kontrol hizmeti geçerli bir tarama işi döndürmedi.");
      updateJob(job);
      setScopeConfirmed(false);
      setNotice(`${job.id} taraması kuyruğa alındı.`);
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : "Tarama başlatılamadı.",
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
        `${cancellableScans.length} kuyrukta veya çalışan iş için iptal sinyali gönderildi.`,
      );
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : "İşler iptal edilemedi.",
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
      setNotice(`${scan.id} işi için iptal sinyali gönderildi.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "İş iptal edilemedi.");
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
      setNotice("Dışa aktarılabilecek yüklenmiş rapor yok.");
      return;
    }
    const blob = new Blob([JSON.stringify(reports, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `webcyber-reports-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    setNotice(`${reports.length} yüklenmiş JSON raporu indirildi.`);
  }

  const navItems = [
    { label: "Genel bakış", icon: "▦", badge: "", href: "#overview" },
    {
      label: "Taramalar",
      icon: "◎",
      badge: scans.length ? String(scans.length) : "",
      href: "#scans",
    },
    {
      label: "Bulgular",
      icon: "◇",
      badge: aggregateSummary.total ? String(aggregateSummary.total) : "",
      href: "#findings",
    },
    { label: "Varlıklar", icon: "⌘", badge: "", href: null },
    { label: "Politikalar", icon: "⊡", badge: "", href: null },
  ];
  const displayedScans = showAllScans ? scans : scans.slice(0, 4);
  const scoreStyle = {
    "--score": `${technicalRiskIndex ?? 0}%`,
  } as CSSProperties;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Ana içeriğe geç
      </a>

      <aside
        className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}
        id="mobile-navigation"
        aria-hidden={isMobileViewport && !mobileNavOpen ? true : undefined}
        inert={isMobileViewport && !mobileNavOpen}
      >
        <div className="brand-row">
          <div className="brand-mark" aria-hidden="true">
            W<span>C</span>
          </div>
          <div className="brand-copy">
            <strong>WebCyber</strong>
            <span>Security Operations</span>
          </div>
          <button
            className="nav-close"
            type="button"
            aria-label="Menüyü kapat"
            ref={navCloseButtonRef}
            onClick={() => closeMobileNav()}
          >
            ×
          </button>
        </div>

        <div className="workspace-switcher">
          <span className="workspace-avatar">WC</span>
          <span>
            <small>Çalışma alanı</small>
            <strong>Yerel kontrol düzlemi</strong>
          </span>
          <span className="workspace-chevron" aria-hidden="true">
            ⌄
          </span>
        </div>

        <nav className="primary-nav" aria-label="Ana menü">
          <span className="nav-heading">OPERASYON</span>
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
                <span className="nav-soon">Yakında</span>
              </button>
            ),
          )}

          <span className="nav-heading secondary-heading">YÖNETİM</span>
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
              <span className="nav-soon">Yakında</span>
            </button>
          ))}
        </nav>

        <div className="agent-mini-card">
          <div className="agent-mini-head">
            <span className={`status-dot ${apiState === "online" ? "online" : ""}`} />
            <strong>Go tarama motoru</strong>
          </div>
          <p>
            {apiState === "online"
              ? `v${health?.version || "—"} · ${localPathsEnabled ? "Yerel yollar açık" : "Yalnız web hedefleri"}`
              : apiState === "loading"
                ? "Bağlantı kontrol ediliyor"
                : "Kontrol hizmeti çevrimdışı"}
          </p>
          <button
            type="button"
            onClick={() => void connectControlPlane()}
            disabled={apiState === "loading"}
          >
            {apiState === "loading" ? "Kontrol ediliyor…" : "Bağlantıyı yenile"}
          </button>
        </div>

        <div className="sidebar-footer">
          <span className="user-avatar">WC</span>
          <span>
            <strong>Community Edition</strong>
            <small>Yerel ve açık kaynak</small>
          </span>
        </div>
      </aside>

      {mobileNavOpen && (
        <button
          className="nav-backdrop"
          type="button"
          aria-label="Menüyü kapat"
          onClick={() => closeMobileNav()}
        />
      )}

      <div className="main-column">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu-button"
              type="button"
              aria-label="Menüyü aç"
              aria-expanded={mobileNavOpen}
              aria-controls="mobile-navigation"
              ref={mobileMenuButtonRef}
              onClick={() => setMobileNavOpen(true)}
            >
              ☰
            </button>
            <div className="breadcrumb">
              <span>Operasyon merkezi</span>
              <b>/</b>
              <strong>Genel bakış</strong>
            </div>
          </div>
          <div className="topbar-actions">
            <div
              className={`environment-chip ${apiState === "offline" ? "offline" : ""}`}
              role="status"
            >
              <span />{" "}
              {apiState === "online"
                ? "Go motoru bağlı"
                : apiState === "loading"
                  ? "Bağlanıyor"
                  : "Motor çevrimdışı"}
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
                ? "CANLI"
                : apiState === "loading"
                  ? "BAĞLAN"
                  : "OFFLINE"}
            </span>
            <p>
              <strong>
                {apiState === "online"
                  ? "Gerçek Go kontrol düzlemi bağlı"
                  : apiState === "loading"
                    ? "Kontrol hizmetine bağlanılıyor"
                    : "Tarama motoruna ulaşılamıyor"}
              </strong>
              <span>
                {apiState === "online"
                  ? `${health?.capabilities.maxConcurrency ?? 0} eşzamanlı iş · sonuçlar gerçek tarama raporlarından üretiliyor.`
                  : apiState === "loading"
                    ? "Sağlık ve yetenek bilgileri okunuyor."
                    : `${apiError || "Go kontrol hizmetini başlatıp bağlantıyı yenileyin."} Sahte veri gösterilmiyor.`}
              </span>
            </p>
            {apiState === "offline" && (
              <button
                className="banner-action"
                type="button"
                onClick={() => void connectControlPlane()}
              >
                Yeniden dene
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
                    ? "İptal sinyali gönderiliyor"
                    : cancellingScanCount > 0
                      ? `${cancellingScanCount} iş iptali tamamlıyor`
                      : "Güvenlik sınırları etkin"}
                </strong>
                <span>
                  Observe ve Safe profilleri · Yetki onayı zorunlu · {activeScans.length} etkin iş
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
                ? "İptal ediliyor…"
                : cancellingScanCount > 0 && cancellableScans.length === 0
                  ? "İptal tamamlanıyor…"
                  : "Tüm etkin işleri iptal et"}
            </button>
          </div>

          <section className="page-heading" id="overview">
            <div>
              <span className="eyebrow">CANLI KONTROL DÜZLEMİ</span>
              <h1>Güvenlik operasyon merkezi</h1>
              <p>Web, kaynak kod, mobil ve masaüstü hedeflerini tek kuyruktan yönetin.</p>
            </div>
            <a className="primary-action" href="#new-scan">
              <span aria-hidden="true">+</span> Yeni tarama
            </a>
          </section>

          <section className="overview-grid" aria-label="Güvenlik özeti">
            <article className="score-card panel">
              <div className="card-heading">
                <div>
                  <span className="section-kicker">GENEL DURUM</span>
                  <h2>Son raporların teknik risk endeksi</h2>
                </div>
                <button
                  className="text-button"
                  type="button"
                  onClick={() =>
                    setNotice(
                      "Endeks, her hedefin en yeni tamamlanmış veya kısmi raporundaki şiddet ağırlıklarından türetilir. 0 daha düşük, 100 daha yüksek gözlenen teknik risk yükünü gösterir; güvenlik garantisi değildir.",
                    )
                  }
                >
                  Nasıl hesaplanır?
                </button>
              </div>

              <div className="score-content">
                <div
                  className={`score-ring risk-index ${technicalRiskIndex === null ? "score-empty" : ""}`}
                  style={scoreStyle}
                  aria-label={
                    technicalRiskIndex === null
                      ? "Henüz teknik risk endeksi hesaplanmadı"
                      : `Teknik risk endeksi 100 üzerinden ${technicalRiskIndex}`
                  }
                >
                  <div>
                    <strong>{technicalRiskIndex ?? "—"}</strong>
                    <span>/100</span>
                  </div>
                </div>
                <div className="score-summary">
                  <div className="score-grade">
                    <span className="grade-pill risk">RİSK</span>
                    <p>
                      <strong>
                        {technicalRiskIndex === null
                          ? "Rapor bekleniyor"
                          : "Şiddet ağırlıklı teknik gösterge"}
                      </strong>
                      <span>
                        {assessmentScans.length} hedefin en yeni raporu işlendi
                      </span>
                    </p>
                  </div>
                  <p className="score-note">
                    {technicalRiskIndex === null
                      ? "İlk tamamlanmış veya kısmi rapor geldiğinde endeks hesaplanır."
                      : `${aggregateSummary.critical} kritik, ${aggregateSummary.high} yüksek şiddetli bulgu. Bu endeks güvenlik garantisi değildir.`}
                  </p>
                  <div className="score-bar" aria-hidden="true">
                    <span
                      className="risk"
                      style={{ width: `${technicalRiskIndex ?? 0}%` }}
                    />
                  </div>
                  <div className="score-meta">
                    <span>{aggregateSummary.total} son rapor bulgusu</span>
                    <span>{assessmentScans.length} benzersiz hedef</span>
                  </div>
                </div>
              </div>
            </article>

            <div className="metric-grid">
              <article className="metric-card panel">
                <div className="metric-icon critical" aria-hidden="true">!</div>
                <div>
                  <span>Kritik bulgu</span>
                  <strong>{aggregateSummary.critical}</strong>
                  <small>En yeni hedef raporları</small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon high" aria-hidden="true">↑</div>
                <div>
                  <span>Yüksek risk</span>
                  <strong>{aggregateSummary.high}</strong>
                  <small>En yeni hedef raporları</small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon verified" aria-hidden="true">✓</div>
                <div>
                  <span>Değerlendirilen hedef</span>
                  <strong>{assessmentScans.length}</strong>
                  <small>
                    {completedReportCount} tamamlandı · {partialReportCount} kısmi
                  </small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon coverage" aria-hidden="true">◎</div>
                <div>
                  <span>Rapor kapsamı</span>
                  <strong>{reportCoverage === null ? "—" : `%${reportCoverage}`}</strong>
                  <small>
                    {assessmentScans.length} / {assessmentCandidates.length} seçili hedef
                    raporu yüklendi
                  </small>
                </div>
              </article>
            </div>
          </section>

          <section className="operations-grid">
            <article className="new-scan-card panel" id="new-scan">
              <div className="card-heading scan-heading">
                <div>
                  <span className="section-kicker">ORKESTRATÖR</span>
                  <h2>Yeni tarama oluştur</h2>
                  <p>Hedef, profil ve açık yetki beyanıyla gerçek bir tarama işi başlatın.</p>
                </div>
                <span className="safe-badge">
                  <span /> Observe / Safe
                </span>
              </div>

              <form onSubmit={submitScan} noValidate>
                <div className="target-tabs" role="group" aria-label="Hedef türü">
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
                          <small>{disabled ? "Yerel erişim kapalı" : option.eyebrow}</small>
                        </span>
                      </button>
                    );
                  })}
                </div>
                <p className="sr-only" id="local-capability-help">
                  Bu hedef türü için Go kontrol hizmetinde yerel yol erişimi etkin olmalıdır.
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
                        ? "Geçersiz"
                        : targetValidation.valid
                          ? "Biçim geçerli"
                          : "Hedef bekleniyor"}
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
                      <strong>Yerel yol taraması etkin</strong>
                      <p>
                        Hedef, Go kontrol hizmetinin çalıştığı makinede ve süreç izinleriyle okunur.
                      </p>
                    </div>
                  </div>
                )}

                <fieldset className="profile-fieldset">
                  <legend>Tarama profili</legend>
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
                        <small>Pasif keşif</small>
                      </span>
                      <em>Salt okunur</em>
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
                        <small>Güvenli gözlem / statik analiz</small>
                      </span>
                      <em>Önerilen</em>
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
                        <small>Doğrulama testleri</small>
                      </span>
                      <em>Kilitli</em>
                    </button>
                  </div>
                  <p
                    className={`active-profile-help ${activeNotice ? "visible" : ""}`}
                    id="active-profile-help"
                  >
                    <span aria-hidden="true">!</span>
                    Active profil bu sürümde sunulmuyor. Yalnız Observe ve Safe işleri kabul edilir.
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
                      <strong>Bu hedefi test etmeye yetkim var</strong>
                      <small>Bu beyan hedef her değiştiğinde sıfırlanır ve API isteğine eklenir.</small>
                    </span>
                  </label>
                  <button
                    type="submit"
                    className="start-scan-button"
                    disabled={!scanCanStart}
                  >
                    <span aria-hidden="true">▷</span>
                    {isSubmitting ? "Kuyruğa alınıyor…" : "Taramayı başlat"}
                  </button>
                </div>
              </form>
            </article>

            <article className="running-card panel" id="scans">
              <div className="card-heading">
                <div>
                  <span className="section-kicker">GERÇEK İŞ KUYRUĞU</span>
                  <h2>Tarama işleri</h2>
                </div>
                <span className="live-indicator">
                  <span /> {activeScans.length} etkin
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
                              ? `${scan.id} işini iptal et`
                              : `${scan.id}: ${statusLabels[scan.status]}`
                          }
                          title={
                            canCancel
                              ? "İşi iptal et"
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
                      ? "Henüz tarama işi yok. İlk hedefi yukarıdan kuyruğa alın."
                      : "Kontrol hizmeti bağlı olmadığından iş kuyruğu gösterilemiyor."}
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
                  {showAllScans ? "Son dört işi göster" : `Tüm ${scans.length} işi göster`}
                  <span aria-hidden="true">{showAllScans ? "↑" : "↓"}</span>
                </button>
              )}
            </article>
          </section>

          <section className="findings-card panel" id="findings">
            <div className="findings-header">
              <div>
                <span className="section-kicker">RİSK GÖRÜNÜMÜ</span>
                <h2>Rapor bulguları</h2>
                <p>
                  Her hedefin en yeni tamamlanmış veya kısmi Go raporu kullanılır.
                </p>
              </div>
              <button
                type="button"
                className="export-button"
                onClick={exportReports}
                disabled={exportableReportCount === 0}
              >
                <span aria-hidden="true">⇩</span> Yüklenmiş JSON raporlarını indir
              </button>
            </div>

            <div className="report-scope-note" role="note">
              <span aria-hidden="true">!</span>
              <p>
                <strong>Rapor ve görünüm sınırları</strong>
                <span>
                  En fazla {REPORT_HYDRATION_LIMIT} benzersiz hedefin en güncel
                  tamamlanmış veya kısmi raporu yüklenir; bulgu görünümü hedef +
                  fingerprint ile tekilleştirilerek en fazla{" "}
                  {FINDING_CACHE_LIMIT} satır tutar ve {FINDING_PAGE_SIZE} satırlık
                  sayfalar gösterir.
                  {partialReportCount > 0 &&
                    ` ${partialReportCount} kısmi rapor eksik kapsam içerebilir; rapor sınırlamalarını inceleyin.`}
                  {missingAssessmentReportCount > 0 &&
                    ` Seçili ${missingAssessmentReportCount} raporun ayrıntısı yüklenemedi; endeks ve bulgulara dahil edilmedi.`}
                  {omittedAssessmentTargetCount > 0 &&
                    ` Daha eski ${omittedAssessmentTargetCount} benzersiz hedef raporu kaynak sınırı nedeniyle bu görünüme alınmadı.`}
                  {findingsTruncated &&
                    " Toplamlarla görüntülenen satırlar tekilleştirme veya satır sınırı nedeniyle farklı olabilir."}
                </span>
              </p>
            </div>

            <div className="findings-toolbar">
              <div className="filter-tabs" aria-label="Şiddete göre filtrele">
                {(["Tümü", "Kritik", "Yüksek", "Orta", "Düşük", "Bilgi"] as const).map(
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
                      {filter === "Tümü" && (
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
                Yalnız yüksek güven
              </label>
            </div>

            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Bulgu</th>
                    <th scope="col">Hedef</th>
                    <th scope="col">Şiddet</th>
                    <th scope="col">Güven</th>
                    <th scope="col">Bulundu</th>
                    <th scope="col">İnceleme</th>
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
                          aria-label={`${finding.id} bulgusunun özetini göster`}
                          onClick={() =>
                            setNotice(
                              `${finding.description}${finding.remediation ? ` Çözüm: ${finding.remediation}` : ""}`,
                            )
                          }
                        >
                          <span aria-hidden="true">!</span>
                          İnsan incelemesi gerekli
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
                      ? "Henüz raporlanmış bulgu yok. Tamamlanan taramaların sonuçları burada görünecek."
                      : "Kontrol hizmeti çevrimdışı; sahte bulgu gösterilmiyor."
                    : "Bu filtrelerle eşleşen bulgu yok."}
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
                  Sonraki{" "}
                  {Math.min(
                    FINDING_PAGE_SIZE,
                    filteredFindings.length - displayedFindings.length,
                  )}{" "}
                  bulguyu göster
                  <span aria-hidden="true">↓</span>
                </button>
              )}
            </div>

            <div className="findings-footer">
              <p>
                <span aria-hidden="true">◉</span>
                {assessmentScans.length} en yeni hedef raporu ·{" "}
                {aggregateSummary.total} toplam bulgu · {allFindings.length} satır
              </p>
              <button
                type="button"
                onClick={() => {
                  setSeverityFilter("Tümü");
                  setHighConfidenceOnly(false);
                  setVisibleFindingLimit(FINDING_PAGE_SIZE);
                }}
              >
                Filtreleri temizle <span aria-hidden="true">→</span>
              </button>
            </div>
          </section>

          <footer className="product-footer">
            <span>WebCyber Community Edition · v{health?.version || "0.1.0-alpha"}</span>
            <span>Açık kaynak · Apache-2.0 · Verileriniz sizde kalır</span>
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
        <button type="button" aria-label="Bildirimi kapat" onClick={() => setNotice("")}>
          ×
        </button>
      </div>
    </div>
  );
}
