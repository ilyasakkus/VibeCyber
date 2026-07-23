"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

type TargetType = "web" | "source" | "mobile" | "desktop";
type Profile = "observe" | "safe";
type ScanStatus = "RUNNING" | "QUEUED" | "PAUSED";
type Severity = "Kritik" | "Yüksek" | "Orta" | "Düşük";

type ScanJob = {
  id: string;
  name: string;
  target: string;
  kind: TargetType;
  phase: string;
  progress: number;
  status: ScanStatus;
  pausedFrom?: Exclude<ScanStatus, "PAUSED">;
  pausedByKill?: boolean;
  started: string;
};

type Finding = {
  id: string;
  title: string;
  detail: string;
  target: string;
  severity: Severity;
  confidence: number;
  verified: "Doğrulandı" | "Korelasyonlu" | "İncelenmeli";
  age: string;
};

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
    hint: "Gerçek istemcide kapsam yalnız bu ana makine ve izin verilen alt yollarla sınırlanır.",
  },
  source: {
    label: "Depo veya proje yolu",
    placeholder: "/projeler/api",
    hint: "Yerel klasörler ajan üzerinden salt okunur bağlanır.",
  },
  mobile: {
    label: "Mobil paket yolu",
    placeholder: "/builds/app-release.apk veya uygulama.ipa",
    hint: "Gerçek istemcide APK ve IPA paketleri yerel, izole analiz alanında açılır.",
  },
  desktop: {
    label: "Uygulama veya binary yolu",
    placeholder: "/Applications/Uygulama.app veya uygulama.exe",
    hint: "EXE, DMG, AppImage, .app ve yerel uygulama klasörleri desteklenir.",
  },
};

const initialScans: ScanJob[] = [
  {
    id: "SCN-8421",
    name: "Staging API",
    target: "api.staging.acme.test",
    kind: "web",
    phase: "Tek salt-okunur yanıt gözlemi",
    progress: 68,
    status: "RUNNING",
    started: "12 dk",
  },
  {
    id: "SCN-8418",
    name: "Android 4.8.0",
    target: "acme-release.apk",
    kind: "mobile",
    phase: "Statik manifest analizi",
    progress: 41,
    status: "RUNNING",
    started: "19 dk",
  },
  {
    id: "SCN-8416",
    name: "Checkout Service",
    target: "services/checkout",
    kind: "source",
    phase: "Statik bağımlılık envanteri",
    progress: 87,
    status: "RUNNING",
    started: "26 dk",
  },
];

const findings: Finding[] = [
  {
    id: "WCB-2049",
    title: "Log4j bileşeni çalışan kod yolunda",
    detail: "CVE-2021-44228 · CWE-502",
    target: "checkout-service/pom.xml",
    severity: "Kritik",
    confidence: 99,
    verified: "Korelasyonlu",
    age: "6 dk önce",
  },
  {
    id: "WCB-2047",
    title: "Electron nodeIntegration etkin",
    detail: "CWE-749 · mainWindow.ts:42",
    target: "Acme Desktop 3.2",
    severity: "Yüksek",
    confidence: 100,
    verified: "Doğrulandı",
    age: "14 dk önce",
  },
  {
    id: "WCB-2044",
    title: "Yetkisiz dışa açık Android Activity",
    detail: "CWE-926 · AndroidManifest.xml",
    target: "acme-release.apk",
    severity: "Yüksek",
    confidence: 94,
    verified: "Doğrulandı",
    age: "18 dk önce",
  },
  {
    id: "WCB-2041",
    title: "Eski TLS 1.0 protokolü kabul ediliyor",
    detail: "CWE-326 · 443/tcp",
    target: "api.staging.acme.test",
    severity: "Orta",
    confidence: 98,
    verified: "Doğrulandı",
    age: "23 dk önce",
  },
  {
    id: "WCB-2038",
    title: "Oturum çerezinde SameSite niteliği eksik",
    detail: "CWE-1275 · /auth/callback",
    target: "portal.acme.test",
    severity: "Orta",
    confidence: 82,
    verified: "İncelenmeli",
    age: "31 dk önce",
  },
  {
    id: "WCB-2031",
    title: "Kullanılmayan test anahtarı kaynakta tutuluyor",
    detail: "CWE-798 · config/example.env:7",
    target: "web-client",
    severity: "Düşük",
    confidence: 76,
    verified: "İncelenmeli",
    age: "1 sa önce",
  },
];

const navItems = [
  { label: "Genel bakış", icon: "▦", badge: "", href: "#overview" },
  { label: "Taramalar", icon: "◎", badge: "3", href: "#scans" },
  { label: "Bulgular", icon: "◇", badge: "12", href: "#findings" },
  { label: "Varlıklar", icon: "⌘", badge: "", href: null },
  { label: "Politikalar", icon: "⊡", badge: "", href: null },
];

const secondaryNavItems = [
  { label: "Entegrasyonlar", icon: "∞" },
  { label: "Raporlar", icon: "≡" },
  { label: "Ayarlar", icon: "⚙" },
];

function shortTarget(value: string) {
  return value
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "")
    .split("/")
    .slice(-2)
    .join("/");
}

function targetKindLabel(kind: TargetType) {
  return targetOptions.find((item) => item.id === kind)?.label ?? "Hedef";
}

function validateTarget(type: TargetType, value: string) {
  const cleanTarget = value.trim();

  if (!cleanTarget) {
    return { valid: false, error: "Taranacak hedefi girin." };
  }

  if (type !== "web") {
    return { valid: true, error: "" };
  }

  try {
    const parsedTarget = new URL(cleanTarget);
    const hasAllowedProtocol =
      parsedTarget.protocol === "http:" || parsedTarget.protocol === "https:";

    if (!hasAllowedProtocol) {
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

function demoPhase(type: TargetType, profile: Profile) {
  if (type === "web") {
    return profile === "observe"
      ? "Pasif URL bilgisi önizlemesi"
      : "Tek salt-okunur yanıt gözlemi";
  }

  return profile === "observe"
    ? "Paket bilgisi önizlemesi"
    : "Statik metadata analizi";
}

export default function Home() {
  const [targetType, setTargetType] = useState<TargetType>("web");
  const [target, setTarget] = useState("");
  const [targetTouched, setTargetTouched] = useState(false);
  const [profile, setProfile] = useState<Profile>("safe");
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [agentConnected, setAgentConnected] = useState(false);
  const [activeNotice, setActiveNotice] = useState(false);
  const [notice, setNotice] = useState("");
  const [scans, setScans] = useState(initialScans);
  const [severityFilter, setSeverityFilter] = useState<"Tümü" | Severity>(
    "Tümü",
  );
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [allPaused, setAllPaused] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [isMobileViewport, setIsMobileViewport] = useState(false);
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const navCloseButtonRef = useRef<HTMLButtonElement>(null);

  const isLocalTarget = targetType !== "web";
  const targetValidation = useMemo(
    () => validateTarget(targetType, target),
    [target, targetType],
  );
  const showTargetError = targetTouched && !targetValidation.valid;
  const queuedScanIds = scans
    .filter((scan) => scan.status === "QUEUED")
    .map((scan) => scan.id)
    .join("|");
  const scanCanStart =
    targetValidation.valid &&
    scopeConfirmed &&
    !allPaused &&
    (!isLocalTarget || agentConnected);

  useEffect(() => {
    const progressTimer = window.setInterval(() => {
      setScans((current) =>
        current.map((scan) =>
          scan.status === "RUNNING" && scan.progress < 96
            ? { ...scan, progress: Math.min(96, scan.progress + 1) }
            : scan,
        ),
      );
    }, 5000);

    return () => window.clearInterval(progressTimer);
  }, []);

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
    if (allPaused || !queuedScanIds) return;

    const queueTimer = window.setTimeout(() => {
      setScans((current) =>
        current.map((scan) =>
          scan.status === "QUEUED"
            ? { ...scan, status: "RUNNING", progress: Math.max(scan.progress, 9) }
            : scan,
        ),
      );
    }, 1200);

    return () => window.clearTimeout(queueTimer);
  }, [allPaused, queuedScanIds]);

  const visibleFindings = useMemo(
    () =>
      findings.filter((finding) => {
        const severityMatches =
          severityFilter === "Tümü" || finding.severity === severityFilter;
        const verificationMatches =
          !verifiedOnly || finding.verified !== "İncelenmeli";
        return severityMatches && verificationMatches;
      }),
    [severityFilter, verifiedOnly],
  );

  function changeTargetType(nextType: TargetType) {
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

  function submitScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const cleanTarget = target.trim();

    if (allPaused) {
      setNotice("Demo kill switch açıkken yeni iş oluşturulamaz.");
      return;
    }

    if (!targetValidation.valid) {
      setTargetTouched(true);
      setNotice(targetValidation.error);
      return;
    }

    if (!scopeConfirmed) {
      setNotice("Tarama başlatmak için kapsam yetkisini doğrulayın.");
      return;
    }

    if (isLocalTarget && !agentConnected) {
      setNotice("Yerel hedef için masaüstü ajanını eşleştirin.");
      return;
    }

    const jobNumber = 8422 + scans.length;
    const nextJob: ScanJob = {
      id: `SCN-${jobNumber}`,
      name: targetKindLabel(targetType),
      target: shortTarget(cleanTarget),
      kind: targetType,
      phase: demoPhase(targetType, profile),
      progress: 4,
      status: "QUEUED",
      started: "şimdi",
    };

    setScans((current) => [nextJob, ...current]);
    setScopeConfirmed(false);
    setNotice(
      `${nextJob.id} örnek işi eklendi. Web demosu gerçek ağ isteği, crawl veya exploit çalıştırmaz.`,
    );
  }

  function toggleKillSwitch() {
    const nextPaused = !allPaused;
    setAllPaused(nextPaused);
    setScans((current) =>
      current.map((scan) => {
        if (nextPaused) {
          return scan.status === "PAUSED"
            ? scan
            : {
                ...scan,
                status: "PAUSED",
                pausedFrom: scan.status,
                pausedByKill: true,
              };
        }

        return scan.status === "PAUSED" && scan.pausedByKill
          ? {
              ...scan,
              status: scan.pausedFrom ?? "RUNNING",
              pausedFrom: undefined,
              pausedByKill: undefined,
            }
          : scan;
      }),
    );
    setNotice(
      nextPaused
        ? "Demo kill switch etkin: örnek ilerleme ve yeni iş oluşturma durduruldu."
        : "Örnek iş akışı kaldığı durumdan devam ediyor.",
    );
  }

  function toggleSingleScan(scanId: string) {
    setScans((current) =>
      current.map((scan) =>
        scan.id === scanId
          ? {
              ...scan,
              status:
                scan.status === "PAUSED"
                  ? scan.pausedFrom ?? "RUNNING"
                  : "PAUSED",
              pausedFrom:
                scan.status === "PAUSED" ? undefined : scan.status,
              pausedByKill: undefined,
            }
          : scan,
      ),
    );
  }

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
          <span className="workspace-avatar">AC</span>
          <span>
            <small>Çalışma alanı</small>
            <strong>Acme Security</strong>
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
            <span className={`status-dot ${agentConnected ? "online" : ""}`} />
            <strong>Masaüstü ajanı</strong>
          </div>
          <p>
            {agentConnected
              ? "Demo eşleşme gösterimi"
              : "Yerel dosya taramaları için gerekli"}
          </p>
          <button
            type="button"
            onClick={() => {
              setAgentConnected((connected) => !connected);
              setNotice(
                agentConnected
                  ? "Demo ajan durumu sıfırlandı."
                  : "Masaüstü ajanı bağlıymış gibi gösteren demo durumu etkinleştirildi.",
              );
            }}
          >
            {agentConnected ? "Demo durumunu sıfırla" : "Demo ajanı eşleştir"}
          </button>
        </div>

        <div className="sidebar-footer">
          <span className="user-avatar">WC</span>
          <span>
            <strong>Yerel kullanıcı</strong>
            <small>Proje yöneticisi</small>
          </span>
          <button
            type="button"
            aria-label="Hesap bilgisi"
            onClick={() => setNotice("Bu interaktif demoda hesap yönetimi bulunmuyor.")}
          >
            ···
          </button>
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
            <button
              className="command-search"
              type="button"
              onClick={() => setNotice("Hızlı arama yakında komut paletiyle açılacak.")}
            >
              <span aria-hidden="true">⌕</span>
              <span>Hedef, bulgu veya CVE ara</span>
              <kbd>⌘ K</kbd>
            </button>
            <button
              className="icon-button"
              type="button"
              aria-label="Bildirimler, iki okunmamış bildirim"
              onClick={() => setNotice("2 örnek bildirim: demo işi tamamlandı, politika taslağı güncellendi.")}
            >
              ○
              <span className="notification-pip" />
            </button>
            <div className="environment-chip">
              <span /> İnteraktif demo
            </div>
          </div>
        </header>

        <main id="main-content">
          <div className="demo-banner" role="note">
            <span className="demo-banner-label">DEMO</span>
            <p>
              <strong>İnteraktif arayüz önizlemesi</strong>
              <span>
                Skorlar, işler ve bulgular örnek veridir. Gerçek taramalar CLI veya
                masaüstü uygulamasında çalışır.
              </span>
            </p>
          </div>

          <div
            className={`safety-strip ${allPaused ? "safety-strip-paused" : ""}`}
            id="kill-switch-state"
          >
            <div>
              <span className="safety-icon" aria-hidden="true">
                {allPaused ? "‖" : "✓"}
              </span>
              <p>
                <strong>{allPaused ? "Taramalar duraklatıldı" : "Güvenlik sınırları etkin"}</strong>
                <span>
                  {allPaused
                    ? "Örnek ilerleme durdu; bu panel gerçek bir tarayıcıya bağlı değil."
                    : "Web demosu ağ isteği üretmez · Active profil kapalı · Crawl ve exploit yok"}
                </span>
              </p>
            </div>
            <button type="button" onClick={toggleKillSwitch}>
              <span aria-hidden="true">{allPaused ? "▶" : "■"}</span>
              {allPaused ? "Demoya devam et" : "Demo kill switch"}
            </button>
          </div>

          <section className="page-heading" id="overview">
            <div>
              <span className="eyebrow">22 TEMMUZ 2026 · SON 24 SAAT</span>
              <h1>Günaydın, ekip.</h1>
              <p>Örnek risk görünümü ve güvenli tarama iş akışı önizlemesi.</p>
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
                  <h2>Güvenlik puanı</h2>
                </div>
                <button
                  className="text-button"
                  type="button"
                  onClick={() => setNotice("Puan; açık bulgular, varlık kapsamı ve doğrulama güvenine göre hesaplanır.")}
                >
                  Nasıl hesaplanır?
                </button>
              </div>

              <div className="score-content">
                <div className="score-ring" aria-label="Güvenlik puanı 100 üzerinden 86">
                  <div>
                    <strong>86</strong>
                    <span>/100</span>
                  </div>
                </div>
                <div className="score-summary">
                  <div className="score-grade">
                    <span className="grade-pill">B+</span>
                    <p>
                      <strong>Kontrol altında</strong>
                      <span>Geçen haftaya göre <b>↑ 4 puan</b></span>
                    </p>
                  </div>
                  <p className="score-note">
                    Kritik risk tek bir kaynağa bağlı. Erişilebilir Log4j bulgusunu önceliklendirin.
                  </p>
                  <div className="score-bar" aria-hidden="true">
                    <span />
                  </div>
                  <div className="score-meta">
                    <span>12 açık bulgu</span>
                    <span>38 varlık izlendi</span>
                  </div>
                </div>
              </div>
            </article>

            <div className="metric-grid">
              <article className="metric-card panel">
                <div className="metric-icon critical" aria-hidden="true">
                  !
                </div>
                <div>
                  <span>Kritik bulgu</span>
                  <strong>1</strong>
                  <small><b>−2</b> geçen haftaya göre</small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon high" aria-hidden="true">
                  ↑
                </div>
                <div>
                  <span>Yüksek risk</span>
                  <strong>3</strong>
                  <small>1 yeni bulgu</small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon verified" aria-hidden="true">
                  ✓
                </div>
                <div>
                  <span>Doğrulanan</span>
                  <strong>7</strong>
                  <small>%91 ort. güven</small>
                </div>
              </article>
              <article className="metric-card panel">
                <div className="metric-icon coverage" aria-hidden="true">
                  ◎
                </div>
                <div>
                  <span>Kapsam</span>
                  <strong>%94</strong>
                  <small>38 / 40 varlık</small>
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
                  <p>Hedef türünü seçin; bu ekran yalnızca güvenli bir örnek iş oluşturur.</p>
                </div>
                <span className="safe-badge">
                  <span /> Crawl / exploit yok
                </span>
              </div>

              <form onSubmit={submitScan} noValidate>
                <div className="target-tabs" role="group" aria-label="Hedef türü">
                  {targetOptions.map((option) => (
                    <button
                      type="button"
                      aria-pressed={targetType === option.id}
                      className={targetType === option.id ? "selected" : ""}
                      key={option.id}
                      onClick={() => changeTargetType(option.id)}
                    >
                      <span className="target-icon" aria-hidden="true">
                        {option.icon}
                      </span>
                      <span>
                        <strong>{option.label}</strong>
                        <small>{option.eyebrow}</small>
                      </span>
                    </button>
                  ))}
                </div>

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
                  <div className={`agent-requirement ${agentConnected ? "connected" : ""}`}>
                    <span className="agent-requirement-icon" aria-hidden="true">
                      {agentConnected ? "✓" : "⌁"}
                    </span>
                    <div>
                      <strong>
                        {agentConnected
                          ? "Masaüstü ajanı hazır"
                          : "Masaüstü ajanı gerekli"}
                      </strong>
                      <p>
                        {agentConnected
                          ? "Arayüz önizlemesi için bağlantı simüle edildi; dosya aktarılmaz."
                          : "Tarayıcı yerel dosyalara erişemez. Gerçek analiz masaüstü uygulamasında başlatılır."}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setAgentConnected(true);
                        setNotice("Demo ajan durumu etkinleştirildi; hiçbir yerel dosya okunmadı.");
                      }}
                    >
                      {agentConnected ? "Demo ajan hazır" : "Demo ajanı eşleştir"}
                    </button>
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
                        <small>Tek salt-okunur gözlem / statik analiz</small>
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
                      <span className="profile-lock" aria-hidden="true">
                        ⌑
                      </span>
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
                    Active profil, yazılı hedef yetkisi ve ikinci bir proje yöneticisinin onay anahtarı olmadan açılamaz.
                  </p>
                </fieldset>

                <div className="scope-row">
                  <label className="scope-check">
                    <input
                      type="checkbox"
                      checked={scopeConfirmed}
                      onChange={(event) => setScopeConfirmed(event.target.checked)}
                    />
                    <span aria-hidden="true" />
                    <span>
                      <strong>Bu hedefi test etmeye yetkim var</strong>
                      <small>Onay hedef değişince sıfırlanır. Web demosu gerçek tarama başlatmaz.</small>
                    </span>
                  </label>
                  <button
                    type="submit"
                    className="start-scan-button"
                    disabled={!scanCanStart}
                    aria-describedby={allPaused ? "kill-switch-state" : undefined}
                  >
                    <span aria-hidden="true">▷</span>
                    Güvenli örnek işi oluştur
                  </button>
                </div>
              </form>
            </article>

            <article className="running-card panel" id="scans">
              <div className="card-heading">
                <div>
                  <span className="section-kicker">ÖRNEK İŞ KUYRUĞU</span>
                  <h2>Demo tarama işleri</h2>
                </div>
                <span className="live-indicator">
                  <span /> Demo · {scans.filter((scan) => scan.status === "RUNNING").length} ilerliyor
                </span>
              </div>

              <div className="scan-list">
                {scans.slice(0, 4).map((scan) => (
                  <div className="scan-item" key={scan.id}>
                    <div className="scan-item-top">
                      <div className={`scan-kind ${scan.kind}`} aria-hidden="true">
                        {targetOptions.find((option) => option.id === scan.kind)?.icon}
                      </div>
                      <div className="scan-name">
                        <strong>{scan.name}</strong>
                        <span>{scan.target}</span>
                      </div>
                      <button
                        type="button"
                        aria-label={`${scan.name} örnek işini ${scan.status === "PAUSED" ? "sürdür" : "duraklat"}`}
                        onClick={() => toggleSingleScan(scan.id)}
                        disabled={allPaused}
                      >
                        {scan.status === "PAUSED" ? "▶" : "‖"}
                      </button>
                    </div>
                    <div className="scan-progress-meta">
                      <span>
                        {scan.status === "PAUSED"
                          ? "Duraklatıldı"
                          : scan.status === "QUEUED"
                            ? "Kuyrukta"
                            : scan.phase}
                      </span>
                      <strong>%{scan.progress}</strong>
                    </div>
                    <div
                      className={`progress-track ${scan.status === "PAUSED" ? "paused" : ""}`}
                      role="progressbar"
                      aria-label={`${scan.name} ilerlemesi`}
                      aria-valuenow={scan.progress}
                      aria-valuemin={0}
                      aria-valuemax={100}
                    >
                      <span style={{ width: `${scan.progress}%` }} />
                    </div>
                    <div className="scan-foot">
                      <span>{scan.id}</span>
                      <span>{scan.started} önce başladı</span>
                    </div>
                  </div>
                ))}
              </div>

              <button
                type="button"
                className="view-all-button"
                onClick={() => setNotice(`Demo listesinde toplam ${scans.length} örnek iş var.`)}
              >
                Tüm örnek işleri gör <span aria-hidden="true">→</span>
              </button>
            </article>
          </section>

          <section className="findings-card panel" id="findings">
            <div className="findings-header">
              <div>
                <span className="section-kicker">RİSK GÖRÜNÜMÜ</span>
                <h2>Örnek bulgular</h2>
                <p>Güven seviyesi, teknik şiddet ve doğrulama durumu ayrı değerlendirilir.</p>
              </div>
              <button
                type="button"
                className="export-button"
                onClick={() => setNotice("Demo raporu hazır: gerçek sürüm SARIF, JSON ve PDF sunacak.")}
              >
                <span aria-hidden="true">⇩</span> Raporu dışa aktar
              </button>
            </div>

            <div className="findings-toolbar">
              <div className="filter-tabs" aria-label="Şiddete göre filtrele">
                {(["Tümü", "Kritik", "Yüksek", "Orta", "Düşük"] as const).map(
                  (filter) => (
                    <button
                      type="button"
                      className={severityFilter === filter ? "active" : ""}
                      aria-pressed={severityFilter === filter}
                      key={filter}
                      onClick={() => setSeverityFilter(filter)}
                    >
                      {filter}
                      {filter === "Tümü" && <span>{findings.length}</span>}
                    </button>
                  ),
                )}
              </div>
              <label className="verified-toggle">
                <input
                  type="checkbox"
                  checked={verifiedOnly}
                  onChange={(event) => setVerifiedOnly(event.target.checked)}
                />
                <span aria-hidden="true" />
                Yalnız doğrulananlar
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
                    <th scope="col">Doğrulama</th>
                    <th scope="col">Bulundu</th>
                    <th scope="col"><span className="sr-only">Eylem</span></th>
                  </tr>
                </thead>
                <tbody>
                  {visibleFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <div className="finding-title">
                          <span className={`severity-marker ${finding.severity.toLocaleLowerCase("tr-TR")}`} />
                          <div>
                            <strong>{finding.title}</strong>
                            <small>
                              {finding.id} · {finding.detail}
                            </small>
                          </div>
                        </div>
                      </td>
                      <td><span className="target-cell">{finding.target}</span></td>
                      <td>
                        <span className={`severity-pill ${finding.severity.toLocaleLowerCase("tr-TR")}`}>
                          {finding.severity}
                        </span>
                      </td>
                      <td>
                        <div className="confidence-cell">
                          <span>
                            <i style={{ width: `${finding.confidence}%` }} />
                          </span>
                          <strong>%{finding.confidence}</strong>
                        </div>
                      </td>
                      <td>
                        <span className={`verification-pill ${finding.verified === "İncelenmeli" ? "review" : "confirmed"}`}>
                          <span aria-hidden="true">{finding.verified === "İncelenmeli" ? "?" : "✓"}</span>
                          {finding.verified}
                        </span>
                      </td>
                      <td><span className="age-cell">{finding.age}</span></td>
                      <td>
                        <button
                          type="button"
                          className="row-action"
                          aria-label={`${finding.id} bulgusunu aç`}
                          onClick={() => setNotice(`${finding.id} ayrıntı paneli demo sürümünde salt okunur.`)}
                        >
                          →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {visibleFindings.length === 0 && (
                <div className="empty-state">Bu filtrelerle eşleşen bulgu yok.</div>
              )}
            </div>

            <div className="findings-footer">
              <p><span aria-hidden="true">◉</span> Son korelasyon: 2 dk önce</p>
              <button
                type="button"
                onClick={() => {
                  setSeverityFilter("Tümü");
                  setVerifiedOnly(false);
                  setNotice("Tüm bulgular gösteriliyor.");
                }}
              >
                Tüm {findings.length} bulguyu göster <span aria-hidden="true">→</span>
              </button>
            </div>
          </section>

          <footer className="product-footer">
            <span>WebCyber Community Edition · v0.1.0-alpha</span>
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
