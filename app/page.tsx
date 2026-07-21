"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

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
    hint: "Yalnız bu ana makine ve izin verilen alt yollar taranır.",
  },
  source: {
    label: "Depo veya proje yolu",
    placeholder: "/projeler/api veya git@github.com:ekip/api.git",
    hint: "Yerel klasörler ajan üzerinden salt okunur bağlanır.",
  },
  mobile: {
    label: "Mobil paket yolu",
    placeholder: "/builds/app-release.apk veya uygulama.ipa",
    hint: "APK ve IPA paketleri izole bir analiz alanında açılır.",
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
    phase: "Uç nokta haritalama",
    progress: 68,
    status: "RUNNING",
    started: "12 dk",
  },
  {
    id: "SCN-8418",
    name: "Android 4.8.0",
    target: "acme-release.apk",
    kind: "mobile",
    phase: "Manifest ve secret analizi",
    progress: 41,
    status: "RUNNING",
    started: "19 dk",
  },
  {
    id: "SCN-8416",
    name: "Checkout Service",
    target: "services/checkout",
    kind: "source",
    phase: "SCA erişilebilirlik kontrolü",
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
  { label: "Genel bakış", icon: "▦", badge: "" },
  { label: "Taramalar", icon: "◎", badge: "3" },
  { label: "Bulgular", icon: "◇", badge: "12" },
  { label: "Varlıklar", icon: "⌘", badge: "" },
  { label: "Politikalar", icon: "⊡", badge: "" },
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

export default function Home() {
  const [targetType, setTargetType] = useState<TargetType>("web");
  const [target, setTarget] = useState("https://staging.example.com");
  const [profile, setProfile] = useState<Profile>("safe");
  const [scopeConfirmed, setScopeConfirmed] = useState(true);
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

  const isLocalTarget = targetType !== "web";

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
    setActiveNotice(false);
  }

  function submitScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const cleanTarget = target.trim();

    if (!cleanTarget) {
      setNotice("Önce taranacak hedefi girin.");
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
      phase: profile === "observe" ? "Pasif envanter keşfi" : "Güvenli kontroller hazırlanıyor",
      progress: 4,
      status: "QUEUED",
      started: "şimdi",
    };

    setScans((current) => [nextJob, ...current]);
    setAllPaused(false);
    setNotice(
      `${nextJob.id} kuyruğa alındı. Bu demo işi exploit veya yıkıcı payload çalıştırmaz.`,
    );

    window.setTimeout(() => {
      setScans((current) =>
        current.map((scan) =>
          scan.id === nextJob.id
            ? {
                ...scan,
                status: "RUNNING",
                phase:
                  profile === "observe"
                    ? "Pasif sinyal toplama"
                    : "Başlık ve yapılandırma kontrolleri",
                progress: 9,
              }
            : scan,
        ),
      );
    }, 1200);
  }

  function toggleKillSwitch() {
    setAllPaused((paused) => {
      const nextPaused = !paused;
      setScans((current) =>
        current.map((scan) => ({
          ...scan,
          status: nextPaused
            ? "PAUSED"
            : scan.status === "QUEUED"
              ? "QUEUED"
              : "RUNNING",
        })),
      );
      setNotice(
        nextPaused
          ? "Kill switch etkin: yeni istekler durduruldu ve worker'lar duraklatıldı."
          : "Tarama kuyruğu kontrollü biçimde yeniden başlatıldı.",
      );
      return nextPaused;
    });
  }

  function toggleSingleScan(scanId: string) {
    setScans((current) =>
      current.map((scan) =>
        scan.id === scanId
          ? {
              ...scan,
              status: scan.status === "PAUSED" ? "RUNNING" : "PAUSED",
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

      <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}>
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
            onClick={() => setMobileNavOpen(false)}
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
          {navItems.map((item, index) => (
            <a
              className={`nav-item ${index === 0 ? "active" : ""}`}
              href={index === 0 ? "#overview" : index === 1 ? "#scans" : index === 2 ? "#findings" : "#"}
              key={item.label}
              onClick={() => setMobileNavOpen(false)}
            >
              <span className="nav-icon" aria-hidden="true">
                {item.icon}
              </span>
              <span>{item.label}</span>
              {item.badge && <span className="nav-badge">{item.badge}</span>}
            </a>
          ))}

          <span className="nav-heading secondary-heading">YÖNETİM</span>
          {secondaryNavItems.map((item) => (
            <a
              className="nav-item"
              href="#"
              key={item.label}
              onClick={() => setMobileNavOpen(false)}
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
            <span className={`status-dot ${agentConnected ? "online" : ""}`} />
            <strong>Masaüstü ajanı</strong>
          </div>
          <p>
            {agentConnected
              ? "WC-LOCAL-01 · Bağlı"
              : "Yerel dosya taramaları için gerekli"}
          </p>
          <button
            type="button"
            onClick={() => {
              setAgentConnected((connected) => !connected);
              setNotice(
                agentConnected
                  ? "Masaüstü ajanı bağlantısı kesildi."
                  : "Demo masaüstü ajanı salt okunur modda eşleştirildi.",
              );
            }}
          >
            {agentConnected ? "Bağlantıyı kes" : "Ajanı eşleştir"}
          </button>
        </div>

        <div className="sidebar-footer">
          <span className="user-avatar">IA</span>
          <span>
            <strong>İlyas Akkuş</strong>
            <small>Proje yöneticisi</small>
          </span>
          <button type="button" aria-label="Hesap menüsü">
            ···
          </button>
        </div>
      </aside>

      {mobileNavOpen && (
        <button
          className="nav-backdrop"
          type="button"
          aria-label="Menüyü kapat"
          onClick={() => setMobileNavOpen(false)}
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
              onClick={() => setNotice("2 bildirim: 1 tarama tamamlandı, 1 politika güncellendi.")}
            >
              ○
              <span className="notification-pip" />
            </button>
            <div className="environment-chip">
              <span /> Canlı sistem
            </div>
          </div>
        </header>

        <main id="main-content">
          <div className={`safety-strip ${allPaused ? "safety-strip-paused" : ""}`}>
            <div>
              <span className="safety-icon" aria-hidden="true">
                {allPaused ? "‖" : "✓"}
              </span>
              <p>
                <strong>{allPaused ? "Taramalar duraklatıldı" : "Güvenlik sınırları etkin"}</strong>
                <span>
                  {allPaused
                    ? "Yeni istek üretilmiyor. Worker durumları korunuyor."
                    : "Kapsam dışı istekler engellenir · Active profil kapalı · Worker'lar izole"}
                </span>
              </p>
            </div>
            <button type="button" onClick={toggleKillSwitch}>
              <span aria-hidden="true">{allPaused ? "▶" : "■"}</span>
              {allPaused ? "Kontrollü devam et" : "Kill switch"}
            </button>
          </div>

          <section className="page-heading" id="overview">
            <div>
              <span className="eyebrow">22 TEMMUZ 2026 · SON 24 SAAT</span>
              <h1>Günaydın, İlyas.</h1>
              <p>Varlıklarınızın risk görünümü ve devam eden güvenli taramalar.</p>
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
                  <p>Hedef türünü seçin; en uygun analiz hattı otomatik kurulsun.</p>
                </div>
                <span className="safe-badge">
                  <span /> Güvenli varsayılanlar
                </span>
              </div>

              <form onSubmit={submitScan} noValidate>
                <div className="target-tabs" role="tablist" aria-label="Hedef türü">
                  {targetOptions.map((option) => (
                    <button
                      type="button"
                      role="tab"
                      aria-selected={targetType === option.id}
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
                  <div className="input-shell">
                    <span className="input-prefix" aria-hidden="true">
                      {targetOptions.find((option) => option.id === targetType)?.icon}
                    </span>
                    <input
                      id="scan-target"
                      value={target}
                      onChange={(event) => setTarget(event.target.value)}
                      placeholder={targetConfig[targetType].placeholder}
                      autoComplete="off"
                      spellCheck="false"
                    />
                    <span className="input-status">Kapsamlı</span>
                  </div>
                  <span className="field-hint">{targetConfig[targetType].hint}</span>
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
                          ? "WC-LOCAL-01 bu hedefi salt okunur ve izole iş alanında aktaracak."
                          : "Tarayıcı yerel dosyalara erişemez. İmzalanmış ajan yolu güvenli biçimde worker'a aktarır."}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setAgentConnected(true);
                        setNotice("Demo masaüstü ajanı salt okunur modda eşleştirildi.");
                      }}
                    >
                      {agentConnected ? "Ajan bağlı" : "Ajanı eşleştir"}
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
                      <em>0 istek</em>
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
                        <small>Zararsız kontroller</small>
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
                      <small>Kapsam dışı yönlendirmeler ve varlıklar otomatik kesilir.</small>
                    </span>
                  </label>
                  <button
                    type="submit"
                    className="start-scan-button"
                    disabled={!target.trim() || !scopeConfirmed}
                  >
                    <span aria-hidden="true">▷</span>
                    Güvenli taramayı başlat
                  </button>
                </div>
              </form>
            </article>

            <article className="running-card panel" id="scans">
              <div className="card-heading">
                <div>
                  <span className="section-kicker">CANLI KUYRUK</span>
                  <h2>Çalışan taramalar</h2>
                </div>
                <span className="live-indicator">
                  <span /> {scans.filter((scan) => scan.status === "RUNNING").length} aktif
                </span>
              </div>

              <div className="scan-list" aria-live="polite">
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
                        aria-label={`${scan.name} taramasını ${scan.status === "PAUSED" ? "sürdür" : "duraklat"}`}
                        onClick={() => toggleSingleScan(scan.id)}
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
                onClick={() => setNotice(`Kuyrukta toplam ${scans.length} tarama var.`)}
              >
                Tüm taramaları gör <span aria-hidden="true">→</span>
              </button>
            </article>
          </section>

          <section className="findings-card panel" id="findings">
            <div className="findings-header">
              <div>
                <span className="section-kicker">RİSK GÖRÜNÜMÜ</span>
                <h2>Son bulgular</h2>
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
