# WebCyber Mimarisi

## Tasarım kararı

İlk sürüm, dağıtık bir mikroservis yığını yerine modüler bir kontrol düzlemi ve
ayrı güven sınırına sahip worker/yerel agent kullanır. İş hacmi büyüdüğünde aynı
job ve finding sözleşmeleri korunarak modüller bağımsız servislere ayrılabilir.

## Bileşenler

```text
┌──────────────── istemciler ────────────────┐
│ Web paneli │ Electron masaüstü │ Go CLI    │
└────────────┬───────────────────────┬────────┘
             │                       │ yerel dosya yetkisi
             ▼                       ▼
┌──────────────── control plane ─────────────┐
│ Auth/RBAC │ target verification │ policy   │
│ scan plan │ queue/lease          │ events   │
└───────────────────┬────────────────────────┘
                    ▼
┌──────────────── worker sınırı ─────────────┐
│ web/api │ source/sca │ mobile │ binary     │
└───────────────────┬────────────────────────┘
                    ▼
       normalizer → dedupe → correlation
                    ▼
            JSON / SARIF / HTML / SBOM
```

## Hedef türleri

### Web ve API

1. URL canonicalize edilir; yalnızca HTTP(S) kabul edilir.
2. DNS sonucu ve her redirect private, loopback, link-local, multicast, ULA ve
   metadata ağlarına karşı yeniden doğrulanır.
3. `observe` profili TLS, sertifika, güvenlik başlıkları ve cookie özelliklerini
   okur.
4. `safe` profili yalnız doğrulanmış origin içinde sınırlı crawl ve incelenmiş
   şablon çalıştırır.
5. Subdomain/port genişletmesi ayrı bir doğrulanmış scope ister.

### Kaynak kod

- Yerel agent salt okunur klasör yetkisi alır.
- Symlink takip edilmez; dosya sayısı, tekil/toplam boyut ve süre sınırlandırılır.
- Projenin build/install scriptleri, Git hook'ları ve binary'leri çalıştırılmaz.
- Semgrep, Trivy/OSV ve Gitleaks daha sonra sabit OCI digest'li adaptörlerdir.

### Mobil ve masaüstü

- APK/IPA/asar/PE/ELF/Mach-O yalnızca statik olarak açılır; içerik çalıştırılmaz.
- Arşiv açma zip-slip, symlink, nesting, dosya sayısı ve sıkıştırma oranı
  kontrollerinden geçer.
- IPA analizi, şifreli App Store paketlerinde sınırlı olarak raporlanır.
- Binary koruma analizi format ve işletim sistemi bazlı adaptörlere ayrılır.

## Tarama yaşam döngüsü

```text
PENDING → RUNNING → COMPLETED
              ├──→ PARTIAL
              ├──→ CANCELLING → CANCELLED
              └──→ FAILED
```

Bir modülün hata vermesi “zafiyet yok” anlamına gelmez; tüm tarama `PARTIAL`
olur. Her module run kullanılan araç/kural sürümü, limit, başlangıç/bitiş ve
sanitize edilmiş hata bilgisini taşır.

## Normalize bulgu

Her bulgu şu ortak alanlara sahiptir:

- sabit fingerprint ve occurrence kimliği
- severity ile ayrı confidence
- `unverified`, `observed`, `verified` doğrulama durumu
- CWE/CVE/OWASP eşlemesi ve isteğe bağlı CVSS vector
- araç, sürüm, kural paketi ve konum
- maskelenmiş kanıt ve uygulanabilir çözüm
- suppression/false-positive durumu ve audit izi

## Üretim veri katmanı

Üretim şeması tenant merkezli olmalıdır: organizations, memberships, targets,
target_verifications, scan_authorizations, scans, scan_jobs, module_runs,
artifacts, findings, finding_occurrences, suppressions ve audit_events. Secret ve
test oturumları düz metin scan config içinde değil ayrı bir vault referansıyla
tutulur.
