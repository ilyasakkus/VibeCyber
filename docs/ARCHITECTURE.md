# WebCyber Mimarisi

## Tasarım kararı

Faz 1a, dağıtık bir mikroservis yığını yerine aynı makinede çalışan modüler bir
Go kontrol servisi kullanır. Amaç web panelini gerçek tarama çekirdeğine
bağlarken ağ ve iş sınırlarını önce küçük, gözlemlenebilir ve test edilebilir
tutmaktır. İş ve bulgu sözleşmeleri, Faz 1b'de kalıcı kontrol düzlemine geçerken
korunacaktır.

## Faz 1a bileşenleri

```text
┌──────────────────────── istemciler ────────────────────────┐
│ Web tarayıcısı        │ Electron masaüstü      │ Go CLI    │
└──────────┬────────────┴──────────────┬──────────┴────┬──────┘
           │                           │               │
           ▼                           ▼               │
┌─────────────────────┐      ┌──────────────────┐      │
│ same-origin web     │      │ paketlenmiş CLI  │      │
│ proxy katmanı       │      │ köprüsü          │      │
└──────────┬──────────┘      └─────────┬────────┘      │
           │ bearer token              │               │
           ▼                           └───────┬───────┘
┌─────────────────────────────────────────────▼───────────────┐
│ loopback Go kontrol API'si                                 │
│ sınırlı bellek içi kuyruk │ son işler │ iptal │ SSE olayları│
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌──────────────────── Go tarama çekirdeği ────────────────────┐
│ web gözlemi │ source statik │ mobile statik │ desktop statik│
└───────────────────────────┬─────────────────────────────────┘
                            ▼
                  normalize → tekilleştir
                            ▼
                       JSON / SARIF
```

Electron köprüsü ve doğrudan CLI, kontrol API'sinin kuyruğundan bağımsız olarak
yerel Go tarama çekirdeğini çağırır. Web paneli ise yalnızca `same-origin` proxy
üzerinden kontrol API'siyle konuşur.

## Yerel kontrol sınırı

`cmd/webcyberd` varsayılan olarak `127.0.0.1:7071` adresine bağlanır ve boş
`WEBCYBER_CONTROL_TOKEN` ile başlamayı reddeder. Web proxy katmanı sunucu
tarafındaki `WEBCYBER_API_URL` ve `WEBCYBER_CONTROL_TOKEN` yapılandırmalarını kullanır;
bearer token tarayıcıya verilmez. API CORS açmaz ve istek gövdesi ile başlık
boyutlarını sınırlar.

`npm run dev:full`, ortamda token verilmemişse her çalıştırmada rastgele bir
değer üretip web ve Go süreçlerine ortak verir, Go servisinin sağlık yanıtını
bekler ve iki sürecin yaşam döngüsünü birlikte yönetir. `npm run dev` yalnızca
web panelini başlatır; API yoksa panel çevrimdışı görünür ve sahte sonuç
üretmez.

Kontrol API'sinin sürümlü yüzeyi özetle şunları sağlar:

- sağlık ve yetenek bilgisi;
- tarama işi oluşturma, listeleme ve okuma;
- tek işi veya çalışan/bekleyen tüm işleri iptal etme;
- iş yaşam döngüsünü ileten SSE akışı.

Her oluşturma isteği açık bir yetki beyanı taşır. Bu beyan hedef sahipliği
kanıtı değildir; üretim hedef doğrulama akışının yerini tutmaz.

## Kuyruk ve yaşam döngüsü

Faz 1a kuyruğu süreç belleğindedir. Eşzamanlılık, aktif iş sayısı ve saklanan son
iş sayısı sınırlıdır; varsayılan olarak en fazla 100 iş tutulur. Servis yeniden
başlatıldığında iş geçmişi ve raporlar kaybolur. SSE olayları hedefi veya raporu
taşımaz; terminal olaydan sonra istemci yetkili iş ucundan güncel raporu okur.

```text
QUEUED ───────────────→ CANCELLED
   │
   └──→ RUNNING ─────→ COMPLETED
             ├───────→ PARTIAL
             ├───────→ CANCELLING → CANCELLED
             └───────→ FAILED
```

Bekleyen iş hemen `CANCELLED` olur. Çalışan iş Go context iptali istendikten
sonra `CANCELLING` durumunda kalır; worker gerçekten döndüğünde terminal
`CANCELLED` olayı ve bitiş zamanı yayımlanır. İptal tek yönlüdür;
“duraklat/devam et” semantiği yoktur. Bir modülün hata vermesi “zafiyet yok”
anlamına gelmez; tarama `PARTIAL` olabilir. Rapor, kullanılan modül ve limitler
ile sanitize edilmiş hata bilgisini taşır.

## Hedef türleri

### Web ve API

1. URL canonicalize edilir; yalnızca HTTP(S) kabul edilir.
2. DNS sonucu ve her redirect private, loopback, link-local, multicast, ULA ve
   metadata ağlarına karşı yeniden doğrulanır.
3. `observe` profili TLS, sertifika, güvenlik başlıkları ve cookie özelliklerini
   okur.
4. Faz 1a'da `observe` ve `safe` aynı tek salt-okunur HTTP gözlemini yapar.
   Crawl veya aktif payload yoktur.
5. Subdomain/port genişletmesi ayrı ve doğrulanmış bir scope gerektirecektir.

### Kaynak kod

- Kontrol API'sinde `source` yalnızca `WEBCYBER_ALLOW_LOCAL=true` iken kabul
  edilir.
- Yerel tarayıcı salt okunur klasör erişimi kullanır.
- Symlink takip edilmez; dosya sayısı, tekil/toplam boyut ve süre sınırlandırılır.
- Projenin build/install scriptleri, Git hook'ları ve binary'leri çalıştırılmaz.
- Semgrep, Trivy/OSV ve Gitleaks daha sonra sabit OCI digest'li adaptörlerdir.

### Mobil ve masaüstü

- Kontrol API'sinde `mobile` ve `desktop` yalnızca
  `WEBCYBER_ALLOW_LOCAL=true` iken kabul edilir.
- APK/IPA/asar/PE/ELF/Mach-O yalnızca statik olarak açılır; içerik çalıştırılmaz.
- Arşiv okuma zip-slip, symlink, nesting, dosya sayısı ve sıkıştırma oranı
  kontrollerinden geçer.
- IPA analizi, şifreli App Store paketlerinde sınırlı olarak raporlanır.
- Binary koruma analizi format ve işletim sistemi bazlı adaptörlere ayrılır.

## Normalize bulgu

Her bulgu şu ortak alanlara sahiptir:

- sabit fingerprint ile kural ve modül kimliği;
- severity ile ayrı confidence;
- isteğe bağlı CWE/CVE eşlemesi;
- açıklama, uygulanabilir çözüm ve referanslar;
- konum, satır, URL ve sınırlandırılmış/maskelenmiş kanıt ayrıntıları.

Occurrence geçmişi, OWASP/CVSS eşlemesi, insan doğrulama durumu, suppression ve
audit izi bugünkü rapor sözleşmesinde yoktur; kalıcı bulgu yaşam döngüsüyle
birlikte Faz 1b/2 kapsamında eklenecektir.

## Faz 1b üretim topolojisi

Faz 1a bir SaaS kontrol düzlemi değildir. Faz 1b; organization/workspace,
kimlik doğrulama, RBAC, hedef sahipliği challenge'ı, süreli tarama yetkisi,
tenant bazlı oran limiti, PostgreSQL kalıcılığı, Redis tabanlı kuyruk/lease,
artifact saklama, audit ve retention ekleyecektir.

Üretim şeması tenant merkezli olacaktır: organizations, memberships, targets,
target_verifications, scan_authorizations, scans, scan_jobs, module_runs,
artifacts, findings, finding_occurrences, suppressions ve audit_events.
Secret'lar ve test oturumları düz metin scan config içinde değil ayrı bir vault
referansıyla tutulacaktır.

Faz 1a Go API'si ve web proxy katmanı bu kontroller olmadan açık internete
açılmamalıdır.
