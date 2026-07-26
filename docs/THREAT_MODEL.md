# Tehdit Modeli

## Kapsam ve güvenlik iddiası

Bu belge iki ayrı dağıtım hedefini ayırır:

- **Faz 1a:** Loopback Go kontrol API'si, `same-origin` web proxy katmanı, bellek içi
  kuyruk ve yerel Electron/CLI köprüsü.
- **Faz 1b:** Çok kullanıcılı üretim kontrol düzlemi, kalıcı veri ve dağıtık
  worker'lar.

Faz 1a'daki bearer token süreçler arası yerel sınırı korur; kullanıcı hesabı,
tenant yetkilendirmesi veya hedef sahipliği kanıtı değildir. Faz 1b kontrolleri
tamamlanmadan mevcut Go API + web proxy birleşimi açık internete
açılmamalıdır.

## Korunan varlıklar

- Kullanıcının kaynak kodu, uygulama paketleri ve rapor kanıtları
- Test credential/cookie/token'ları
- Kontrol bearer token'ı ve yerel dosya erişim sınırı
- Gelecekteki tenant sınırı, audit kayıtları ve hedef yetkilendirmeleri
- Worker altyapısı, kontrol düzlemi ve iç ağ
- Eklenti/kural paketlerinin bütünlüğü

## Güven sınırları

1. Tarayıcı ↔ `same-origin` web proxy katmanı
2. Web proxy katmanı ↔ loopback Go kontrol API'si
3. Go kontrol API'si ↔ bellek içi kuyruk ↔ tarama çekirdeği
4. Electron renderer ↔ preload/main IPC ↔ paketlenmiş Go CLI
5. Tarama çekirdeği ↔ hedef ağ
6. Tarama çekirdeği ↔ kullanıcı artifact'ı
7. Gelecekte control plane ↔ kalıcı kuyruk ↔ izole worker
8. Eklenti ve kural tedarik zinciri

## Faz 1a tehditleri ve mevcut kontroller

| Tehdit | Mevcut kontrol | Kalan sınır |
| --- | --- | --- |
| Kontrol API'sine yetkisiz istek | Boş token ile başlamama, sabit zamanlı bearer doğrulama, varsayılan loopback bağlantısı, CORS açmama | Tek token kullanıcı/tenant kimliği değildir |
| Bearer token bilgisinin tarayıcıya sızması | Değer yalnız sunucu tarafındaki web proxy katmanı ile Go süreci ortamında tutulur | Host veya geliştirme süreci ele geçirilirse token korunamaz |
| Yerel dosya yolunun uzaktan kötüye kullanılması | Go servisi tek başına başlatıldığında `source`, `mobile` ve `desktop` kapalıdır; yalnız `WEBCYBER_ALLOW_LOCAL=true` ile açılır | Bu seçenek, güvenilmeyen kullanıcıların eriştiği bir sunucuda açılmamalıdır |
| Servisin tarama proxy'si olarak kullanılması | HTTP(S) izin listesi, URL/IP doğrulama, her yönlendirmede tekrar kontrol, metadata/iç ağ engeli | Faz 1a hedef sahipliğini doğrulamaz |
| Zararlı repo veya paket | Kod çalıştırmama, salt okunur erişim, symlink/arşiv ve boyut limitleri | Derin üçüncü taraf araçları için izolasyon worker'ı gerekir |
| Kaynak tüketimi/DoS | Sınırlı istek boyutu, aktif iş/retention/eşzamanlılık kotası, süre limitleri ve iptal | Tenant bazlı kota ve dağıtık rate-limit yoktur |
| SSE üzerinden rapor veya hedef sızıntısı | Olay yalnız iş kimliği, durum ve zamanı taşır; rapor yetkili GET ile okunur | Tek token'a sahip taraf son işlerin tümünü okuyabilir |
| Secret'ın bulguya sızması | Değer saklamama, redaksiyon ve maskeli kanıt | Faz 1a raporları süreç belleğinde token kapsamındaki tüm istemcilere açıktır |
| Sahte “başarılı” tarama algısı | `partial`, `failed` ve `cancelled` durumları ayrı; API yoksa panel çevrimdışı ve demo üretmez | Kullanıcı modül sınırlamalarını raporla birlikte değerlendirmelidir |
| İş geçmişinin kaybı | Bellek içi saklama açıkça belgelenir | Kalıcılık ve kurtarma Faz 1b'dedir |
| Rapor arayüzü saldırısı | React metin kaçışlama; rapor verisini HTML olarak enjekte etmeme | Dağıtım CSP'si ve yeni renderer'lar ayrıca sertleştirilmelidir |

`authorized: true` alanı, kullanıcının izin beyanıdır; kriptografik hedef
sahipliği doğrulaması değildir.

## Faz 1b'de zorunlu üretim kontrolleri

- Kullanıcı kimlik doğrulaması, organization/workspace üyeliği ve nesne bazlı
  RBAC
- DNS/HTTP challenge ile hedef sahipliği ve süreli scan authorization
- Rules of Engagement kaydı, tenant bazlı rate-limit, kota ve abuse response
- PostgreSQL kalıcılığı, tenant_id zorunluluğu, RLS/servis kontrolleri ve audit
- Redis tabanlı lease/heartbeat/retry kuyruğu
- Secret/vault referansı, encryption, artifact retention ve güvenli silme
- Hedefe özel egress proxy ve yalnız doğrulanmış scope'a ağ erişimi
- Her job için rootless tek kullanımlık container veya microVM

Bu kontroller uygulanmadan Faz 1a'yı internet erişimli veya çok kullanıcılı bir
servis olarak dağıtmak desteklenmez.

## Worker minimum profili

İzole worker adaptörleri eklendiğinde minimum profil:

- Her job için tek kullanımlık container veya microVM
- Root olmayan UID, `cap-drop=ALL`, `no-new-privileges`
- Docker socket/host PID/host network/host path mount yok
- Artifact salt okunur; scratch alanı boyut sınırlı tmpfs
- Varsayılan ağ `none`; web worker için yalnız doğrulanmış hedefe egress
- Maksimum süre sonunda tüm process tree'nin sonlandırılması
- İncelenmiş, imzalı ve OCI digest ile sabitlenmiş araç/kural paketleri

## Kasıtlı non-goals

İlk sürüm otomatik exploit zinciri kurmaz, kalıcı XSS payload bırakmaz, SQL veri
çıkarmaya çalışmaz, brute force/credential stuffing yapmaz, uygulama binary'si
çalıştırmaz ve kullanıcı tarafından yüklenen keyfî scanner/template çalıştırmaz.
Web `observe` ve `safe` profilleri pasif, tek istekli ve salt okunurdur; crawl
ve active profil henüz yoktur.

Bu belge her yeni hedef türü, ağ yetkisi, kimlik sınırı veya executable eklenti
eklendiğinde güncellenmelidir.
