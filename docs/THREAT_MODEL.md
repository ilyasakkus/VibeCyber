# Tehdit Modeli

## Korunan varlıklar

- Kullanıcının kaynak kodu, uygulama paketleri ve rapor kanıtları
- Test credential/cookie/token'ları
- Tenant sınırı, audit kayıtları ve hedef yetkilendirmeleri
- Worker altyapısı, kontrol düzlemi ve iç ağ
- Eklenti/kural paketlerinin bütünlüğü

## Güven sınırları

1. Tarayıcı ↔ web kontrol düzlemi
2. Masaüstü renderer ↔ preload/main IPC
3. Control plane ↔ kuyruk ↔ worker
4. Worker ↔ hedef ağ
5. Worker ↔ kullanıcı artifact'ı
6. Eklenti ve kural tedarik zinciri

## Ana tehditler ve kontroller

| Tehdit | Kontrol |
| --- | --- |
| SaaS'ın SSRF proxy olarak kullanılması | URL/IP doğrulama, redirect tekrar kontrolü, hedefe özel egress proxy, metadata/iç ağ engeli |
| Yetkisiz üçüncü taraf taraması | DNS/HTTP challenge, süreli sahiplik doğrulaması, Rules of Engagement, rate limit |
| Komut enjeksiyonu | Shell yok, sabit binary, allowlist argümanlar, temiz environment |
| Zararlı repo veya paket | Kod çalıştırmama, salt okunur mount, symlink/arşiv limitleri, disposable sandbox |
| Worker kaçışı | rootless, read-only rootfs, cap-drop, no-new-privileges, seccomp, PID/CPU/RAM/disk/time limit |
| Tenant veri sızıntısı | tenant_id zorunluluğu, nesne bazlı authz, RLS/servis kontrolleri, audit |
| Secret'ın rapora sızması | değer saklamama, maskeli fingerprint, header/body redaksiyonu, retention |
| Zararlı topluluk eklentisi | public SaaS'ta keyfî kod yok; inceleme, imza ve OCI digest pinleme |
| Rapor renderer saldırısı | untrusted metni escape etme, uzak URL fetch kapalı, CSP |
| Kaynak tüketimi/DoS | concurrency, request, byte, file, process ve süre kotası; kill switch |

## Worker minimum profili

- Her job için tek kullanımlık container veya microVM
- Root olmayan UID, `cap-drop=ALL`, `no-new-privileges`
- Docker socket/host PID/host network/host path mount yok
- Artifact salt okunur; scratch alanı boyut sınırlı tmpfs
- Varsayılan ağ `none`; web worker için yalnız doğrulanmış hedefe egress
- Maksimum süre sonunda tüm process tree sonlandırılır

## Kasıtlı non-goals

İlk sürüm otomatik exploit zinciri kurmaz, kalıcı XSS payload bırakmaz, SQL veri
çıkarmaya çalışmaz, brute force/credential stuffing yapmaz, uygulama binary'si
çalıştırmaz ve kullanıcı tarafından yüklenen keyfî scanner/template çalıştırmaz.

Bu belge her yeni hedef türü, ağ yetkisi veya executable eklenti eklendiğinde
güncellenmelidir.
