# Yol Haritası

## Faz 0 — güvenli temel (tamamlandı)

- Ortak Go scan/finding modeli ve CLI
- `observe` web kontrolleri ve sınırlı statik kaynak taraması
- JSON/SARIF çıktı, fingerprint ve partial durum
- Web paneli ve yerel dosya seçen Electron masaüstü/CLI köprüsü
- SSRF, dosya, süre, çıktı ve iptal sınırları
- Tehdit modeli, SECURITY ve eklenti sözleşmesi

## Faz 1a — yerel kontrol düzlemi (tamamlandı)

- Loopback üzerinde bearer token zorunlu Go kontrol API'si
- Web panelinden token'ı gizleyen `same-origin` sunucu proxy katmanı
- `npm run dev:full` ile varsayılan ortak rastgele token, sağlık yanıtını
  bekleme ve süreçleri birlikte yönetme
- Sınırlandırılmış bellek içi kuyruk, eşzamanlı worker'lar ve son iş listesi
- Queued/running/cancelling/terminal yaşam döngüsü, tekli/toplu iptal ve SSE
  olayları
- API yokken sahte demo yerine açık çevrimdışı panel durumu
- Web dışındaki yerel hedefleri `WEBCYBER_ALLOW_LOCAL` ile kapatma
- Pasif ve salt-okunur web tarama sınırının korunması

Faz 1a yerel geliştirme ve tek makine kullanımı içindir. İşler ve raporlar süreç
belleğinde tutulur; servis yeniden başladığında kaybolur.

## Faz 1b — üretim kontrol düzlemi (sıradaki)

- Organization/workspace, kullanıcı kimlik doğrulaması, üyelik ve RBAC
- Hedef sahipliği challenge'ı, Rules of Engagement ve süreli tarama yetkisi
- Tenant bazlı oran limiti, kota, kötüye kullanım önleme ve audit
- PostgreSQL kalıcılığı ve tenant izolasyonu
- Redis tabanlı kuyruk, job lease, heartbeat, retry ve yatay worker ölçekleme
- Artifact store, retention, encryption ve secret/vault referansları
- HTML rapor, diff/baseline ve suppression iş akışı

Bu faz tamamlanmadan Faz 1a Go API + web proxy birleşimi açık internete
açılmayacaktır.

## Faz 2 — worker adaptörleri

- Semgrep, Trivy/OSV ve Gitleaks
- Curated safe Nuclei ve same-origin Katana
- Tool/rule sürüm pinleme, imza ve lisans matrisi
- SBOM: CycloneDX ve SPDX
- Parser fixture, snapshot ve kasıtlı zayıf e2e hedefleri

## Faz 3 — mobil ve masaüstü

- APK manifest/network-security-config analizi ve MobSF adapter
- Electron asar/preload ayarları
- PE, ELF ve Mach-O koruma bayrakları için ayrı runner'lar
- iOS için şifreli/çözülmüş paket sınırlarının açık raporlanması

## Faz 4 — açık izinli ileri testler

- Kullanıcı tanımlı iki hesap/rol matrisiyle BOLA senaryoları
- Staging/self-hosted hedeflerde doğrulanmış `active` profil
- Zararsız, yeniden üretilebilir doğrulama kanıtları
- İnsan onaylı correlation/reachability

## Yayın kapıları

Her faz; tehdit modeli değişikliği, test kapsamı, lisans incelemesi, SBOM, imzalı
artifact ve geri alma/kill-switch planı olmadan yayınlanmaz.
