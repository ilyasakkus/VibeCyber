# WebCyber

WebCyber; web adreslerini, kaynak kod klasörlerini, mobil paketleri ve masaüstü
uygulamalarını aynı bulgu modeliyle inceleyen açık kaynaklı bir güvenlik tarama
platformudur.

> [!IMPORTANT]
> WebCyber yalnızca sahibi olduğunuz veya test etme izniniz bulunan hedeflerde
> kullanılmalıdır. Varsayılan `observe` ve `safe` profilleri veri değiştiren,
> kalıcı payload bırakan veya exploit çalıştıran testler yapmaz.

## Bugünkü durum

Depo, Faz 1a yerel kontrol düzlemiyle çalışan bir dikey dilim içerir:

- Cloudflare uyumlu React web kontrol paneli ve `same-origin` API proxy katmanı
- Yerel geri döngüde (loopback) çalışan, bearer token zorunlu Go kontrol API'si
- Sınırlandırılmış bellek içi iş kuyruğu, son işler, iptal ve SSE durum olayları
- Güvenli varsayılanlara sahip Go CLI ve ortak bulgu modeli
- Go CLI'yi paketleyen, yerel dosya seçimi ve dar IPC kullanan Electron
  masaüstü köprüsü
- JSON ve SARIF çıktı sözleşmeleri
- SSRF, yönlendirme, dosya/symlink, süre ve çıktı sınırları
- Güvenlik politikası, tehdit modeli ve eklenti manifest sözleşmesi

Web taraması bugün pasif ve salt okunurdur. Kaynak kod, mobil paket ve masaüstü
uygulaması taramaları kontrol API'sinde yalnızca `WEBCYBER_ALLOW_LOCAL=true`
iken açılır. Bu izin, doğrudan CLI kullanımını veya masaüstü uygulamasının
kullanıcının seçtiği yerel hedefe erişimini değiştirmez.

Nuclei, Semgrep, Trivy, Gitleaks, MobSF ve derin binary analiz araçları daha
sonra imzalı ve sabitlenmiş worker adaptörleri olarak eklenecektir. Kullanıcı
girdisi hiçbir zaman shell komutuna dönüştürülmez.

## Mimari

```text
Web tarayıcısı → same-origin web proxy → loopback Go kontrol API'si
                                           │
                                           ▼
                              sınırlı bellek içi kuyruk
                                           │
                                           ▼
                                  Go tarama çekirdeği

Electron masaüstü → paketlenmiş Go CLI → Go tarama çekirdeği
Go CLI ───────────────────────────────→ Go tarama çekirdeği
```

Tarayıcı, kontrol token'ını görmez; web sunucusundaki proxy bu bilgiyi Go
isteğine ekler. Web tarayıcısı kullanıcının yerel dosya yolunu kendi başına
okuyamaz. Yerel hedefler geliştirmede aynı makinedeki kontrol API'si, normal
masaüstü kullanımında ise kullanıcının açıkça seçtiği yol üzerinden taranır.

Ayrıntılar için [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) ve
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) dosyalarına bakın.

## Gereksinimler

- Node.js 22.13 veya üzeri
- Go 1.24 veya üzeri
- Masaüstü geliştirme için Electron'ın desteklediği bir işletim sistemi

## Çalıştırma

Bağımlılıkları kurduktan sonra web panelini ve gerçek Go kontrol düzlemini
birlikte başlatmanın önerilen yolu:

```bash
npm install
npm run dev:full
```

`dev:full`, Go API'yi varsayılan olarak `127.0.0.1:7071` üzerinde açar; ortamda
önceden bir değer verilmemişse her çalıştırmada rastgele bearer token üretir ve
aynı token'ı yalnızca web sunucusu ile Go sürecine verir. Yerel geliştirme için
`WEBCYBER_ALLOW_LOCAL` varsayılanı bu komutta `true` olur. Süreçlerden biri
kapanırsa diğeri de kontrollü biçimde sonlandırılır.

Yalnızca arayüz geliştirmek için:

```bash
npm run dev
```

Bu komut Go bileşenini başlatmaz. Yapılandırılmış API'ye ulaşılamıyorsa panel
bilinçli olarak çevrimdışı durumu gösterir; sahte tarama veya demo sonucu
üretmez.

Kontrol servisini ayrı çalıştırmak isteyen geliştiriciler
`WEBCYBER_CONTROL_TOKEN` değerini zorunlu olarak vermelidir.
`WEBCYBER_API_URL` web proxy'sinin bağlanacağı adresi,
`WEBCYBER_CONTROL_ADDR` Go servisinin dinleyeceği adresi ve
`WEBCYBER_ALLOW_LOCAL` yerel hedef türlerinin API üzerinden açılıp
açılmayacağını belirler. API; sağlık/yetenek bilgisi, iş oluşturma, listeleme ve
okuma, tekli veya toplu iptal ve iş başına SSE olay uç noktalarını sağlar.

Go CLI:

```bash
go test ./cmd/... ./internal/...
go run ./cmd/webcyber scan --type source --target . --profile observe --format json
```

İzinli bir URL üzerinde yalnızca gözlem kontrolleri:

```bash
go run ./cmd/webcyber scan \
  --type web \
  --target https://example.com \
  --profile observe \
  --format sarif
```

Masaüstü kabuğu:

```bash
npm --prefix desktop install
npm --prefix desktop run prepare:scanner
npm --prefix desktop start
```

## Güvenlik profilleri

| Profil | Amaç | Varsayılan sınır |
| --- | --- | --- |
| `observe` | TLS, başlık, metadata ve yerel statik analiz | Veri değiştirmez |
| `safe` | MVP'de aynı salt-okunur web gözlemi; daha geniş yerel statik kurallar için sözleşme | Veri değiştirmez; crawl henüz yok |
| `active` | Yetkili staging ortamında ileri testler | Bu ilk dilimde kapalı |

> [!WARNING]
> Faz 1a kontrol API'si yerel geliştirme içindir. Bu Go API + web proxy
> birleşimini güçlü kullanıcı kimlik doğrulaması, tenant bazlı yetkilendirme ve
> oran limiti ile hedef sahipliği doğrulaması eklenmeden açık internete
> açmayın. Bellek içi kuyruk kalıcı değildir; PostgreSQL, Redis, RBAC, audit ve
> hedef sahipliği kontrolleri Faz 1b kapsamındadır.

## Depo yapısı

```text
app/                 Web kontrol paneli ve same-origin kontrol proxy katmanı
cmd/webcyber/        CLI giriş noktası
cmd/webcyberd/       Yerel Go kontrol servisi
internal/            Tarama çekirdeği, kontrol kuyruğu ve yerleşik adaptörler
desktop/             Güvenli Electron masaüstü kabuğu ve CLI köprüsü
docs/                Mimari, tehdit modeli ve yol haritası
schemas/             Eklenti sözleşmeleri
```

## Yol haritası

Faz 1a, panel ile Go çekirdeğini güvenli bir yerel kontrol sınırında birleştirir.
Faz 1b kalıcı ve çok kullanıcılı üretim kontrol düzlemini ekleyecektir. Ardından
worker adaptörleri, daha derin mobil/masaüstü analizleri ve en son açık izinli
aktif DAST gelir. Ayrıntılı plan [`docs/ROADMAP.md`](docs/ROADMAP.md)
içindedir.

## Katkı ve lisans

Katkılar için [`CONTRIBUTING.md`](CONTRIBUTING.md), güvenlik açığı bildirmek
için [`SECURITY.md`](SECURITY.md) dosyasını okuyun. Proje Apache-2.0 lisansıyla
sunulur.
