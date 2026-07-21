# WebCyber

WebCyber; web adreslerini, kaynak kod klasörlerini, mobil paketleri ve masaüstü
uygulamalarını aynı bulgu modeliyle incelemeyi hedefleyen açık kaynaklı bir
güvenlik tarama platformudur.

> [!IMPORTANT]
> WebCyber yalnızca sahibi olduğunuz veya test etme izniniz bulunan hedeflerde
> kullanılmalıdır. Varsayılan `observe` ve `safe` profilleri veri değiştiren,
> kalıcı payload bırakan veya exploit çalıştıran testler yapmaz.

## Bugünkü durum

Bu depo ilk çalışan dikey dilimi içerir:

- Cloudflare uyumlu React web kontrol paneli
- Güvenli varsayılanlara sahip Go CLI ve ortak bulgu modeli
- Yerel dosya seçimi için izole Electron masaüstü kabuğu
- JSON ve SARIF çıktı sözleşmeleri
- SSRF, yönlendirme, dosya/symlink, süre ve çıktı sınırları
- Güvenlik politikası, tehdit modeli ve eklenti manifest sözleşmesi

İlk dilim gözlem ve statik analiz odaklıdır. Nuclei, Semgrep, Trivy, Gitleaks,
MobSF ve binary analiz araçları daha sonra imzalı ve sabitlenmiş worker
adaptörleri olarak eklenir; kullanıcı girdisi hiçbir zaman shell komutuna
dönüştürülmez.

## Mimari

```text
Web paneli ──────────────┐
Masaüstü uygulaması ─────┼─> Control plane / tarama planı
CLI / yerel agent ───────┘            │
                                      ▼
                          İzole worker adaptörleri
                                      │
                                      ▼
                    Normalize et → tekilleştir → raporla
```

Web tarayıcısı kullanıcının yerel dosya yolunu okuyamaz. Bu nedenle URL işleri
doğrulanmış uzak worker'larda, klasör ve uygulama işleri ise masaüstü uygulaması
veya kullanıcının kurduğu yerel agent üzerinde çalışır. Ayrıntılar için
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) ve
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) dosyalarına bakın.

## Gereksinimler

- Node.js 22.13 veya üzeri
- Go 1.25 veya üzeri
- Masaüstü geliştirme için Electron'ın desteklediği bir işletim sistemi

## Çalıştırma

Web paneli:

```bash
npm install
npm run dev
```

Go CLI:

```bash
go test ./...
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
go build -o desktop/resources/bin/webcyber ./cmd/webcyber
npm --prefix desktop install
npm --prefix desktop start
```

## Güvenlik profilleri

| Profil | Amaç | Varsayılan sınır |
| --- | --- | --- |
| `observe` | TLS, başlık, metadata ve yerel statik analiz | Veri değiştirmez |
| `safe` | Sınırlandırılmış crawl ve incelenmiş kurallar | Aynı origin, oran/süre kotası |
| `active` | Yetkili staging ortamında ileri testler | Bu ilk dilimde kapalı |

Halka açık bir WebCyber kurulumu, aktif tarama başlatmadan önce hedef sahipliği,
Rules of Engagement kaydı ve tenant bazlı oran limitini zorunlu tutmalıdır.

## Depo yapısı

```text
app/                 Web kontrol paneli
cmd/webcyber/        CLI giriş noktası
internal/            Tarama çekirdeği ve yerleşik adaptörler
desktop/             Güvenli Electron masaüstü kabuğu
docs/                Mimari, tehdit modeli ve yol haritası
schemas/             Eklenti sözleşmeleri
```

## Yol haritası

Sıralama güvenlik sınırlarını önce kurar: URL + kaynak kod, ardından APK ve
Electron statik analizi, sonrasında platforma özel PE/ELF/Mach-O adaptörleri ve
en son açık izinli aktif DAST. Ayrıntılı plan
[`docs/ROADMAP.md`](docs/ROADMAP.md) içindedir.

## Katkı ve lisans

Katkılar için [`CONTRIBUTING.md`](CONTRIBUTING.md), güvenlik açığı bildirmek
için [`SECURITY.md`](SECURITY.md) dosyasını okuyun. Proje Apache-2.0 lisansıyla
sunulur.
