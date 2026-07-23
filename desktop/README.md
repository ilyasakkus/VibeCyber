# WebCyber Desktop

WebCyber Desktop, renderer ile Go tarama motoru arasinda guvenli bir Electron
siniri kuran ilk scaffold'dur. Renderer hicbir Node.js API'sine veya serbest
dosya sistemi erisimine sahip degildir.

## Calistirma

```sh
cd desktop
npm install
npm run prepare:scanner
npm run check
npm start
```

Electron `43.2.0` surumune tam olarak sabitlenmistir. Bu surum scaffold'un
hazirlandigi 22 Temmuz 2026 tarihinde guncel kararlı serideydi. Electron Chromium
guvenlik duzeltmelerini sik yayimladigi icin surum Dependabot/Renovate ile duzenli
olarak yenilenmelidir. Resmi durum:
<https://releases.electronjs.org/?channel=stable>

## CLI sozlesmesi

Kabuğun calistirdigi tek komut bicimi:

```text
webcyber scan --type web|source|mobile|desktop --target <hedef> --profile observe|safe --format json
```

- Paketli uygulamada binary yolu sabittir: `resources/bin/webcyber` (Windows'ta
  `webcyber.exe`).
- Gelistirmede varsayilan yol `desktop/resources/bin/webcyber` olur.
- Yalniz gelistirme modunda `WEB_CYBER_SCANNER_BIN` kullanilabilir; deger mutlak,
  mevcut ve calistirilabilir bir dosya degilse istek reddedilir.
- Surec `shell: false` ile ve sinirli bir ortam degiskeni listesiyle baslatilir.
- Ayni pencerede tek is ve toplam 8 MiB cikti / 1 MiB stderr siniri vardir. Go
  motorunun tarama butcesi 2 dakikadir; masaustu kabugu kontrollu kapanma icin 15
  saniye pay birakarak sureci en gec 135 saniyede sonlandirir. POSIX sistemlerde
  ayri bir process group sonlandirilir; Windows'ta sabit
  sistem `taskkill.exe /T /F` yolu ile process tree kapatilir. Uygulama cikisi bu
  temizligi kisa bir son tarihe kadar bekler.
- CLI stdout'u tek bir gecerli JSON degeri olmalidir. Motor non-zero cikis koduyla
  sonlansa bile semasi dogrulanan `failed` veya `partial` rapor renderer'a iletilir;
  hata metni, modul sonuclari ve sinirlamalar birlikte gosterilir.

Web URL'leri CLI'ya `--type web` olarak gider. Renderer URL'yi normalize eder;
ana surec protokol, kimlik bilgisi ve uzunluk kontrollerini yeniden uygular.
Mevcut motor public-web-only politikasiyla loopback, private, link-local ve
reserved hedefleri; guvensiz DNS cevaplarini ve yonlendirmeleri reddeder.
Web MVP'si hedefe tek bir salt-okunur GET istegi yapar. Crawl, form gonderimi,
fuzzing veya proof-of-concept payload calistirmaz; `observe` ve `safe` profilleri
bu surumde ayni pasif web davranisini kullanir. Yerel kaynak, mobil ve masaustu
hedeflerinde dosyalar sinirli ve statik olarak okunur; hedef uygulama kodu
calistirilmaz.

## Guvenlik modeli

- `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true` ve
  `webSecurity: true` zorunludur.
- Preload yalniz dar ve dogrulanan yetenekler acar: yerel hedef secme/birakma,
  tarama baslatma, tarama iptali ve sonuc olayini dinleme.
- Yerel hedef yolu renderer tarafindan yazilamaz. Native dialog seciminden sonra
  ana surecte saklanan hedefe rastgele bir kimlik verilir; tarama yalniz bu
  kimligi kabul eder. Kimlik 10 dakika gecerlidir, UI temizlediginde iptal edilir
  ve tarama basladiginda tek kullanimlik olarak tuketilir. Kok hedefin cihaz/inode
  ve dosya turu yeniden dogrulanir.
- Renderer'daki onay kutusu guvenlik siniri sayilmaz. Her taramadan once ana
  surecin actigi native dialog hedef ve profili gostererek kullanici onayi ister.
- Yeni pencere, harici navigasyon, webview, izin istekleri ve indirmeler reddedilir.
- Renderer CSP'si uzak baglanti, inline kod, form gonderimi ve obje/frame
  yuklemelerini engeller.
- Binary argumanlari sabit bir sirayla dizi olarak `spawn`'a verilir; shell
  yorumlamasi yapilmaz.
- Sabit binary canonical `resources/bin` siniri icinde kalmali ve yanindaki
  `<binary>.sha256` manifestindeki tek SHA-256 degeriyle eslesmelidir. Gelistirme
  override'i bu paket manifestinden bilincli olarak muaftir.
- JSON raporu IPC'ye verilmeden once toplam byte sinirina ek olarak kok nesne,
  derinlik, dugum sayisi, alan adi ve tekil metin boyutu sinirlarindan gecirilir.
  Ayrica tarama durumu, hedef/profil eslesmesi, web URL redaksiyonu, tarih ve sure,
  `sha256:` fingerprint bicimi, ozet-bulgu sayim tutarliligi ve 2.000 bulgu tavani
  dogrulanir.

**OS seviyesinde kaynak sandbox'i bu scaffold tarafindan garanti edilmez.** CLI
Electron renderer sandbox'inda degil, uygulamayi calistiran kullanicinin dosya
sistemi ve ag yetkileriyle calisir. Uretim surumunde platform imzasi/notarizasyonu
yaninda ayri, dusuk yetkili bir OS sandbox'i; CPU, RAM, disk, ag ve surec sayisi
kotalari zorunlu tutulmalidir. Mevcut Go motoru yerel taramada symlink'leri takip
etmez, gercek yollari secilen kok siniriyla denetler ve atlanan symlink'leri rapora
yazar. Mobil/masaustu arsiv acma katmani ayrica boyut, dosya sayisi, sikistirma
orani ve yol gecisi sinirlari uygulamalidir.

## Paketleme notu

Henuz bir packager bagimliligi eklenmedi. Secilecek paketleyici
`desktop/resources/bin/webcyber` dosyasini uygulamanin
`resources/bin/webcyber` konumuna **asar disinda** (ASAR icine gommeden)
kopyalamali; ayni dizine yalniz 64 kucuk hex karakter iceren
`webcyber.sha256` (Windows'ta `webcyber.exe.sha256`) manifestini eklemelidir.
macOS, Windows ve Linux imza/notarizasyon adimlari ayri yayin is akisinda zorunlu
tutulmalidir. Hash kontrolu paket imzasinin yerine gecmez ve dosyanin kontrol ile
`spawn` arasinda degistirilmesine karsi tek basina tam TOCTOU korumasi saglamaz.
