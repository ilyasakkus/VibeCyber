# WebCyber Desktop

WebCyber Desktop, renderer ile Go tarama motoru arasinda guvenli bir Electron
siniri kuran ilk scaffold'dur. Renderer hicbir Node.js API'sine veya serbest
dosya sistemi erisimine sahip degildir.

## Calistirma

```sh
cd desktop
npm install
npm run check
npm start
```

Electron `43.1.1` surumune tam olarak sabitlenmistir. Bu surum scaffold'un
hazirlandigi 22 Temmuz 2026 tarihinde guncel kararlı serideydi. Electron Chromium
guvenlik duzeltmelerini sik yayimladigi icin surum Dependabot/Renovate ile duzenli
olarak yenilenmelidir. Resmi durum:
<https://releases.electronjs.org/?channel=stable>

## CLI sozlesmesi

Kabuğun calistirdigi tek komut bicimi:

```text
webcyber scan --type source|mobile|desktop --target <hedef> --profile observe|safe --format json
```

- Paketli uygulamada binary yolu sabittir: `resources/bin/webcyber` (Windows'ta
  `webcyber.exe`).
- Gelistirmede varsayilan yol `desktop/resources/bin/webcyber` olur.
- Yalniz gelistirme modunda `WEB_CYBER_SCANNER_BIN` kullanilabilir; deger mutlak,
  mevcut ve calistirilabilir bir dosya degilse istek reddedilir.
- Surec `shell: false` ile ve sinirli bir ortam degiskeni listesiyle baslatilir.
- Ayni pencerede tek is, 15 dakika ve toplam 8 MiB cikti / 1 MiB stderr siniri
  vardir. Iptalde once `SIGTERM`, iki saniye sonra gerekirse `SIGKILL` kullanilir.
- Basarili CLI ciktisi tek bir gecerli JSON degeri olmalidir.

Web URL'leri CLI'ya `--type source` olarak gider. Renderer URL'yi normalize eder;
ana surec protokol, kimlik bilgisi ve uzunluk kontrollerini yeniden uygular.

## Guvenlik modeli

- `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true` ve
  `webSecurity: true` zorunludur.
- Preload yalniz dort dar yetenek acar: yerel hedef secme, tarama baslatma,
  tarama iptali ve sonuc olayini dinleme.
- Yerel hedef yolu renderer tarafindan yazilamaz. Native dialog seciminden sonra
  ana surecte saklanan hedefe rastgele bir kimlik verilir; tarama yalniz bu
  kimligi kabul eder.
- Yeni pencere, harici navigasyon, webview, izin istekleri ve indirmeler reddedilir.
- Renderer CSP'si uzak baglanti, inline kod, form gonderimi ve obje/frame
  yuklemelerini engeller.
- Binary argumanlari sabit bir sirayla dizi olarak `spawn`'a verilir; shell
  yorumlamasi yapilmaz.

Bu kabuk, tarama motorunun kendisini otomatik olarak guvenilmez hale getirmez.
Uretim surumunde CLI dosyasi imzalanmali, yayin manifestindeki hash ile
dogrulanmali ve mumkunse ayri, dusuk yetkili bir isletim sistemi sandbox'inda
calistirilmalidir. Mobil/masaustu paket acma islemleri de boyut, dosya sayisi,
sikistirma orani ve yol gecisi sinirlari uygulamalidir.

## Paketleme notu

Henuz bir packager bagimliligi eklenmedi. Secilecek paketleyici
`desktop/resources/bin/webcyber` dosyasini uygulamanin
`resources/bin/webcyber` konumuna **asar disinda** (ASAR icine gommeden)
kopyalamalidir. macOS, Windows ve Linux imza/notarizasyon adimlari ayri yayin
is akisinda zorunlu tutulmalidir.
