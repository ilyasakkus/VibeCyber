# Güvenlik Politikası

## WebCyber'da bir açık bulduysanız

Lütfen açığı herkese açık issue olarak paylaşmayın. GitHub deposundaki
**Security → Report a vulnerability** akışını kullanarak özel güvenlik bildirimi
gönderin. Depo henüz GitHub'da yayınlanmadıysa maintainer ile özel bir kanal
üzerinden iletişime geçin.

Bildirime sürüm/commit, etkilenen bileşen, yeniden üretim adımları, olası etki
ve varsa önerilen düzeltmeyi ekleyin. Gerçek kullanıcı verisi, çalışan secret,
token veya üçüncü taraf sisteme ait hassas kanıt eklemeyin.

## Kapsam

- CLI, yerel agent ve masaüstü IPC sınırı
- Web kontrol düzlemi ve tenant yetkilendirmesi
- URL doğrulama, SSRF ve redirect kontrolleri
- Worker sandbox ve eklenti tedarik zinciri
- Raporlarda secret/kanıt redaksiyonu

## Güvenli araştırma

- Yalnızca sahibi olduğunuz ya da yazılı izin aldığınız hedefleri test edin.
- Üretim verisini değiştirmeyin, kalıcı payload bırakmayın ve veri çıkarmayın.
- Hizmet kesintisine yol açabilecek yük, brute force veya geniş port taraması
  kullanmayın.
- Bir üçüncü taraf üründe açık bulursanız o ürünün sorumlu bildirim sürecini
  izleyin; kanıtı WebCyber issue'larına taşımayın.

WebCyber'ın güvenlik politikalarını aşmaya yarayan değişiklikler varsayılan
dağıtıma kabul edilmez.
