# Katkı Rehberi

Katkı göndermeden önce bir issue ile amaç ve güvenlik etkisini paylaşın.

## Geliştirme ilkeleri

1. Güvenli varsayılanları gevşetmeyin; yeni ağ veya dosya yetkisini açıkça
   belgeleyin.
2. Kullanıcı girdisini shell'e aktarmayın. Sabit binary ve ayrı argüman dizisi
   kullanın.
3. Yeni scanner adaptörü için sürüm/digest, izinler, kaynak limitleri ve normalize
   çıktı sözleşmesi tanımlayın.
4. Secret değerlerini test fixture'larında dahi gerçek biçimde kullanmayın.
5. Yeni davranışa birim testi ve mümkünse parser fixture testi ekleyin.

## Kontroller

```bash
go test ./cmd/... ./internal/...
npm run lint
npm test
node --check desktop/main.mjs
node --check desktop/preload.mjs
```

Exploit zinciri, kalıcı payload, credential stuffing, veri silme veya genel
amaçlı komut çalıştırma ekleyen katkılar kabul edilmez. Zararsız doğrulama
kuralları açık bir Rules of Engagement ve scope modeliyle sunulmalıdır.
