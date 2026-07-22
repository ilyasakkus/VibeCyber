# Tarama motoru konumu

Paketleme sirasinda imzali Go CLI dosyasini bu dizine `webcyber` (Windows icin
`webcyber.exe`) adi ile koyun. Uretim paketi ayni dosyayi
`resources/bin/webcyber` konumuna kopyalamalidir.

Binary ile ayni dizinde sadece 64 karakterlik kucuk hex SHA-256 degeri iceren
`webcyber.sha256` (Windows icin `webcyber.exe.sha256`) bulunmasi zorunludur.
Kabuğun sabit bundled binary modu bu degeri her taramadan once dogrular. Yayin
sureci hash dosyasini imzalanmis binary olustuktan sonra uretmelidir.

Gelistirmede alternatif bir binary yalnizca mutlak, mevcut ve calistirilabilir
bir yol ile belirtilebilir:

```sh
WEB_CYBER_SCANNER_BIN=/mutlak/yol/webcyber npm start
```
