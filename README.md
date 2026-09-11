# ESP32-GA1202

Grup Arge **GA1202** reaktif güç kontrol rölesi (kompanzasyon rölesi) için
ESP32 tabanlı Modbus→MQTT gateway firmware'i. Binary Enerji'nin mevcut
ürünleri (ANL13, ANL21 güç analizörleri) ile aynı donanım deseni kullanılıyor:
ESP32 + RS-485 (MAX485 modülü) ile cihaza Modbus RTU üzerinden bağlanıp,
okunan/yazılan verileri TLS üzerinden MQTT ile `binaryenerji.com`'a taşıyor.

## Donanım notu

Bu karttaki USB-UART çipi **CH9102X** (WCH) — CP2102/CH340'tan farklı bir
sürücü gerektirir. macOS/Windows'ta "WCH CH340/CH9102" sürücüsü kurulu
değilse kart, Arduino IDE'nin Port listesinde hiç görünmez. Bu yalnızca
**flaşlama/programlama** aşamasını ilgilendirir, çalışan firmware'in
mantığını etkilemez.

## Şu an hazır olan (ANL13/ANL21'den birebir taşındı, kanıtlanmış)

- WiFi kurulumu: cihazın kendi açtığı AP + telefon uygulamasından JSON ile
  ev WiFi bilgisinin gönderilmesi (Tuya benzeri, tarayıcı/portal sayfası yok).
- MQTT + TLS (Let's Encrypt kök sertifikaları gömülü, `binaryenerji.com:8883`).
- OTA güncelleme: adres allowlist (`https://binaryenerji.com/` ile başlamalı)
  + indirilen `.bin`'in sha256 doğrulaması + başarısız/onaylanmayan güncellemede
  otomatik rollback.
- Cihaz kimliği: MAC adresinden türetilen `ga1202-xxxxxx` ID, fabrikada
  cihaza özel ayar gerekmez.
- Komut yazma altyapısı: `{"register": N, "value": M}` formatında MQTT
  komutunu ilgili Modbus register'ına yazma (fonksiyon kodu 06).
- Backend tarafında `ga1202` cihaz tipi `VALID_DEVICE_TYPES`'a eklendi
  (`power-dashboard/api.py`) — OTA firmware yükleme/dağıtım mekanizması bu
  cihaz tipi için de çalışır durumda.

## Bekleyen — GA1202'nin Modbus register haritası

Cihaza özel kısım (`ROLE VERISI / ROLE KOMUTLARI` bölümü, dosyada açıkça
işaretli) **yazılamadı** çünkü GA1202'nin gerçek Modbus register adresleri,
veri tipleri, ölçek/çarpanları ve yazılabilir komut register'ları elimde yok.
ANL21'de bu, Grup Arge'nin "sebeke-analizoru-modbus-haritasi.xlsx" dosyasından
geldi — GA1202 için aynı türden bir kaynak gerekiyor:

1. **Tercih edilen:** Grup Arge'nin GA1202 için yayınladığı Modbus haritası
   (Excel/PDF) — cihazla birlikte gelen teknik dokümantasyon.
2. **Alternatif:** cihaza bir Modbus poll aracıyla (ör. QModMaster,
   Modbus Poll) bağlanıp register'ları elle keşfetmek — daha yavaş ama
   dokümantasyon yoksa tek yol.

Muhtemelen rapor edilecek/kontrol edilecek veriler (kesin adresler haritadan
gelecek):
- Ölçülen cosφ (güç faktörü) ve/veya reaktif güç (kVAr)
- Her kademenin (kapasitör bankı adımı) o an açık/kapalı durumu
- Hedef cosφ ayarı (yazılabilir register)
- Alarm/hata durumları (aşırı gerilim, harmonik, kontaktör arızası vb.)
- Kademe anahtarlama sayacı / kademe sağlık durumu

Not: cihaz bilgisi bloğu (seri no, ürün/kart ID, versiyon — register 100-125)
ANL13/ANL21 ile aynı adreste olma ihtimaline karşı zaten koda eklendi
(`readDeviceInfo()`), ama **doğrulanmadı** — register haritası gelince ilk
test edilmesi gereken yer burası.

## MQTT topic ismi neden "powermeter" değil

Backend'deki mevcut `powermeter/+/live`, `/energy`, `/stats`, `/peaks`,
`/demand`, `/harmonics` abonelikleri güç analizörü alanlarını (`v1`, `i1`,
`p1`...) bekleyen bir veri şemasına yazıyor. GA1202'nin rapor edeceği veri
tamamen farklı bir şema (röle/kademe durumu, hedef cosφ vb.) olacağı için bu
firmware `relay/<device_id>/...` önekini kullanıyor (`live`, `status`, `cmd`,
`ota`, `wifi`, `info` — aynı sonek sözlüğü, farklı önek). Ayrıca bu, cihaz
sayısına göre faturalanan `devices` tablosuna bir kontrol rölesinin bir "güç
analizörü" gibi karışmasını da önlüyor.

**Backend'de henüz yapılmadı:** `relay/+/status`, `/cmd`, `/ota`, `/wifi`,
`/info` için yeni MQTT abonelikleri (cihaz-yönetimi kısmı, veri şemasından
bağımsız — powermeter'daki aynı handler'lar tekrar kullanılabilir) ve
`relay/+/live` için register haritası netleşince yazılacak yeni bir veri
işleme/depolama yolu. Bu, register haritası gelmeden yapılırsa muhtemelen
yeniden yazılması gerekir, o yüzden bilerek ertelendi.

## Sonraki adım

Register haritası elde edilince: `readDeviceInfo()`'nun hemen altındaki
"ROLE VERISI / ROLE KOMUTLARI" bölümüne ANL21'deki `readPowerAnalyzer()` /
`readTotals()` ile aynı desende okuma fonksiyonları eklenecek, ardından
backend'e `relay/+/...` abonelikleri ve web/iOS/Android tarafına ilgili
ekranlar eklenecek (bkz. proje genelindeki platform-parite kuralı).
