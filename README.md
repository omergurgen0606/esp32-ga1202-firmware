# ESP32-GA1202

Grup Arge **GA1202** reaktif güç kontrol rölesi (kompanzasyon rölesi) için
ESP32 tabanlı Modbus→MQTT gateway firmware'i. Binary Enerji'nin mevcut
ürünleri (ANL13, ANL21 güç analizörleri) ile aynı donanım deseni kullanılıyor:
ESP32 + RS-485 (MAX485 modülü) ile cihaza Modbus RTU üzerinden bağlanıp,
okunan/yazılan verileri TLS üzerinden MQTT ile `binaryenerji.com`'a taşıyor.

Register haritası kaynağı: Grup Arge'nin resmi
"Reaktif-Kontrol-Rolesi-RKRS-Modbus-Tablosu.pdf" dokümanı, `docs/` altında
saklanıyor. PDF'in gömülü fontu bozuk (ToUnicode CMap yok) olduğu için
düz metin araçları (pdftotext, pdfplumber) doğrudan okunamayan `(cid:N)`
kodları veya kaydırılmış karakterler veriyordu; `docs/RKRS-Modbus-Tablosu-cozulmus.txt`
bu kodların çözülmüş (glyph id + 29 = ASCII, Türkçe harfler için ayrı bir
eşleme tablosu) halidir -- Enerjiler/Ayarlar gibi henüz işlenmemiş
bölümlere bakarken PDF'i tekrar açıp çözmek yerine bu dosya kullanılabilir.

## Donanım notu

Bu karttaki USB-UART çipi **CH9102X** (WCH) — CP2102/CH340'tan farklı bir
sürücü gerektirir. macOS/Windows'ta "WCH CH340/CH9102" sürücüsü kurulu
değilse kart, Arduino IDE'nin Port listesinde hiç görünmez. Bu yalnızca
**flaşlama/programlama** aşamasını ilgilendirir, çalışan firmware'in
mantığını etkilemez.

## Şu an hazır olan

**Cihazdan bağımsız çekirdek** (ANL13/ANL21'den birebir taşındı, kanıtlanmış):
- WiFi kurulumu, MQTT+TLS, OTA güncelleme (adres allowlist + sha256 + rollback),
  cihaz kimliği, generic komut yazma (`{"register":N,"value":M}` → Modbus
  fonksiyon kodu 06).
- Backend tarafında `ga1202` cihaz tipi `VALID_DEVICE_TYPES`'a eklendi
  (`power-dashboard/api.py`) — OTA firmware dağıtımı bu cihaz tipi için de
  çalışıyor.

**Cihaza özel, register haritasından doğrulanarak yazıldı:**
- **Cihaz Bilgileri** (100-125) — ANL13/ANL21 ile birebir aynı adreste,
  doğrulandı.
- **Anlık Değerler** (10002-10124, `readRelayLive()`) — 3 fazlı gerilim/akım/
  güç/frekans/cosφ/tanφ/PF/THD, SVC durumu, jeneratör durumu, sıcaklık,
  cihaz iç besleme gerilimi, pil gerilimi, hedef cosφ (L1/L2/L3). 2 saniyede
  bir okunup `relay/<id>/live` topic'ine yayınlanıyor.
- **Kademeler** (40006-40470+, `readKademelerOzet()` + `readKademeDetaylari()`)
  — cihaz durumu (Boşta/Kurulumda/Kompanzasyonda/...), kademe sayısı,
  kademe durumları (bitfield), toplam online/kondansatör gücü, ve her
  kademe için güç (L1/L2/L3) + çalışma süresi + anahtarlama sayısı
  (`MAX_KADEME=12` ile sınırlı — cihaz 32 kademeye kadar destekliyor, gerçek
  kurulu sayı `Cihaz Kademe Sayısı` register'ından okunuyor). 10 saniyede
  bir okunup `relay/<id>/kademeler` topic'ine yayınlanıyor.
- **Yazma komutları** (9000-9041) — kod gerektirmiyor, mevcut generic
  `{"register":N,"value":M}` mekanizmasıyla zaten çalışıyor. Tam liste ve
  hangi komutun ne yaptığı `.ino` dosyasında "YAZMA KOMUTLARI" başlığı
  altında belgelendi (ortak komutlar ANL13/ANL21 ile birebir aynı numaralar;
   9024 Fabrika Ayarlarına Dön / 9022 Şifre Sıfırla / 9025 Cihaz Reset
  **yüksek riskli, UI'da çift onay gerektirmeli**).

`arduino-cli compile --fqbn esp32:esp32:esp32` ile derleme doğrulandı.

## Belirsizlikler (gerçek donanımla ilk testte doğrulanmalı)

- **"Common V1/V2/V3" ve "Ek Güç L1/L2/L3"** (10006-10016) — PDF'teki
  etiketler bu şekilde ama tam anlamları açık değil, ham değer olarak
  taşınıyor.
- PDF'te bu satırların yanında ayrıca "0: Termik Devre Dışı / 1: Termik
  Normal / 2: Termik Yüksek Sıcaklık / 3: Termik Hatası / 4: Termik Pasif /
  5: Termik Uygulanabilir Değil" şeklinde 6 değerli bir enum legend'i var,
  ama PDF→metin dönüşümünde bu legend'in TAM OLARAK hangi register'a ait
  olduğu net ayırt edilemedi (yan yana iki tablo karışmış olabilir) —
  kodda YORUMLANMADI.
- `WORDS_HIGH_FIRST` (32-bit değerlerde hangi 16-bit kelimenin önce geldiği)
  ANL13/ANL21 ile aynı varsayıldı (`true`) ama GA1202 için doğrulanmadı —
  ilk gerçek okumada değer absürt çıkarsa `false` yapılıp tekrar denenmeli.
- Modbus hızı (19200) ve slave adresi (1) ANL13/ANL21 varsayılanları — GA1202
  cihazının Ayarlar ekranındaki gerçek değerle karşılaştırılmalı.

## Bilerek ertelenen (sonraki faz)

ANL21'de izlenen aşamalı yaklaşımla aynı: önce çekirdek + en değerli veri
(Live + Kademeler) çalışır hale getirildi, aşağıdakiler istenirse ayrı bir
adımda eklenecek:
- **Enerjiler** sayfası (Wh/VArh sayaçları)
- **Anlık Tepe Değerleri** (Tüketim 11010+ / Üretim 11260+)
- **RGP** (Reaktif Güç Profili — 44xxx, alarm/olay günlüğü) ve Olay/Uyarı
  günlükleri (47xxx/48xxx/49xxx)
- **Ayarlar/Parametreler** (200-450 aralığı, W/R — kademe eşikleri, termik
  limitler, şirket adı vb. yazılabilir ayarlar)

## MQTT topic ismi neden "powermeter" değil

Backend'deki mevcut `powermeter/+/live` vb. abonelikleri güç analizörü
alanlarını (`v1`, `i1`, `p1`...) bekleyen bir şemaya yazıyor. GA1202'nin
`live` verisi kısmen örtüşse de (aynı 3-faz ölçüm bloğu) `kademeler` verisi
tamamen farklı bir şema, bu yüzden bu firmware `relay/<device_id>/...`
önekini kullanıyor (`live`, `kademeler`, `status`, `cmd`, `ota`, `wifi`,
`info`). Ayrıca bu, cihaz sayısına göre faturalanan `devices` tablosuna bir
kontrol rölesinin bir "güç analizörü" gibi karışmasını önlüyor.

**Backend'de henüz yapılmadı:** `relay/+/...` için MQTT abonelikleri, yeni
veritabanı tabloları, ve `GET` endpoint'leri. Register haritası artık net
olduğu için bu bir sonraki adım — web/iOS/Android taraflarındaki ekranlarla
birlikte, platform-parite kuralı gereği üçünde de aynı anda yapılacak.
