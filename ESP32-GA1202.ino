#include <ModbusMaster.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <Preferences.h>
#include <PubSubClient.h>
#include <HTTPClient.h>
#include <Update.h>
#include <mbedtls/sha256.h>
#include <esp_random.h>
#include <esp_mac.h>
#include <esp_ota_ops.h>

// Grup Arge GA1202 -- reaktif guc kontrol rolesi (kompanzasyon rolesi) icin
// ESP32 Modbus gateway'i. Bu dosya, ANL13/ANL21 guc analizoru gateway'leriyle
// AYNI kanitlanmis WiFi/MQTT/OTA/provisioning cekirdegini kullanir (bkz.
// ESP32-ANL21.ino) -- o kisim cihazdan bagimsizdir, sadece Modbus register
// okuma/yazma mantigi GA1202'ye ozeldir.
//
// DURUM: cekirdek (WiFi kurulumu, MQTT+TLS, OTA, cihaz kimligi, komut yazma)
// hazir ve calisir durumda. Cihaza ozel kisim (asagida ROLESI VERISI /
// ROLESI KOMUTLARI bolumleri) GA1202'nin Modbus register haritasi
// gelmeden yazilamaz -- ANL21'de bu, "sebeke-analizoru-modbus-haritasi.xlsx"
// dosyasindan geldi; GA1202 icin ayni turden bir kaynak (Grup Arge'nin
// teknik dokumani ya da cihaza bir Modbus poll araciyla baglanip
// register'lari elle kesfetme) gerekiyor. Bkz. README.md.
#define FW_VERSION "0.1.0"

#define RE_DE_PIN 4
#define RXD2 16
#define TXD2 17
#define WIFI_RESET_PIN 0 // ESP32 devkit'lerdeki BOOT tusu

// NOT: Bu karttaki USB-UART cipi CH9102X (WCH) -- CP2102/CH340'tan farkli
// surucu gerektirir (macOS/Windows'ta "WCH CH340/CH9102" surucusu kurulmali,
// yoksa kart Arduino IDE'nin Port listesinde hic gorunmez). Bu sadece
// FLASHLAMA/PROGRAMLAMA asamasini ilgilendirir, calisan firmware'in
// mantigini etkilemez.

// WiFi kesintisiz olarak bu sureden uzun surerse (WiFi.reconnect() ise yaramiyorsa)
// cihaz kendini yeniden baslatir -- bazi durumlarda WiFi yiginini sadece tam reboot kurtarir.
#define WIFI_RECONNECT_RESTART_MS (3UL * 60UL * 1000UL)

// Kurulum (AP) modundayken kayitli ag da denenmeye devam eder. Bkz. ANL21'deki
// ayni mekanizmanin notu -- bu olmadan cihaz, modem yeniden baslatildiginda
// kurulum moduna dusup ORADA KALIYORDU.
#define PROVISION_RETRY_INTERVAL_MS (45UL * 1000UL)
#define PROVISION_RETRY_WINDOW_MS   (15UL * 1000UL)

// TLS sertifikasi bu ALAN ADINA duzenlendi; IP ile baglanmak host dogrulamasini
// kirar. Broker 8883'te TLS ile dinliyor.
const char* mqtt_server = "binaryenerji.com";
const uint16_t mqtt_port = 8883;

// Let's Encrypt zincirinin kok sertifikalari (ANL21 ile birebir ayni --
// binaryenerji.com'un TLS sertifikasini dogrulamak icin tum cihazlarda
// gomulu olmasi gereken degismez deger).
static const char ISRG_ROOTS[] PROGMEM = R"CERT(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
)CERT";

// Gomulu CA'nin gercekten sertifika oldugunu DERLEME ZAMANINDA dogrula
// (bkz. ANL21'deki ayni kontrolun notu -- bu tam olarak iki kez basimiza geldi).
static_assert(sizeof(ISRG_ROOTS) > 2000,
              "Gomulu CA cok kucuk -- sertifika yerine yer tutucu metin kalmis olabilir");

// Bu cihazin 32-bit (Signed 32, 2 register) degerlerinde hangi kelimenin once
// geldigi BILINMIYOR -- Modbus haritasi elde edilince ilk gercek okumada
// deger absurt buyuk/kucuk cikarsa bunu false yapip tekrar deneyin. ANL13/ANL21'de
// de ayni belirsizlik vardi.
#define WORDS_HIGH_FIRST true

ModbusMaster node;
WiFiClientSecure espClient;
int tlsBasarisizSayaci = 0;
bool tlsDogrulamaKapali = false;
unsigned long tlsTekrarDenemeMs = 0;
#define TLS_DOGRULAMA_TEKRAR_MS (10UL * 60UL * 1000UL)
PubSubClient mqttClient(espClient);

// Dongu periyodu hedefi -- bir kontrol rolesi icin canli olcum gereksinimi
// bir guc analizorunden farkli olabilir (ornegin roleyi 5-10 saniyede bir
// yoklamak yeterli olabilir). Modbus haritasi gelene kadar ANL21 ile ayni
// deger korunuyor, gercek ihtiyaca gore ayarlanacak.
static const uint32_t LOOP_PERIYODU_MS = 2000;
static const uint32_t ASGARI_BEKLEME_MS = 200;

// Blok okuma tablolarinin tipleri. BILEREK dosyanin bu kadar basinda:
// Arduino'nun .ino on-islemcisi fonksiyon prototiplerini ilk fonksiyondan
// ONCE uretiyor, struct'lar asagida tanimli olursa prototipler "RegDef does
// not name a type" ile patliyor.
struct RegDef {
  const char *anahtar;
  uint16_t adres;    // mutlak Modbus adresi (Tepe tablosunda: base'e BAGIL)
  float olcek;       // negatif = "bu alan isaretli" (bkz. blok16Oku)
  uint8_t basamak;   // JSON'da kac ondalik basamak yazilacak
};

// Cok parcali okumalarda ayni JSON buffer'ina ekleme yapilabilsin diye
// offset/ilk durumu disaridan tasiniyor.
struct JsonYazici {
  char *buf;
  size_t bufSize;
  size_t offset;
  bool ilk;
};

// Excel/register haritasindaki "Signed 32" degerler, buffer'da 2 ardisik
// 16-bit register olarak gelir. Isaretli (negatif olabilen) 32-bit'e cevirir.
int32_t readS32(uint16_t bufIndex) {
  uint16_t a = node.getResponseBuffer(bufIndex);
  uint16_t b = node.getResponseBuffer(bufIndex + 1);
  uint16_t hi = WORDS_HIGH_FIRST ? a : b;
  uint16_t lo = WORDS_HIGH_FIRST ? b : a;
  return (int32_t)(((uint32_t)hi << 16) | lo);
}

// Her cihaz kendi MAC adresinden benzersiz bir ID uretir -- ayni firmware
// tum GA1202 birimlerine (fabrikada cihaza ozel ayar gerekmeden) yuklenebilir.
//
// Topic on eki BILEREK "relay" -- "powermeter" DEGIL. Backend'deki mevcut
// powermeter/+/live, /energy, /stats, /peaks, /demand, /harmonics wildcard'lari
// guc analizoru alanlarini (v1,i1,p1...) bekleyen bir veritabani semasina
// yaziyor; GA1202'nin rapor edecegi veri (role/kademe durumu, hedef cosfi vb.)
// bambaska bir sema. Ayni "powermeter" onekini kullanmak, cihaz sayisina gore
// FATURALANAN "devices" tablosuna bu roleyi de bir "guc analizoru" gibi
// karistirirdi -- oysa bu tamamen farkli bir urun kategorisi. status/cmd/ota/wifi/info
// gibi cihaz-yonetimi konulari (urun turunden bagimsiz) icin backend'e AYRI
// bir relay/+/... abonelik seti eklenmesi gerekiyor (bkz. README.md).
String deviceId;
String liveTopic, statusTopic, cmdTopic, otaTopic, wifiTopic, infoTopic, kademelerTopic;
String toplamTopic, tepeTuketimTopic, tepeUretimTopic;
String enerjiTuketimTopic, enerjiUretimTopic, paramTopic;
// Bir parametre yazildiktan sonra bir sonraki donguda parametreleri yeniden
// okumak icin bayrak (bkz. onMqttMessage sonu).
volatile bool paramHemenOku = false;
int wifiDegisimSonucu = 0;

// OTA guvenlik agi: yeni firmware yazildiktan hemen sonra "pending" olarak
// isaretlenir (bkz. ANL21'deki ayni mekanizmanin notu -- kotu bir OTA cihazi
// sahada "tugla"ya cevirmesin diye onaylanamazsa onceki firmware'e donulur).
Preferences otaPrefs;
bool otaPendingConfirm = false;
unsigned long otaPendingSince = 0;
#define OTA_CONFIRM_TIMEOUT_MS (90UL * 1000UL)

void setupDeviceId() {
  // esp_read_mac() donanima gomulu MAC'i dogrudan okur (efuse) -- WiFi.macAddress()
  // aksine WiFi radyosunun baslatilmis/bagli olmasina bagli degildir.
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char idBuf[20];
  snprintf(idBuf, sizeof(idBuf), "ga1202-%02x%02x%02x", mac[3], mac[4], mac[5]);
  deviceId = String(idBuf);
  liveTopic      = "relay/" + deviceId + "/live";
  statusTopic    = "relay/" + deviceId + "/status";
  cmdTopic       = "relay/" + deviceId + "/cmd";
  otaTopic       = "relay/" + deviceId + "/ota";
  wifiTopic      = "relay/" + deviceId + "/wifi";
  infoTopic      = "relay/" + deviceId + "/info";
  kademelerTopic = "relay/" + deviceId + "/kademeler";
  toplamTopic        = "relay/" + deviceId + "/toplam";
  tepeTuketimTopic   = "relay/" + deviceId + "/tepe/tuketim";
  tepeUretimTopic    = "relay/" + deviceId + "/tepe/uretim";
  enerjiTuketimTopic = "relay/" + deviceId + "/enerji/tuketim";
  enerjiUretimTopic  = "relay/" + deviceId + "/enerji/uretim";
  paramTopic         = "relay/" + deviceId + "/parametreler";
}

void preTransmission()  { digitalWrite(RE_DE_PIN, HIGH); }
void postTransmission() { digitalWrite(RE_DE_PIN, LOW); }

// RS-485 hattinin toparlanmasini beklerken MQTT'yi de besler (bkz. ANL21'deki
// ayni fonksiyonun notu -- mqttClient.loop() duzenli cagrilmazsa broker
// keepalive asimindan baglantiyi dusurur).
static void hatBekle(uint32_t ms) {
  uint32_t bas = millis();
  do {
    mqttClient.loop();
    delay(5);
  } while (millis() - bas < ms);
}

// ==================== Cihaz Bilgileri (sadece aciliste bir kez) ====================
// Grup Arge'nin resmi Modbus tablosuyla (Reaktif-Kontrol-Rolesi-RKRS-Modbus-
// Tablosu.pdf, sayfa 51) DOGRULANDI: ANL13/ANL21 ile BIREBIR AYNI adreste
// (100-125, "Ozel" sayfasi).
struct DeviceInfo {
  int32_t seriNo, urunId, kartId, sistemVersiyon, ulkeKodu, firmaKodu;
  int32_t beslemeTipi, ekranTipi, keyboardTipi, kutuTipi, klemensTipi, connections, storage;
};
DeviceInfo deviceInfo;
bool deviceInfoOk = false;
bool deviceInfoPublished = false;

bool readDeviceInfo() {
  uint8_t result = node.readHoldingRegisters(100, 26);
  if (result != node.ku8MBSuccess) return false;
  #define I(off) readS32(off)
  deviceInfo.seriNo         = I(0);
  deviceInfo.urunId         = I(2);
  deviceInfo.kartId         = I(4);
  deviceInfo.sistemVersiyon = I(6);
  deviceInfo.ulkeKodu       = I(8);
  deviceInfo.firmaKodu      = I(10);
  deviceInfo.beslemeTipi    = I(12);
  deviceInfo.ekranTipi      = I(14);
  deviceInfo.keyboardTipi   = I(16);
  deviceInfo.kutuTipi       = I(18);
  deviceInfo.klemensTipi    = I(20);
  deviceInfo.connections    = I(22);
  deviceInfo.storage        = I(24);
  #undef I
  return true;
}

// ==================== ANLIK DEGERLER (2sn) ====================
// Kaynak: Reaktif-Kontrol-Rolesi-RKRS-Modbus-Tablosu.pdf, "Anlik Degerler"
// sayfasi, 10002-10124 araligi (62 alan x 2 register = 124 register).
// ModbusMaster'in 64 register'lik sabit tampon siniri (ANL21'de de ayni
// sinira takilmisti) yuzunden iki parcaya bolundu: ilk parca tam 64 register
// (10002-10064, "1. Faz Akim"a kadar), ikinci parca kalan 60 register.
//
// BELIRSIZLIKLER (ilk gercek okumada dogrulanmali):
//   - "Common V1/V2/V3" ve "Ek Guc L1/L2/L3" (10006-10016) etiketleri PDF'te
//     bu sekilde geciyor ama tam anlamlari acik degil -- ham deger olarak
//     tasiniyor, yorumlanmiyor.
//   - PDF'te bu satirlarin yaninda ayrica "0: Termik Devre Disi / 1: Termik
//     Normal / 2: Termik Yuksek Sicaklik / 3: Termik Hatasi / 4: Termik
//     Pasif / 5: Termik Uygulanabilir Degil" seklinde bir 6 degerli enum
//     legend'i var, ama PDF'teki tablo duzeni bu legend'in TAM OLARAK hangi
//     register'a ait oldugunu net ayirt ettirmiyor (yan yana iki tablo
//     PDF->metin donusumunde birbirine karismis olabilir). Bu yuzden bu enum
//     kodda YORUMLANMADI, sadece bu yorumda not dusuldu.
#define LIVE_BLOCK1_START 10002
#define LIVE_BLOCK1_COUNT 32  // 10002..10064, 32 alan x 2 = 64 register
#define LIVE_BLOCK2_START 10066
#define LIVE_BLOCK2_COUNT 30  // 10066..10124, 30 alan x 2 = 60 register

struct RelayLiveData {
  // --- Blok 1 ---
  int32_t remote1, svcDurumBit;
  int32_t commonV1, commonV2, commonV3;   // bkz. yukaridaki belirsizlik notu
  float ekGucL1, ekGucL2, ekGucL3;        // VAr, carpan 1
  float hedefCosL1, hedefCosL2, hedefCosL3;
  int32_t baglantiDetayi;                 // index (0:Off 1:On -- Kademe Ortak Kontrolu ile ayni Table-1 mi net degil)
  int32_t akimGucHassasiyeti;
  int32_t akimTrafoOrani;                 // index
  float nominalHatGerilimi, nominalOlcmeGerilimi; // V
  int32_t jeneratorDurumu;                // 0:Off 1:On
  float sicaklik;                         // Santigrat, carpan 0.1
  float cihazIcBeslemeGerilim;            // Volt
  float pilGerilimi;                      // Volt, carpan 0.001
  int32_t tarihSaatUtc;                   // Unix timestamp
  int32_t seriNumarasi;
  // --- Blok 2 ---
  float vLN1, vLN2, vLN3, vN;             // Volt, carpan 0.1
  float vL12, vL23, vL31;                 // Volt, carpan 0.1
  float i1, i2, i3;                       // Amper, carpan 0.001
  float p1, p2, p3;                       // Watt
  float q1, q2, q3;                       // VAr
  float s1, s2, s3;                       // VA
  float f1, f2, f3;                       // Hz, carpan 0.01
  float cos1, cos2, cos3;                 // carpan 0.001
  float tan1, tan2, tan3;                 // carpan 0.001
  float pf1, pf2, pf3;                    // carpan 0.001
  float thdv1, thdv2, thdv3;              // %, carpan 0.1
  float thdi1, thdi2, thdi3;              // %, carpan 0.1
};
RelayLiveData live;

bool readRelayLive() {
  uint8_t result = node.readHoldingRegisters(LIVE_BLOCK1_START, LIVE_BLOCK1_COUNT * 2);
  if (result != node.ku8MBSuccess) return false;
  #define B1(off) readS32(off)
  live.remote1      = B1(0);
  live.svcDurumBit  = B1(2);
  live.commonV1     = B1(4);
  live.commonV2     = B1(6);
  live.commonV3     = B1(8);
  live.ekGucL1      = B1(10) * 1.0;
  live.ekGucL2      = B1(12) * 1.0;
  live.ekGucL3      = B1(14) * 1.0;
  live.hedefCosL1   = B1(16) * 0.001;
  live.hedefCosL2   = B1(18) * 0.001;
  live.hedefCosL3   = B1(20) * 0.001;
  live.baglantiDetayi     = B1(22);
  live.akimGucHassasiyeti = B1(24);
  live.akimTrafoOrani     = B1(26);
  live.nominalHatGerilimi   = B1(28) * 1.0;
  live.nominalOlcmeGerilimi = B1(30) * 1.0;
  live.jeneratorDurumu = B1(32);
  live.sicaklik = B1(34) * 0.1;
  // B1(36),(38) = Dummy,Dummy (10038,10040)
  live.cihazIcBeslemeGerilim = B1(40) * 1.0;
  live.pilGerilimi = B1(42) * 0.001;
  live.tarihSaatUtc = B1(44);
  live.seriNumarasi = B1(46);
  live.vLN1 = B1(48) * 0.1;
  live.vLN2 = B1(50) * 0.1;
  live.vLN3 = B1(52) * 0.1;
  live.vN   = B1(54) * 0.1;
  live.vL12 = B1(56) * 0.1;
  live.vL23 = B1(58) * 0.1;
  live.vL31 = B1(60) * 0.1;
  live.i1   = B1(62) * 0.001;
  #undef B1

  delay(30);
  result = node.readHoldingRegisters(LIVE_BLOCK2_START, LIVE_BLOCK2_COUNT * 2);
  if (result != node.ku8MBSuccess) return false;
  #define B2(off) readS32(off)
  live.i2 = B2(0) * 0.001;
  live.i3 = B2(2) * 0.001;
  live.p1 = B2(4) * 1.0;
  live.p2 = B2(6) * 1.0;
  live.p3 = B2(8) * 1.0;
  live.q1 = B2(10) * 1.0;
  live.q2 = B2(12) * 1.0;
  live.q3 = B2(14) * 1.0;
  live.s1 = B2(16) * 1.0;
  live.s2 = B2(18) * 1.0;
  live.s3 = B2(20) * 1.0;
  live.f1 = B2(22) * 0.01;
  live.f2 = B2(24) * 0.01;
  live.f3 = B2(26) * 0.01;
  live.cos1 = B2(28) * 0.001;
  live.cos2 = B2(30) * 0.001;
  live.cos3 = B2(32) * 0.001;
  live.tan1 = B2(34) * 0.001;
  live.tan2 = B2(36) * 0.001;
  live.tan3 = B2(38) * 0.001;
  live.pf1 = B2(40) * 0.001;
  live.pf2 = B2(42) * 0.001;
  live.pf3 = B2(44) * 0.001;
  live.thdv1 = B2(46) * 0.1;
  live.thdv2 = B2(48) * 0.1;
  live.thdv3 = B2(50) * 0.1;
  live.thdi1 = B2(52) * 0.1;
  live.thdi2 = B2(54) * 0.1;
  live.thdi3 = B2(56) * 0.1;
  #undef B2
  return true;
}

void buildLiveJson(char *buf, size_t bufSize) {
  snprintf(buf, bufSize,
    "{\"svc_durum\":%ld,\"jenerator_durumu\":%ld,\"sicaklik\":%.1f,"
    "\"cihaz_ic_besleme\":%.0f,\"pil_gerilimi\":%.3f,"
    "\"hedef_cos_l1\":%.3f,\"hedef_cos_l2\":%.3f,\"hedef_cos_l3\":%.3f,"
    "\"v1\":%.1f,\"i1\":%.3f,\"p1\":%.0f,\"q1\":%.0f,\"s1\":%.0f,\"f1\":%.2f,\"cos1\":%.3f,\"tan1\":%.3f,\"pf1\":%.3f,\"thdv1\":%.1f,\"thdi1\":%.1f,"
    "\"v2\":%.1f,\"i2\":%.3f,\"p2\":%.0f,\"q2\":%.0f,\"s2\":%.0f,\"f2\":%.2f,\"cos2\":%.3f,\"tan2\":%.3f,\"pf2\":%.3f,\"thdv2\":%.1f,\"thdi2\":%.1f,"
    "\"v3\":%.1f,\"i3\":%.3f,\"p3\":%.0f,\"q3\":%.0f,\"s3\":%.0f,\"f3\":%.2f,\"cos3\":%.3f,\"tan3\":%.3f,\"pf3\":%.3f,\"thdv3\":%.1f,\"thdi3\":%.1f,"
    "\"vN\":%.1f,\"iN\":0,\"vL12\":%.1f,\"vL23\":%.1f,\"vL31\":%.1f}",
    (long)live.svcDurumBit, (long)live.jeneratorDurumu, live.sicaklik,
    live.cihazIcBeslemeGerilim, live.pilGerilimi,
    live.hedefCosL1, live.hedefCosL2, live.hedefCosL3,
    live.vLN1, live.i1, live.p1, live.q1, live.s1, live.f1, live.cos1, live.tan1, live.pf1, live.thdv1, live.thdi1,
    live.vLN2, live.i2, live.p2, live.q2, live.s2, live.f2, live.cos2, live.tan2, live.pf2, live.thdv2, live.thdi2,
    live.vLN3, live.i3, live.p3, live.q3, live.s3, live.f3, live.cos3, live.tan3, live.pf3, live.thdv3, live.thdi3,
    live.vN, live.vL12, live.vL23, live.vL31);
}

// ==================== KADEMELER (10sn) ====================
// Kaynak: "Kademeler" sayfasi, 40000-40470+ araligi. Bir kademe (kapasitor
// banki adimi) basina 5 alan x 2 register = 10 register, 1. kademe 40160'ta
// basliyor, her kademe +10 register (2. kademe 40170, 3. kademe 40180, ...).
// PDF'te 32. kademeye kadar (40470) yer var -- bu, cihazin DESTEKLEDIGI ust
// sinir, gercek kurulu kademe sayisi "Cihaz Kademe Sayisi" (40128) ile
// okunuyor ve sadece o kadari okunuyor (MAX_KADEME ile sinirli, guvenlik
// icin -- cihaz bozuk/asiri buyuk bir sayi donerse sonsuz okumaya girmesin).
#define MAX_KADEME 12
#define KADEME_BASE 40160
#define KADEME_STRIDE 10 // register cinsinden (5 alan x 2)

struct KademeData {
  float gucL1, gucL2, gucL3; // VAr
  int32_t calismaSuresi;     // Saniye
  int32_t anahtarlamaSayisi;
};

struct KademelerData {
  int32_t cihazDurumu;        // Table-1: 0 Bosta,1 ServisDisi,2 Kurulumda,3 Kompanzasyonda,4 Kademe Ogrenmede,5 Uygulanamaz
  int32_t kademeSayisi;
  int32_t kademeDurumlari;    // bitfield -- her bit bir kademenin acik/kapali durumu (PDF'te bit sirasi ayrica dokumante degil)
  int32_t kademeOgrenmeDurumu;
  int32_t hataliKademeDurumu;
  int32_t kademeIptalDurumu;
  int32_t kademeManuelAuto;
  float toplamOnlineGucL1, toplamOnlineGucL2, toplamOnlineGucL3; // Watt
  float toplamKondansatorGucL1, toplamKondansatorGucL2, toplamKondansatorGucL3; // VAr
  int32_t kademeCount; // gercekten okunan kademe sayisi (min(kademeSayisi, MAX_KADEME))
  KademeData kademe[MAX_KADEME];
};
KademelerData kademeler;

bool readKademelerOzet() {
  // Cihaz Durumu (40006) + Toplam Online Kademe Gucu (40014-40018) + Toplam
  // Kondansator Gucu (40026-40030) -- tek okumada sigmiyor (40006'dan
  // 40030'a 25 register, ama araya "Dummy" degil gercek baska alanlar
  // giriyor: 40020-24 Toplam Islerme Yuk Gucu). Tek seferde 40006-40030
  // arasi (13 alan x 2 = 26 register) okunup gerekenler cikartiliyor.
  uint8_t result = node.readHoldingRegisters(40006, 26);
  if (result != node.ku8MBSuccess) return false;
  #define K(off) readS32(off)
  kademeler.cihazDurumu = K(0); // 40006
  kademeler.toplamOnlineGucL1 = K(8) * 1.0;  // 40014
  kademeler.toplamOnlineGucL2 = K(10) * 1.0; // 40016
  kademeler.toplamOnlineGucL3 = K(12) * 1.0; // 40018
  // 40020-24 Toplam Islerme Yuk Gucu -- v1'de okunmuyor (dusuk oncelik)
  kademeler.toplamKondansatorGucL1 = K(20) * 1.0; // 40026
  kademeler.toplamKondansatorGucL2 = K(22) * 1.0; // 40028
  kademeler.toplamKondansatorGucL3 = K(24) * 1.0; // 40030
  #undef K

  delay(30);
  // Kademe Sayisi (40128) .. Kademe Manuel/Auto (40138): 6 alan x 2 = 12 register
  result = node.readHoldingRegisters(40128, 12);
  if (result != node.ku8MBSuccess) return false;
  #define K2(off) readS32(off)
  kademeler.kademeSayisi        = K2(0); // 40128
  kademeler.kademeDurumlari     = K2(2); // 40130
  kademeler.kademeOgrenmeDurumu = K2(4); // 40132
  kademeler.hataliKademeDurumu  = K2(6); // 40134
  kademeler.kademeIptalDurumu   = K2(8); // 40136
  kademeler.kademeManuelAuto    = K2(10); // 40138
  #undef K2

  kademeler.kademeCount = kademeler.kademeSayisi;
  if (kademeler.kademeCount < 0) kademeler.kademeCount = 0;
  if (kademeler.kademeCount > MAX_KADEME) kademeler.kademeCount = MAX_KADEME;
  return true;
}

bool readKademeDetaylari() {
  if (kademeler.kademeCount <= 0) return true; // okunacak kademe yok, hata degil
  uint16_t registerCount = kademeler.kademeCount * KADEME_STRIDE;
  // ModbusMaster 64 register siniri: MAX_KADEME=12 -> 120 register, sinira
  // takilir. Bu yuzden 6'sar kademelik (60 register) iki parcaya bolunuyor.
  uint16_t okunan = 0;
  while (okunan < kademeler.kademeCount) {
    uint16_t buParcaKademe = (kademeler.kademeCount - okunan > 6) ? 6 : (kademeler.kademeCount - okunan);
    uint16_t adres = KADEME_BASE + okunan * KADEME_STRIDE;
    uint8_t result = node.readHoldingRegisters(adres, buParcaKademe * KADEME_STRIDE);
    if (result != node.ku8MBSuccess) return false;
    for (uint16_t i = 0; i < buParcaKademe; i++) {
      uint16_t off = i * KADEME_STRIDE;
      KademeData &k = kademeler.kademe[okunan + i];
      k.gucL1 = readS32(off) * 1.0;
      k.gucL2 = readS32(off + 2) * 1.0;
      k.gucL3 = readS32(off + 4) * 1.0;
      k.calismaSuresi = readS32(off + 6);
      k.anahtarlamaSayisi = readS32(off + 8);
    }
    okunan += buParcaKademe;
    if (okunan < kademeler.kademeCount) delay(30);
  }
  return true;
}

void buildKademelerJson(char *buf, size_t bufSize) {
  size_t offset = snprintf(buf, bufSize,
    "{\"cihaz_durumu\":%ld,\"kademe_sayisi\":%ld,\"kademe_durumlari\":%ld,"
    "\"kademe_ogrenme_durumu\":%ld,\"hatali_kademe_durumu\":%ld,"
    "\"kademe_iptal_durumu\":%ld,\"kademe_manuel_auto\":%ld,"
    "\"toplam_online_guc_l1\":%.0f,\"toplam_online_guc_l2\":%.0f,\"toplam_online_guc_l3\":%.0f,"
    "\"toplam_kondansator_guc_l1\":%.0f,\"toplam_kondansator_guc_l2\":%.0f,\"toplam_kondansator_guc_l3\":%.0f,"
    "\"kademeler\":[",
    (long)kademeler.cihazDurumu, (long)kademeler.kademeSayisi, (long)kademeler.kademeDurumlari,
    (long)kademeler.kademeOgrenmeDurumu, (long)kademeler.hataliKademeDurumu,
    (long)kademeler.kademeIptalDurumu, (long)kademeler.kademeManuelAuto,
    kademeler.toplamOnlineGucL1, kademeler.toplamOnlineGucL2, kademeler.toplamOnlineGucL3,
    kademeler.toplamKondansatorGucL1, kademeler.toplamKondansatorGucL2, kademeler.toplamKondansatorGucL3);
  for (int i = 0; i < kademeler.kademeCount; i++) {
    KademeData &k = kademeler.kademe[i];
    offset += snprintf(buf + offset, bufSize - offset,
      "%s{\"guc_l1\":%.0f,\"guc_l2\":%.0f,\"guc_l3\":%.0f,\"calisma_suresi\":%ld,\"anahtarlama_sayisi\":%ld}",
      i > 0 ? "," : "", k.gucL1, k.gucL2, k.gucL3, (long)k.calismaSuresi, (long)k.anahtarlamaSayisi);
  }
  snprintf(buf + offset, bufSize - offset, "]}");
}

// ==================== TABLO GUDUMLU BLOK OKUMA ====================
// Register haritasinin geri kalani (Toplam/Ortalama, Tepe Degerleri,
// Enerjiler, Parametreler) yuzlerce alan iceriyor. Her birini ayri struct
// alani + elle yazilmis snprintf satiri yapmak ~800 satir kod ve her
// satirda bir yazim hatasi riski demekti. Bunun yerine her blok bir
// {anahtar, adres, olcek} tablosu; tek bir generic okuyucu bloklari
// okuyup JSON'a ceviriyor. Yeni bir alan eklemek tek satir.
static void jsonBasla(JsonYazici &y, char *buf, size_t bufSize) {
  y.buf = buf; y.bufSize = bufSize; y.offset = 0; y.ilk = true;
  if (bufSize > 1) { buf[0] = '{'; y.offset = 1; buf[1] = '\0'; }
}

static void jsonBitir(JsonYazici &y) {
  if (y.offset + 2 < y.bufSize) {
    y.buf[y.offset++] = '}';
    y.buf[y.offset] = '\0';
  }
}

// 32-bit (int32, 2 register) bir blogu okuyup tablodaki alanlari JSON'a ekler.
// Tablo TUM blogun alanlarini icerebilir; sadece [basAdres, basAdres+regSayisi)
// araligina dusenler bu cagrida yazilir, digerleri sonraki parcada.
static bool blok32Oku(uint16_t basAdres, uint16_t regSayisi,
                      const RegDef *tanimlar, size_t tanimSayisi, JsonYazici &y) {
  uint8_t sonuc = node.readHoldingRegisters(basAdres, regSayisi);
  if (sonuc != node.ku8MBSuccess) return false;
  for (size_t i = 0; i < tanimSayisi; i++) {
    const RegDef &d = tanimlar[i];
    if (d.adres < basAdres) continue;
    uint16_t off = d.adres - basAdres;
    if (off + 1 >= regSayisi) continue;
    float deger = readS32(off) * d.olcek;
    y.offset += snprintf(y.buf + y.offset, y.bufSize - y.offset,
                         "%s\"%s\":%.*f", y.ilk ? "" : ",", d.anahtar, d.basamak, deger);
    y.ilk = false;
  }
  return true;
}

// 16-bit (Uint16, tek register) blok -- Parametreler sayfasi bu tipte.
static bool blok16Oku(uint16_t basAdres, uint16_t regSayisi,
                      const RegDef *tanimlar, size_t tanimSayisi, JsonYazici &y) {
  uint8_t sonuc = node.readHoldingRegisters(basAdres, regSayisi);
  if (sonuc != node.ku8MBSuccess) return false;
  for (size_t i = 0; i < tanimSayisi; i++) {
    const RegDef &d = tanimlar[i];
    if (d.adres < basAdres) continue;
    uint16_t off = d.adres - basAdres;
    if (off >= regSayisi) continue;
    // Zaman Dilimi (249) gibi birkac alan isaretli; 32768'den buyuk ham
    // degeri negatife ceviriyoruz ki -12..+12 araligi dogru gozuksun.
    int32_t ham = (int32_t)node.getResponseBuffer(off);
    if (d.olcek < 0) { if (ham > 32767) ham -= 65536; }
    float olcek = d.olcek < 0 ? -d.olcek : d.olcek;
    y.offset += snprintf(y.buf + y.offset, y.bufSize - y.offset,
                         "%s\"%s\":%.*f", y.ilk ? "" : ",", d.anahtar, d.basamak, ham * olcek);
    y.ilk = false;
  }
  return true;
}

// ==================== TOPLAM / ORTALAMA (10410-10500) ====================
// Kaynak: "Anlik Toplam Ve Ortalama Degerler" sayfasi.
static const RegDef TOPLAM_REGS[] = {
  {"p_toplam_tuketim", 10410, 1, 0}, {"q_toplam_tuketim", 10412, 1, 0},
  {"ql_toplam_tuketim", 10414, 1, 0}, {"qc_toplam_tuketim", 10416, 1, 0},
  {"s_toplam_tuketim", 10418, 1, 0},
  {"p_toplam_uretim", 10430, 1, 0}, {"q_toplam_uretim", 10432, 1, 0},
  {"ql_toplam_uretim", 10434, 1, 0}, {"qc_toplam_uretim", 10436, 1, 0},
  {"s_toplam_uretim", 10438, 1, 0},
  {"i_ort_tuketim", 10452, 1, 0}, {"p_ort_tuketim", 10454, 1, 0},
  {"cos_ort_tuketim", 10456, 0.001, 3}, {"tan_ort_tuketim", 10458, 0.001, 3},
  {"pf_ort_tuketim", 10460, 0.001, 3},
  {"i_ort_uretim", 10472, 1, 0}, {"p_ort_uretim", 10474, 1, 0},
  {"cos_ort_uretim", 10476, 0.001, 3}, {"tan_ort_uretim", 10478, 0.001, 3},
  {"pf_ort_uretim", 10480, 0.001, 3},
  {"v_ort_ln", 10492, 0.1, 1}, {"v_ort_ll", 10494, 0.1, 1},
  {"f_ort", 10496, 0.01, 2}, {"thdi_ort", 10498, 0.1, 1}, {"thdv_ort", 10500, 0.1, 1},
};

bool readToplamJson(char *buf, size_t bufSize) {
  JsonYazici y; jsonBasla(y, buf, bufSize);
  const size_t n = sizeof(TOPLAM_REGS) / sizeof(TOPLAM_REGS[0]);
  // ModbusMaster 64 register siniri -- iki parca.
  if (!blok32Oku(10410, 64, TOPLAM_REGS, n, y)) return false;
  hatBekle(30);
  if (!blok32Oku(10474, 28, TOPLAM_REGS, n, y)) return false;
  jsonBitir(y);
  return true;
}

// ==================== TEPE DEGERLERI (Min/Max) ====================
// Tuketim blogu 11010'da, Uretim blogu 11260'ta basliyor ve IC DUZENLERI
// BIREBIR AYNI (THDV her ikisinde de base+90, frekans base+126). Bu yuzden
// tablo BAGIL offset tutuyor, tek tablo iki blogu da okuyor.
static const RegDef TEPE_REGS[] = {
  {"v_ln_min_1", 0, 0.1, 1}, {"v_ln_min_2", 2, 0.1, 1}, {"v_ln_min_3", 4, 0.1, 1},
  {"v_n_min", 6, 0.1, 1},
  {"v_ln_max_1", 8, 0.1, 1}, {"v_ln_max_2", 10, 0.1, 1}, {"v_ln_max_3", 12, 0.1, 1},
  {"v_n_max", 14, 0.1, 1},
  {"v_ll_min_12", 16, 0.1, 1}, {"v_ll_min_23", 18, 0.1, 1}, {"v_ll_min_31", 20, 0.1, 1},
  {"v_ll_max_12", 22, 0.1, 1}, {"v_ll_max_23", 24, 0.1, 1}, {"v_ll_max_31", 26, 0.1, 1},
  {"i_min_1", 28, 1, 0}, {"i_min_2", 30, 1, 0}, {"i_min_3", 32, 1, 0}, {"i_n_min", 34, 1, 0},
  {"i_max_1", 36, 1, 0}, {"i_max_2", 38, 1, 0}, {"i_max_3", 40, 1, 0}, {"i_n_max", 42, 1, 0},
  {"p_min_1", 44, 1, 0}, {"p_min_2", 46, 1, 0}, {"p_min_3", 48, 1, 0},
  {"p_max_1", 50, 1, 0}, {"p_max_2", 52, 1, 0}, {"p_max_3", 54, 1, 0},
  {"q_min_1", 56, 1, 0}, {"q_min_2", 58, 1, 0}, {"q_min_3", 60, 1, 0},
  {"q_max_1", 62, 1, 0}, {"q_max_2", 64, 1, 0}, {"q_max_3", 66, 1, 0},
  {"s_min_1", 68, 1, 0}, {"s_min_2", 70, 1, 0}, {"s_min_3", 72, 1, 0},
  {"s_max_1", 74, 1, 0}, {"s_max_2", 76, 1, 0}, {"s_max_3", 78, 1, 0},
  {"thdv_min_1", 90, 0.1, 1}, {"thdv_min_2", 92, 0.1, 1}, {"thdv_min_3", 94, 0.1, 1},
  {"thdv_max_1", 96, 0.1, 1}, {"thdv_max_2", 98, 0.1, 1}, {"thdv_max_3", 100, 0.1, 1},
  {"thdi_min_1", 102, 0.1, 1}, {"thdi_min_2", 104, 0.1, 1}, {"thdi_min_3", 106, 0.1, 1},
  {"thdi_max_1", 108, 0.1, 1}, {"thdi_max_2", 110, 0.1, 1}, {"thdi_max_3", 112, 0.1, 1},
  {"f_min", 126, 0.01, 2}, {"f_max", 128, 0.01, 2},
  {"v_dengesizlik_min", 130, 0.1, 1}, {"v_dengesizlik_max", 132, 0.1, 1},
  {"i_dengesizlik_min", 134, 0.1, 1}, {"i_dengesizlik_max", 136, 0.1, 1},
};

// Bagil tabloyu mutlak adrese cevirerek okuyor (gecici tablo yerine offset
// kaydirmasiyla: tablo zaten bagil, blok32Oku'ya bagil "basAdres" veriliyor).
bool readTepeJson(uint16_t base, char *buf, size_t bufSize) {
  JsonYazici y; jsonBasla(y, buf, bufSize);
  const size_t n = sizeof(TEPE_REGS) / sizeof(TEPE_REGS[0]);
  // Tablo bagil oldugu icin blok32Oku'ya da bagil basAdres veriyoruz; gercek
  // Modbus adresi base + bagil.
  struct { uint16_t bagil; uint16_t adet; } parcalar[] = {{0, 64}, {64, 64}, {128, 12}};
  for (auto &p : parcalar) {
    uint8_t sonuc = node.readHoldingRegisters(base + p.bagil, p.adet);
    if (sonuc != node.ku8MBSuccess) return false;
    for (size_t i = 0; i < n; i++) {
      const RegDef &d = TEPE_REGS[i];
      if (d.adres < p.bagil) continue;
      uint16_t off = d.adres - p.bagil;
      if (off + 1 >= p.adet) continue;
      y.offset += snprintf(y.buf + y.offset, y.bufSize - y.offset,
                           "%s\"%s\":%.*f", y.ilk ? "" : ",", d.anahtar, d.basamak,
                           readS32(off) * d.olcek);
      y.ilk = false;
    }
    hatBekle(30);
  }
  jsonBitir(y);
  return true;
}

// ==================== ENERJILER (uint64) ====================
// Kaynak: "Enerji Degerleri (Tuketim/Uretim)" sayfalari. Bu blok int32 DEGIL,
// uint64: her alan 4 register. Sayaclar kWh/kVARh cinsinden, carpan 1.
struct EnerjiAlan { const char *anahtar; uint16_t bagil; };
static const EnerjiAlan ENERJI_ALANLARI[] = {
  {"aktif_toplam", 0}, {"enduktif_toplam", 4}, {"kapasitif_toplam", 8},
  {"aktif_l1", 12}, {"aktif_l2", 16}, {"aktif_l3", 20},
  {"enduktif_l1", 24}, {"enduktif_l2", 28}, {"enduktif_l3", 32},
  {"kapasitif_l1", 36}, {"kapasitif_l2", 40}, {"kapasitif_l3", 44},
};

// uint64: 4 ardisik register. WORDS_HIGH_FIRST duzeni int32'dekiyle ayni
// mantikta, kelime ciftleri sirasiyla en anlamliden en az anlamliya.
static double readU64(uint16_t off) {
  uint64_t v = 0;
  for (int i = 0; i < 4; i++) {
    uint16_t w = node.getResponseBuffer(WORDS_HIGH_FIRST ? off + i : off + 3 - i);
    v = (v << 16) | w;
  }
  return (double)v;
}

bool readEnerjiJson(uint16_t base, char *buf, size_t bufSize) {
  JsonYazici y; jsonBasla(y, buf, bufSize);
  uint8_t sonuc = node.readHoldingRegisters(base, 48);
  if (sonuc != node.ku8MBSuccess) return false;
  for (auto &a : ENERJI_ALANLARI) {
    y.offset += snprintf(y.buf + y.offset, y.bufSize - y.offset,
                         "%s\"%s\":%.0f", y.ilk ? "" : ",", a.anahtar, readU64(a.bagil));
    y.ilk = false;
  }
  jsonBitir(y);
  return true;
}

// ==================== PARAMETRELER (200-429, Uint16, cogu W/R) ====================
// Kaynak: "Parametre" sayfalari. Cihazin TUM ayarlari burada. Sirket Adi_1..20
// (320-339) bilerek disarida: 20 adet ham karakter kodu, sayisal olarak
// anlamsiz. Negatif olcek "bu alan isaretli" demek (bkz. blok16Oku).
static const RegDef PARAM_REGS[] = {
  {"parametre_versiyonu", 200, 1, 0}, {"calisma_suresi", 201, 1, 0},
  {"reset_durumu", 202, 1, 0}, {"power_down_counter", 203, 1, 0},
  {"modbus_adresi", 206, 1, 0}, {"modbus_hizi", 210, 1, 0},
  {"okuma_koruma_biti", 214, 1, 0}, {"yazma_koruma_biti", 215, 1, 0},
  {"okuma_sifresi_onay", 216, 1, 0}, {"yazma_sifresi_onay", 217, 1, 0},
  {"akim_trafo_orani", 221, 1, 0}, {"hat_voltaji", 222, 1, 0},
  {"olcum_voltaji", 223, 1, 0}, {"demand_periyodu", 226, 1, 0},
  {"modbus_akim_hassasiyeti", 227, 1, 0}, {"enerji_periyodu", 228, 1, 0},
  {"reset_bilinmeyen", 240, 1, 0}, {"reset_power_on", 241, 1, 0},
  {"reset_brown_out", 242, 1, 0}, {"reset_watchdog", 243, 1, 0},
  {"reset_software", 244, 1, 0}, {"reset_mclr", 245, 1, 0},
  {"reset_option_byte", 246, 1, 0}, {"reset_v18_power", 247, 1, 0},
  {"zaman_dilimi", 249, -1, 0},
  {"ekran_ornek_sayisi", 252, 1, 0}, {"ekran_yuzdelik_fark", 253, 1, 0},
  {"ekran_tazeleme_araligi", 254, 1, 0}, {"ekran_koruyucu", 256, 1, 0},
  {"ekran_koruyucu_bekleme", 257, 1, 0}, {"ekran_parlaklik", 258, 1, 0},
  {"dil", 260, 1, 0}, {"erisim_seviyesi", 261, 1, 0},
  {"erisim_kontrol", 262, 1, 0},
  {"harmonik_profili", 265, 1, 0}, {"harmonik_limiti", 266, 1, 0},
  {"harmonik_analizi", 267, 1, 0},
  {"rgp_guc_cozunurlugu", 316, 1, 0}, {"rgp_maksimum_fark", 317, 1, 0},
  {"rgp_yuzdesi", 318, 1, 0},
  {"asiri_gerilim_koruma", 341, 1, 0}, {"dusuk_gerilim_koruma", 342, 1, 0},
  {"asiri_harmonik_koruma", 343, 1, 0}, {"asiri_sicaklik_koruma", 344, 1, 0},
  {"dusuk_gerilim_degeri", 345, 1, 0}, {"asiri_harmonik_degeri", 347, 1, 0},
  {"asiri_sicaklik_degeri", 348, 1, 0},
  {"ozel_ct_orani_l1", 350, 1, 0}, {"ozel_ct_orani_l2", 351, 1, 0},
  {"ozel_ct_orani_l3", 352, 1, 0},
  {"jenerator", 353, 1, 0}, {"kademe_desarj_suresi", 354, 1, 0},
  {"akim_yonu_eslesme", 356, 1, 0},
  {"enduktif_limit", 357, 1, 0}, {"kapasitif_limit", 358, 1, 0},
  {"histerisis_enduktif", 359, 1, 0}, {"histerisis_kapasitif", 360, 1, 0},
  {"histerisis_normal", 361, 1, 0},
  {"enduktif_cevap_suresi", 362, 1, 0}, {"kapasitif_cevap_suresi", 363, 1, 0},
  {"normal_cevap_suresi", 364, 1, 0},
  {"kademe_ortak_kontrol", 365, 1, 0},
  {"hedef_cos_hat", 366, -1, 0}, {"hedef_cos_jenerator", 367, -1, 0},
  {"ek_guc_suresi", 368, 1, 0}, {"ek_reaktif_guc_3faz", 369, -1, 0},
  {"ek_reaktif_guc_l1", 370, -1, 0}, {"ek_reaktif_guc_l2", 371, -1, 0},
  {"ek_reaktif_guc_l3", 372, -1, 0},
  {"aktif_svc_orani", 378, 1, 0}, {"normal_svc_yuzdesi", 379, 1, 0},
  {"reaktif_svc_yuzdesi", 380, 1, 0}, {"termik_kontrol", 381, 1, 0},
  {"kademe_ortak1_tipi", 383, 1, 0}, {"kademe_ortak1_olcme_gerilim", 384, 1, 0},
  {"kademe_ortak1_yuzdelik", 385, 1, 0},
  {"kademe_ortak2_tipi", 386, 1, 0}, {"kademe_ortak2_olcme_gerilim", 387, 1, 0},
  {"kademe_ortak2_yuzdelik", 388, 1, 0},
  {"kademe_ortak3_tipi", 389, 1, 0}, {"kademe_ortak3_olcme_gerilim", 390, 1, 0},
  {"kademe_ortak3_yuzdelik", 391, 1, 0},
  {"faz_faz_kontrolu", 394, 1, 0}, {"akim_gerilim_eslestirme", 395, 1, 0},
  {"es_yaslandirma_kontrol", 400, 1, 0}, {"es_yaslandirma_yuzdelik", 401, 1, 0},
  {"es_yaslandirma_sure", 402, 1, 0},
  {"kademe_ara_suresi", 403, 1, 0}, {"kademeler_daimi_kontrol", 404, 1, 0},
  {"olcme_hatasi_tanima", 405, 1, 0}, {"kademe_faz_hatasi", 406, 1, 0},
  {"kademe_deger_kaybi", 407, 1, 0},
  {"kurulum_modu", 410, 1, 0}, {"kurulum_tekrar_sayisi", 411, 1, 0},
  {"baglanti_sekli", 412, 1, 0}, {"kurulum_daimi_kontrol", 413, 1, 0},
  {"olcme_hatasi_kurulum", 414, 1, 0},
  {"modbus_modu", 425, 1, 0}, {"modbus_data_bits", 426, 1, 0},
  {"modbus_parity", 427, 1, 0}, {"modbus_stop_bits", 428, 1, 0},
  {"modbus_sessizlik_suresi", 429, 1, 0},
};

bool readParamJson(char *buf, size_t bufSize) {
  JsonYazici y; jsonBasla(y, buf, bufSize);
  const size_t n = sizeof(PARAM_REGS) / sizeof(PARAM_REGS[0]);
  struct { uint16_t bas; uint16_t adet; } parcalar[] = {
    {200, 64}, {264, 64}, {328, 64}, {392, 38},
  };
  for (auto &p : parcalar) {
    if (!blok16Oku(p.bas, p.adet, PARAM_REGS, n, y)) return false;
    hatBekle(30);
  }
  jsonBitir(y);
  return true;
}

// ==================== YAZMA KOMUTLARI (referans) ====================
// Kaynak: "Komutlar" sayfasi, adres 9000-9041. Tetikleme deseni ANL13/ANL21
// ile AYNI: register'a value=0xAA55 (43605) yazilir (fonksiyon kodu 06,
// bkz. onMqttMessage'daki genel {"register":N,"value":M} mekanizmasi -- bu
// mekanizma zaten mevcut, asagidaki liste sadece HANGI register'in NE
// yaptigini dokumante ediyor, ayrica kod gerektirmiyor).
//
// ORTAK (ANL13/ANL21 ile BIREBIR AYNI numaralar -- Grup Arge'nin tum urun
// ailesinde bu blok sabit gorunuyor):
//   9001 Enerjileri Sil          9002 Min/Max'lari Sil
//   9003 Demandlari Sil          9004 Tum Alarmlari Sil
//   9022 Sistem Password Reset   9024 Fabrika Ayarlarina Don (YUKSEK RISK)
//   9025 Cihaz Reset             9040 Olaylari Sil    9041 Uyarilari Sil
//
// GA1202'YE OZEL (kademe/SVC/kompanzasyon islemleri):
//   9000 Cihaz Durumu (deger: grup1 tanima=43521, grup2=43522, grup3=43523,
//        tek kademe tanima = 43520+kademe_no -- bu TEK KOMUT, 0xAA55 DEGIL,
//        deger dogrudan tanima kodu)
//   9005 RGP Sil (Reaktif Guc Profili -- alarm/olay gunlugu, 44xxx bloku)
//   9007 Kademe Tanima Baslat (Akilli)
//   9008 Kademe Tanima Baslat (Sirali)
//   9009 Kademe Tanima Baslat (Hizli)
//   9010 SVC Tanimayi Baslat
//   9011 Tek Kademe Tanima (deger: dogrudan kademe numarasi, 0xAA55 DEGIL)
//   9012 Kademe Tanimayi Sonlandir
//   9013 Kuruluma Basla           9014 Kurulumu Sonlandir
//   9015 Kademe Cekme Sayisi ve Suresini Sil
//   9016 Kademe Detaylarini Sil   9019 Kademe Reset
//
// YUKSEK RISKLI (UI'da CIFT ONAY gerektirmeli -- bkz. proje genelindeki
// ANL21 dashboard planinin ayni kurali): 9024 Fabrika Ayarlarina Don,
// 9022 Sistem Password Reset, 9025 Cihaz Reset.

// Backend'ten cmd topic'ine gelen {"register": N, "value": M} komutunu ilgili
// registera yazar (fonksiyon kodu 06, single register write). "value"
// verilmezse varsayilan 1'dir. Bu mekanizma ANL13/ANL21 ile AYNI -- role
// icin de kademe ac/kapa, hedef cosfi yazma gibi komutlar bu sekilde
// gonderilecek, sadece register numaralari haritadan gelecek.
bool extractJsonField(const char* body, const char* key, char* out, size_t outSize) {
  char pattern[32];
  snprintf(pattern, sizeof(pattern), "\"%s\"", key);
  const char* p = strstr(body, pattern);
  if (!p) return false;
  p = strchr(p, ':');
  if (!p) return false;
  p = strchr(p, '"');
  if (!p) return false;
  p++;
  const char* end = strchr(p, '"');
  if (!end) return false;
  size_t len = end - p;
  if (len >= outSize) len = outSize - 1;
  memcpy(out, p, len);
  out[len] = '\0';
  return true;
}

// MQTT'nin tek paylasilan kimlik bilgisini ele geciren birinin cihaza
// istedigi kodu calistiramamasi icin iki kontrol var: adres SADECE
// binaryenerji.com'a gidebiliyor, ve indirilen baytlarin sha256'si
// mesajdakiyle BIREBIR uyusmadan yazma asla tamamlanmiyor (bkz. ANL21'deki
// ayni mekanizmanin uzun notu).
static const char* OTA_IZINLI_ADRES_ONEKI = "https://binaryenerji.com/";

bool otaSha256Dogrula(const char* beklenenHex, const uint8_t* ozet) {
  if (strlen(beklenenHex) != 64) return false;
  char hesaplanan[65];
  for (int i = 0; i < 32; i++) sprintf(hesaplanan + i * 2, "%02x", ozet[i]);
  hesaplanan[64] = '\0';
  return strcasecmp(hesaplanan, beklenenHex) == 0;
}

void handleOtaMessage(byte* payload, unsigned int length) {
  char buf[400];
  unsigned int n = length < sizeof(buf) - 1 ? length : sizeof(buf) - 1;
  memcpy(buf, payload, n);
  buf[n] = '\0';

  char url[300];
  char version[32];
  char beklenenSha256[65];
  if (!extractJsonField(buf, "url", url, sizeof(url))) {
    Serial.println("OTA: gecersiz mesaj, url alani yok");
    return;
  }
  extractJsonField(buf, "version", version, sizeof(version));
  if (!extractJsonField(buf, "sha256", beklenenSha256, sizeof(beklenenSha256))) {
    Serial.println("OTA: reddedildi -- sha256 alani yok, dogrulanamayan firmware kabul edilmiyor.");
    return;
  }
  if (strncmp(url, OTA_IZINLI_ADRES_ONEKI, strlen(OTA_IZINLI_ADRES_ONEKI)) != 0) {
    Serial.print("OTA: reddedildi -- izin verilmeyen adres: ");
    Serial.println(url);
    return;
  }

  Serial.print("OTA baslatiliyor, surum: ");
  Serial.print(version);
  Serial.print(" url: ");
  Serial.println(url);

  otaPrefs.putBool("pending", true);

  WiFiClientSecure client;
  if (tlsDogrulamaKapali) {
    client.setInsecure();
  } else {
    client.setCACert(ISRG_ROOTS);
  }

  HTTPClient http;
  bool otaBasarisiz = false;
  const char* basarisizlikNedeni = "";

  if (!http.begin(client, url)) {
    otaBasarisiz = true;
    basarisizlikNedeni = "baglanti kurulamadi";
  }

  int httpKod = otaBasarisiz ? 0 : http.GET();
  if (!otaBasarisiz && httpKod != HTTP_CODE_OK) {
    otaBasarisiz = true;
    basarisizlikNedeni = "beklenmeyen HTTP yaniti";
  }

  int boyut = otaBasarisiz ? 0 : http.getSize();
  if (!otaBasarisiz && !Update.begin(boyut > 0 ? (size_t)boyut : UPDATE_SIZE_UNKNOWN)) {
    otaBasarisiz = true;
    basarisizlikNedeni = Update.errorString();
  }

  size_t yazilan = 0;
  uint8_t ozet[32];

  if (!otaBasarisiz) {
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);

    NetworkClient* akis = http.getStreamPtr();
    uint8_t tampon[512];
    unsigned long sonVeriMs = millis();

    while (true) {
      if (boyut > 0 && yazilan >= (size_t)boyut) break;
      if (!http.connected() && akis->available() == 0) break;

      size_t mevcut = akis->available();
      if (mevcut == 0) {
        if (millis() - sonVeriMs > 15000) {
          otaBasarisiz = true;
          basarisizlikNedeni = "veri akisi durdu (zaman asimi)";
          break;
        }
        delay(10);
        continue;
      }
      size_t okunacak = mevcut > sizeof(tampon) ? sizeof(tampon) : mevcut;
      if (boyut > 0) {
        size_t kalan = (size_t)boyut - yazilan;
        if (okunacak > kalan) okunacak = kalan;
      }
      size_t okunan = akis->readBytes(tampon, okunacak);
      if (okunan == 0) continue;
      sonVeriMs = millis();

      if (Update.write(tampon, okunan) != okunan) {
        otaBasarisiz = true;
        basarisizlikNedeni = "flash yazma hatasi";
        break;
      }
      mbedtls_sha256_update(&sha, tampon, okunan);
      yazilan += okunan;
    }

    mbedtls_sha256_finish(&sha, ozet);
    mbedtls_sha256_free(&sha);

    if (!otaBasarisiz && boyut > 0 && yazilan != (size_t)boyut) {
      otaBasarisiz = true;
      basarisizlikNedeni = "indirme yarim kaldi";
    }
    if (!otaBasarisiz && !otaSha256Dogrula(beklenenSha256, ozet)) {
      otaBasarisiz = true;
      basarisizlikNedeni = "sha256 uyusmuyor -- indirilen dosya beklenenden farkli";
    }
  }

  http.end();

  if (otaBasarisiz) {
    Serial.print("OTA basarisiz: ");
    Serial.println(basarisizlikNedeni);
    Update.abort();
    otaPrefs.putBool("pending", false);
    mqttClient.publish(statusTopic.c_str(), "ota_failed", false);
    return;
  }

  if (!Update.end(true)) {
    Serial.print("OTA basarisiz: ");
    Serial.println(Update.errorString());
    otaPrefs.putBool("pending", false);
    mqttClient.publish(statusTopic.c_str(), "ota_failed", false);
    return;
  }

  Serial.println("OTA basarili (adres ve sha256 dogrulandi), yeniden baslatiliyor...");
  mqttClient.publish(statusTopic.c_str(), "ota_rebooting", false);
  delay(200);
  ESP.restart();
}

void confirmOtaIfPending() {
  if (!otaPendingConfirm) return;
  esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
  if (err == ESP_OK) {
    Serial.println("OTA onaylandi, bu surum kalici.");
  } else {
    Serial.printf("OTA onayi basarisiz (esp_err=%d) -- rollback bu cihazda desteklenmiyor olabilir.\n", err);
  }
  otaPrefs.putBool("pending", false);
  otaPendingConfirm = false;
}

void checkOtaRollbackTimeout() {
  if (!otaPendingConfirm) return;
  if (millis() - otaPendingSince < OTA_CONFIRM_TIMEOUT_MS) return;
  Serial.println("OTA onaylanamadi, onceki firmware'e donuluyor...");
  esp_ota_mark_app_invalid_rollback_and_reboot();
  otaPrefs.putBool("pending", false);
  otaPendingConfirm = false;
}

static bool jsonDegerCek(const char* buf, const char* anahtar, String &cikti) {
  char desen[24];
  snprintf(desen, sizeof(desen), "\"%s\"", anahtar);
  const char* p = strstr(buf, desen);
  if (!p) return false;
  p = strchr(p + strlen(desen), ':');
  if (!p) return false;
  p = strchr(p, '"');
  if (!p) return false;
  p++;
  const char* son = p;
  while (*son && !(*son == '"' && *(son - 1) != '\\')) son++;
  if (!*son) return false;
  cikti = "";
  for (const char* q = p; q < son; q++) cikti += *q;
  return true;
}

Preferences prefs;
volatile bool wifiConfigured = false;
String pendingSsid, pendingPass;

// Cihazi baska bir WiFi agina tasir. EN KRITIK NOKTA: yanlis bilgi girilirse
// cihaz tamamen kaybolur -- bu yuzden eski bilgiler saklanip yeni ag DENENIYOR;
// olmazsa eskiye donuluyor (bkz. ANL21'deki ayni fonksiyonun notu).
bool connectToWifi(const String &ssid, const String &pass, unsigned long timeoutMs);

void handleWifiConfig(const char* buf) {
  String yeniSsid, yeniPass;
  if (!jsonDegerCek(buf, "ssid", yeniSsid) || yeniSsid.length() == 0) {
    Serial.println("WiFi komutu: ssid yok, yoksayildi.");
    return;
  }
  jsonDegerCek(buf, "pass", yeniPass);

  String eskiSsid = prefs.getString("ssid", "");
  String eskiPass = prefs.getString("pass", "");

  Serial.print("WiFi degistirme istegi: ");
  Serial.println(yeniSsid);

  mqttClient.disconnect();
  WiFi.disconnect();
  delay(300);

  if (connectToWifi(yeniSsid, yeniPass, 20000)) {
    prefs.putString("ssid", yeniSsid);
    prefs.putString("pass", yeniPass);
    Serial.print("Yeni aga gecildi: ");
    Serial.println(WiFi.SSID());
    wifiDegisimSonucu = 1;
  } else {
    Serial.println("Yeni aga baglanilamadi, eski aga donuluyor.");
    if (connectToWifi(eskiSsid, eskiPass, 20000)) {
      Serial.println("Eski aga donuldu, kayitli bilgi degismedi.");
    } else {
      Serial.println("Eski aga da donulemedi -- yeniden baslatma bekleniyor.");
    }
    wifiDegisimSonucu = 2;
  }
}

void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  if (otaTopic.length() && strcmp(topic, otaTopic.c_str()) == 0) {
    handleOtaMessage(payload, length);
    return;
  }

  char buf[256];
  unsigned int n = length < sizeof(buf) - 1 ? length : sizeof(buf) - 1;
  memcpy(buf, payload, n);
  buf[n] = '\0';

  if (strstr(buf, "\"cmd\"") && strstr(buf, "wifi")) {
    handleWifiConfig(buf);
    return;
  }

  char* p = strstr(buf, "\"register\"");
  if (!p) return;
  p = strchr(p, ':');
  if (!p) return;
  int reg = atoi(p + 1);
  if (reg <= 0) return;

  int value = 1;
  char* vp = strstr(buf, "\"value\"");
  if (vp) {
    vp = strchr(vp, ':');
    if (vp) value = atoi(vp + 1);
  }

  uint8_t result = 1;
  int deneme = 0;
  for (deneme = 1; deneme <= 3; deneme++) {
    result = node.writeSingleRegister(reg, value);
    if (result == node.ku8MBSuccess) break;
    delay(60);
  }
  Serial.print("Komut yazildi, register=");
  Serial.print(reg);
  Serial.print(" value=");
  Serial.print(value);
  Serial.print(" deneme=");
  Serial.print(deneme <= 3 ? deneme : 3);
  Serial.print(" sonuc=");
  Serial.println(result == node.ku8MBSuccess ? "OK" : "HATA");
  // Yazma basarili olduysa parametreleri HEMEN yeniden oku: panel, 5 dakikalik
  // normal tazeleme turunu beklemeden yeni degeri gorsun. Kullanici bir ayari
  // degistirip ekranda eski degeri gormeye devam ederse, dogal refleks ayni
  // yazmayi tekrar denemek olur -- bu da cihaza gereksiz yazma demek.
  if (result == node.ku8MBSuccess) paramHemenOku = true;
}

String extractJsonString(const String &body, const String &key) {
  String pattern = "\"" + key + "\"";
  int idx = body.indexOf(pattern);
  if (idx < 0) return "";
  idx = body.indexOf(':', idx);
  if (idx < 0) return "";
  idx = body.indexOf('"', idx);
  if (idx < 0) return "";
  int end = body.indexOf('"', idx + 1);
  if (end < 0) return "";
  return body.substring(idx + 1, end);
}

// Cihazin KENDI URETTIGI, hicbir firmware imajinda ortak olmayan MQTT sifresi
// (bkz. ANL21'deki ayni mekanizmanin uzun notu -- tum cihazlara AYNI .bin
// yuklendigi icin donanim RNG'siyle CIHAZDA uretilen bir deger sart).
Preferences mqttAuthPrefs;
WebServer provisionServer(80);

String uretilenMqttSifresi(size_t bayt = 24) {
  String sonuc;
  sonuc.reserve(bayt * 2);
  char h[3];
  for (size_t i = 0; i < bayt; i++) {
    sprintf(h, "%02x", (uint8_t)(esp_random() & 0xFF));
    sonuc += h;
  }
  return sonuc;
}

String kurulumMqttSifresi() {
  String sifre = mqttAuthPrefs.getString("pass", "");
  if (sifre.length() == 0) {
    sifre = uretilenMqttSifresi();
    mqttAuthPrefs.putString("pass", sifre);
    Serial.println("Yeni MQTT kimligi uretildi (yerel AP uzerinden telefona iletilecek).");
  }
  return sifre;
}

void handleProvisionStatus() {
  String yanit = "{\"device_id\":\"" + deviceId + "\"";
  yanit += ",\"mqtt_username\":\"" + deviceId + "\"";
  yanit += ",\"mqtt_password\":\"" + kurulumMqttSifresi() + "\"";
  yanit += "}";
  provisionServer.send(200, "application/json", yanit);
}

void handleProvisionConfigure() {
  String body = provisionServer.arg("plain");
  String ssid = extractJsonString(body, "ssid");
  String pass = extractJsonString(body, "password");
  if (ssid.length() == 0) {
    provisionServer.send(400, "application/json", "{\"status\":\"error\",\"message\":\"ssid gerekli\"}");
    return;
  }
  pendingSsid = ssid;
  pendingPass = pass;
  provisionServer.send(200, "application/json", "{\"status\":\"ok\"}");
  wifiConfigured = true;
}

// TLS sertifika dogrulamasi cihazin saatine bagli -- ESP32 epoch 0'dan (1970)
// basladigi icin NTP olmadan her dogrulama "sertifika henuz gecerli degil"
// diye duser. Bu yuzden zaman once senkronlanir.
bool senkronlaZaman() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("Saat senkronlaniyor");
  unsigned long basla = millis();
  time_t simdi = time(nullptr);
  while (simdi < 1600000000 && millis() - basla < 15000) {
    delay(300);
    Serial.print(".");
    simdi = time(nullptr);
  }
  Serial.println();
  if (simdi < 1600000000) {
    Serial.println("Saat senkronlanamadi -- sertifika dogrulamasi basarisiz olacak.");
    return false;
  }
  Serial.print("Saat: ");
  Serial.print(ctime(&simdi));
  return true;
}

bool connectToWifi(const String &ssid, const String &pass, unsigned long timeoutMs) {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), pass.c_str());
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(250);
  }
  return WiFi.status() == WL_CONNECTED;
}

// Cihazin kendi Access Point'ini acar ("BinaryEnerji-<cihaz id>", sifresiz) ve
// telefon uygulamasindan gelecek POST /configure ile ev WiFi bilgisini bekler
// (bkz. ANL21'deki ayni fonksiyonun uzun notu).
bool startProvisioningAP(const String &savedSsid, const String &savedPass) {
  WiFi.mode(WIFI_AP_STA);
  String apName = "BinaryEnerji-" + deviceId;
  WiFi.softAP(apName.c_str());
  Serial.print("Kurulum AP'si acildi: ");
  Serial.println(apName);
  Serial.println("Telefon uygulamasindan bu aga baglanip WiFi bilgilerini girin.");
  if (savedSsid.length() > 0) {
    Serial.print("Bu sirada kayitli ag da denenmeye devam edecek: ");
    Serial.println(savedSsid);
  }

  static bool handlerlarKuruldu = false;
  if (!handlerlarKuruldu) {
    provisionServer.on("/status", HTTP_GET, handleProvisionStatus);
    provisionServer.on("/configure", HTTP_POST, handleProvisionConfigure);
    handlerlarKuruldu = true;
  }
  provisionServer.begin();

  wifiConfigured = false;
  unsigned long sonDeneme = millis();
  unsigned long denemeBasi = 0;
  bool denemeSuruyor = false;

  while (!wifiConfigured) {
    provisionServer.handleClient();
    delay(2);

    if (savedSsid.length() == 0) continue;

    if (!denemeSuruyor && millis() - sonDeneme >= PROVISION_RETRY_INTERVAL_MS) {
      Serial.println("Kayitli ag yeniden deneniyor...");
      WiFi.begin(savedSsid.c_str(), savedPass.c_str());
      denemeSuruyor = true;
      denemeBasi = millis();
    }

    if (denemeSuruyor) {
      if (WiFi.status() == WL_CONNECTED) {
        Serial.println("Kayitli aga yeniden baglanildi, kurulum modundan cikiliyor.");
        provisionServer.stop();
        return true;
      }
      if (millis() - denemeBasi >= PROVISION_RETRY_WINDOW_MS) {
        WiFi.disconnect();
        denemeSuruyor = false;
        sonDeneme = millis();
      }
    }
  }
  provisionServer.stop();
  return false;
}

unsigned long wifiDisconnectedSince = 0;
unsigned long loopCount = 0;

void setup() {
  Serial.begin(115200);
  // TODO(register-haritasi): GA1202'nin Ayarlar > Modbus Ayarlari ekranindaki
  // gercek hiza gore guncellenmeli. 19200, Grup Arge'nin diger cihazlarindaki
  // (ANL13/ANL21) varsayilan degeriyle ayni -- bir baslangic varsayimi.
  Serial2.begin(19200, SERIAL_8N1, RXD2, TXD2);

  pinMode(RE_DE_PIN, OUTPUT);
  // TODO(register-haritasi): cihazin gercek Modbus slave adresiyle karsilastir.
  node.begin(1, Serial2);
  node.preTransmission(preTransmission);
  node.postTransmission(postTransmission);

  setupDeviceId();
  Serial.print("CIHAZ ID (etikete/kutuya yazin): ");
  Serial.println(deviceId);

  Serial.print("Firmware surumu: ");
  Serial.println(FW_VERSION);

  otaPrefs.begin("ota", false);
  if (otaPrefs.getBool("pending", false)) {
    Serial.println("Bu, onaylanmamis bir OTA sonrasi ilk acilis -- onaylanamazsa geri donulecek.");
    otaPendingConfirm = true;
    otaPendingSince = millis();
  }

  pinMode(WIFI_RESET_PIN, INPUT_PULLUP);
  prefs.begin("wifi", false);
  mqttAuthPrefs.begin("mqttauth", false);

  if (digitalRead(WIFI_RESET_PIN) == LOW) {
    Serial.println("BOOT tusu basili -- kayitli WiFi bilgisi siliniyor, kurulum moduna giriliyor.");
    prefs.clear();
  }

  String savedSsid = prefs.getString("ssid", "");
  String savedPass = prefs.getString("pass", "");

  bool connected = false;
  if (savedSsid.length() > 0) {
    Serial.print("Kayitli aga baglaniliyor: ");
    Serial.println(savedSsid);
    connected = connectToWifi(savedSsid, savedPass, 15000);
  }

  while (!connected) {
    if (startProvisioningAP(savedSsid, savedPass)) {
      connected = true;
      break;
    }
    connected = connectToWifi(pendingSsid, pendingPass, 20000);
    if (connected) {
      prefs.putString("ssid", pendingSsid);
      prefs.putString("pass", pendingPass);
      savedSsid = pendingSsid;
      savedPass = pendingPass;
    } else {
      Serial.println("Girilen WiFi bilgileriyle baglanilamadi, kurulum moduna donuluyor.");
    }
  }

  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);

  // Modem uyku modu kapatildi -- bkz. ANL21'deki ayni ayarin uzun notu
  // (sebekeden beslenen bir cihaz icin guc tasarrufunun maliyeti anlamsiz,
  // kazanci ise MQTT baglantisinin RF gurultusunde sessizce olmemesi).
  WiFi.setSleep(false);

  Serial.print("WiFi'ya baglanildi: ");
  Serial.println(WiFi.SSID());

  senkronlaZaman();
  espClient.setCACert(ISRG_ROOTS);
  mqttClient.setServer(mqtt_server, mqtt_port);
  mqttClient.setCallback(onMqttMessage);
  mqttClient.setKeepAlive(60);
  // En buyuk payload parametreler (~105 alan, ~2.5 KB); kademeler ve tepe
  // degerleri de 1 KB'i asiyor. Bu sinir asilirsa PubSubClient mesaji SESSIZCE
  // dusuruyor (ANL13'te saatlerce "veri neden gelmiyor" aramasina yol acmisti).
  mqttClient.setBufferSize(4096);

  delay(30);
  deviceInfoOk = readDeviceInfo();
  if (!deviceInfoOk) Serial.println("Cihaz bilgisi okunamadi! (Register haritasi henuz dogrulanmadi.)");
}

void loop() {
  uint32_t donguBasi = millis();

  if (WiFi.status() != WL_CONNECTED) {
    if (wifiDisconnectedSince == 0) {
      wifiDisconnectedSince = millis();
      Serial.println("WiFi baglantisi koptu, yeniden baglanmaya calisiliyor...");
    }
    WiFi.reconnect();
    delay(2000);
    if (millis() - wifiDisconnectedSince > WIFI_RECONNECT_RESTART_MS) {
      Serial.println("WiFi uzun sure baglanamadi, cihaz yeniden baslatiliyor...");
      ESP.restart();
    }
    return;
  }
  wifiDisconnectedSince = 0;

  if (!mqttClient.connected()) {
    String kendiSifre = mqttAuthPrefs.getString("pass", "");
    bool kendiKimlikVar = kendiSifre.length() > 0;
    bool ok = false;
    if (kendiKimlikVar) {
      ok = mqttClient.connect(
        deviceId.c_str(), deviceId.c_str(), kendiSifre.c_str(),
        statusTopic.c_str(), 1, true, "offline");
    }
    if (!ok) {
      ok = mqttClient.connect(
        deviceId.c_str(), "esp32user", "***REDACTED-MQTT-PASSWORD***",
        statusTopic.c_str(), 1, true, "offline");
    }
    if (ok) {
      mqttClient.subscribe(cmdTopic.c_str());
      mqttClient.subscribe(otaTopic.c_str());
      mqttClient.publish(statusTopic.c_str(), "online", true);
      tlsBasarisizSayaci = 0;
      if (wifiDegisimSonucu) {
        mqttClient.publish(
          wifiTopic.c_str(),
          wifiDegisimSonucu == 1
            ? "{\"ok\":true}"
            : "{\"ok\":false,\"hata\":\"yeni aga baglanilamadi, eski ag korundu\"}",
          true);
        wifiDegisimSonucu = 0;
      }
    } else {
      tlsBasarisizSayaci++;
      if (tlsBasarisizSayaci >= 5 && !tlsDogrulamaKapali) {
        Serial.println("UYARI: TLS dogrulamasi 5 kez basarisiz -- dogrulamasiz TLS'e dusuluyor.");
        espClient.setInsecure();
        tlsDogrulamaKapali = true;
        tlsTekrarDenemeMs = millis();
      }
    }
  }
  mqttClient.loop();

  if (tlsDogrulamaKapali && millis() - tlsTekrarDenemeMs > TLS_DOGRULAMA_TEKRAR_MS) {
    tlsTekrarDenemeMs = millis();
    if (senkronlaZaman()) {
      Serial.println("Saat artik gecerli -- dogrulanmis TLS tekrar deneniyor.");
      espClient.setCACert(ISRG_ROOTS);
      tlsDogrulamaKapali = false;
      tlsBasarisizSayaci = 0;
      mqttClient.disconnect();
    }
  }

  checkOtaRollbackTimeout();

  if (deviceInfoOk && !deviceInfoPublished && mqttClient.connected()) {
    char infoPayload[400];
    snprintf(infoPayload, sizeof(infoPayload),
      "{\"seri_no\":%ld,\"urun_id\":%ld,\"kart_id\":%ld,\"sistem_versiyon\":%ld,"
      "\"ulke_kodu\":%ld,\"firma_kodu\":%ld,\"besleme_tipi\":%ld,\"ekran_tipi\":%ld,"
      "\"keyboard_tipi\":%ld,\"kutu_tipi\":%ld,\"klemens_tipi\":%ld,\"connections\":%ld,\"storage\":%ld}",
      (long)deviceInfo.seriNo, (long)deviceInfo.urunId, (long)deviceInfo.kartId, (long)deviceInfo.sistemVersiyon,
      (long)deviceInfo.ulkeKodu, (long)deviceInfo.firmaKodu, (long)deviceInfo.beslemeTipi, (long)deviceInfo.ekranTipi,
      (long)deviceInfo.keyboardTipi, (long)deviceInfo.kutuTipi, (long)deviceInfo.klemensTipi,
      (long)deviceInfo.connections, (long)deviceInfo.storage);
    mqttClient.publish(infoTopic.c_str(), infoPayload, true);
    Serial.println(infoPayload);
    deviceInfoPublished = true;
  }

  bool okLive = readRelayLive();
  if (okLive) confirmOtaIfPending();
  if (okLive) {
    char payload[900];
    buildLiveJson(payload, sizeof(payload));
    mqttClient.publish(liveTopic.c_str(), payload);
    Serial.println(payload);
  } else {
    Serial.println("Modbus okuma hatasi (Anlik Degerler)!");
  }

  // Kademeler daha yavas degistigi icin ~10 saniyede bir okunur (2sn x 5).
  if (loopCount % 5 == 0) {
    hatBekle(30);
    bool ozetOk = readKademelerOzet();
    hatBekle(30);
    bool detayOk = ozetOk && readKademeDetaylari();
    if (ozetOk && detayOk) {
      char buf[1400];
      buildKademelerJson(buf, sizeof(buf));
      mqttClient.publish(kademelerTopic.c_str(), buf);
      Serial.println(buf);
    } else {
      Serial.println("Kademeler okuma hatasi!");
    }
  }

  // Okuma siklıklari kasitli olarak kademeli: RS-485 tek bir hat ve her
  // istek onu mesgul ediyor. Hizli degisen veri sik, yavas degisen veri
  // seyrek okunuyor -- ANL21'deki ayni yaklasim.
  //
  // Toplam/Ortalama: ~10 sn (2sn x 5, kademelerle ayni tur ama kaydirilmis
  // ki ayni dongude iki agir okuma ust uste binmesin).
  if (loopCount % 5 == 2) {
    hatBekle(30);
    char buf[900];
    if (readToplamJson(buf, sizeof(buf))) {
      mqttClient.publish(toplamTopic.c_str(), buf);
    } else {
      Serial.println("Toplam/Ortalama okuma hatasi!");
    }
  }

  // Enerji sayaclari: ~30 sn. Kumulatif degerler, daha sik okumanin faydasi yok.
  if (loopCount % 15 == 3) {
    hatBekle(30);
    char buf[700];
    if (readEnerjiJson(13020, buf, sizeof(buf))) {
      mqttClient.publish(enerjiTuketimTopic.c_str(), buf);
    } else {
      Serial.println("Enerji (tuketim) okuma hatasi!");
    }
    hatBekle(30);
    if (readEnerjiJson(13280, buf, sizeof(buf))) {
      mqttClient.publish(enerjiUretimTopic.c_str(), buf);
    } else {
      Serial.println("Enerji (uretim) okuma hatasi!");
    }
  }

  // Tepe (min/max) degerleri: ~60 sn. Cihaz bunlari kendi biriktiriyor,
  // bizim sik okumamiz degeri degistirmiyor.
  if (loopCount % 30 == 7) {
    hatBekle(30);
    char buf[1600];
    if (readTepeJson(11010, buf, sizeof(buf))) {
      mqttClient.publish(tepeTuketimTopic.c_str(), buf);
    } else {
      Serial.println("Tepe (tuketim) okuma hatasi!");
    }
    hatBekle(30);
    if (readTepeJson(11260, buf, sizeof(buf))) {
      mqttClient.publish(tepeUretimTopic.c_str(), buf);
    } else {
      Serial.println("Tepe (uretim) okuma hatasi!");
    }
  }

  // Parametreler (ayarlar): ~5 dk. Yalnizca biri elle degistirdiginde
  // degisir; ayrica yazma komutundan HEMEN sonra da bir kez okunuyor
  // (bkz. onMqttMessage) ki panel yeni degeri beklemeden gostersin.
  if (loopCount % 150 == 11 || paramHemenOku) {
    paramHemenOku = false;
    hatBekle(30);
    char buf[3000];
    if (readParamJson(buf, sizeof(buf))) {
      mqttClient.publish(paramTopic.c_str(), buf, true);
    } else {
      Serial.println("Parametre okuma hatasi!");
    }
  }

  loopCount++;
  uint32_t gecen = millis() - donguBasi;
  uint32_t kalan = gecen < LOOP_PERIYODU_MS ? LOOP_PERIYODU_MS - gecen : 0;
  hatBekle(kalan > ASGARI_BEKLEME_MS ? kalan : ASGARI_BEKLEME_MS);
}
