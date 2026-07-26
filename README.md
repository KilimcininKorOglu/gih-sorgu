# GİH Sorgu

[![Release](https://img.shields.io/github/v/release/KilimcininKorOglu/gih-sorgu)](https://github.com/KilimcininKorOglu/gih-sorgu/releases)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Türkiye'deki **Güvenli İnternet Hizmeti (GİH)** üzerinden domain engellenme durumunu sorgulayan Go CLI aracı.

Google Gemini API kullanarak CAPTCHA'yı otomatik çözer. Tek dosya, cross-platform binary (~7MB).

## Kurulum

### Hazır Binary (Önerilen)

[Releases](https://github.com/KilimcininKorOglu/gih-sorgu/releases) sayfasından platformunuza uygun binary'yi indirin:

| Platform | Mimari        | Dosya                         |
|----------|---------------|-------------------------------|
| Windows  | x64           | `gih-sorgu-windows-amd64.exe` |
| Windows  | ARM64         | `gih-sorgu-windows-arm64.exe` |
| Linux    | x64           | `gih-sorgu-linux-amd64`       |
| Linux    | ARM64         | `gih-sorgu-linux-arm64`       |
| macOS    | Intel         | `gih-sorgu-darwin-amd64`      |
| macOS    | Apple Silicon | `gih-sorgu-darwin-arm64`      |

### Kaynak Koddan Derleme

```bash
# Repoyu klonla
git clone https://github.com/KilimcininKorOglu/gih-sorgu.git
cd gih-sorgu

# Mevcut platform icin derle
make build            # Linux/macOS
build.bat build       # Windows

# Tum platformlar icin cross-compile (dist/ dizinine)
make build-all        # Linux/macOS
build.bat build-all   # Windows
```

#### Geliştirme Komutları

| Komut               | Açıklama                          |
|---------------------|-----------------------------------|
| `make lint`         | `go fmt` + `go vet` çalıştırır     |
| `make test`         | Tüm testleri çalıştırır           |
| `make test-race`    | Testleri race detector ile koşar  |
| `make test-cover`   | Test kapsamını ölçer              |
| `make run`          | Derleyip TUI'yi başlatır          |
| `make clean`        | Build çıktılarını temizler        |

Windows'ta `build.bat <hedef>` kullanın (`build`, `build-all`, `lint`, `test`, `run`, `clean`).

### Gereksinimler

- **Gemini API Key** - [Google AI Studio](https://aistudio.google.com/app/apikey) adresinden ücretsiz alınabilir

## Yapılandırma

`.env` dosyasını executable ile aynı dizine oluşturun. Geliştirme sırasında çalışma dizinindeki `.env` dosyası da okunur.

```env
GEMINI_API_KEY=your_api_key_here
```

| Değişken            | Zorunlu | Varsayılan         | Açıklama                             |
|---------------------|---------|--------------------|--------------------------------------|
| `GEMINI_API_KEY`    | Evet    | -                  | Google Gemini API anahtarı           |
| `GEMINI_MODEL`      | -       | `gemini-2.5-flash` | Kullanılacak Gemini modeli           |
| `GEMINI_MAX_TOKENS` | -       | `256`              | Maksimum çıktı token sayısı (1-8192) |
| `USER_AGENT`        | -       | Firefox UA         | HTTP isteklerinde User-Agent         |
| `RATE_LIMIT_DELAY`  | -       | `500`              | Sorgular arası bekleme (ms, 0-10000) |

## Kullanım

### İnteraktif TUI Modu

Argümansız çalıştırınca interaktif TUI açılır (Windows'ta exe'ye çift tıklayın):

```bash
./gih-sorgu
```

**TUI Kontrolleri:**
- `Enter` - Domain sorgula
- `Tab` - Geçmişten seç (yeniden eskiye döngü)
- `↑/↓` - Geçmişte gezin
- `Esc` - Çıkış (sonuç/hata ekranında girişe döner)

### CLI Modu

```bash
# Tek domain sorgula
./gih-sorgu discord.com

# Birden fazla domain
./gih-sorgu discord.com twitter.com google.com

# Dosyadan liste oku
./gih-sorgu --liste sites.txt

# Kesintiye uğrayan liste sorgusuna kaldığı yerden devam et
./gih-sorgu --liste sites.txt --resume

# JSON formatında çıktı
./gih-sorgu --json discord.com

# Yardım ve versiyon
./gih-sorgu --help
./gih-sorgu --version
```

### Toplu Sorgu ve Devam Etme

`--liste` ile çoklu sorgu yapıldığında her başarılı sorgudan sonra ilerleme bir checkpoint dosyasına yazılır:

- `--liste sites.txt` için `sites.txt.progress.json`
- Argümanla verilen domainler için `gih-sorgu-progress.json`

Sorgu `Ctrl+C` veya `SIGTERM` ile kesilirse temiz kapanır. `--resume` eklendiğinde daha önce tamamlanan domainler atlanır ve kalanlardan devam edilir. Checkpoint dosyası otomatik silinmez; yeni bir tam çalıştırma için elle silin.

Gemini API art arda 5 kez başarısız olursa toplu sorgu güvenlik için durdurulur.

## Örnek Çıktı

### Normal Çıktı

```
════════════════════════════════════════════════════════════
📌 Domain: discord.com
⏱️ Sorgu Süresi: 1.95s
════════════════════════════════════════════════════════════
🚫 Durum: ENGELLİ
────────────────────────────────────────────────────────────
👨‍👩‍👧 Aile Profili: ❌ Engelli
👶 Çocuk Profili: ❌ Engelli
📅 Engel Tarihi: 2024-10-20 22:34:15
────────────────────────────────────────────────────────────
📝 Mesaj: Bu alan adı aile ve çocuk profilinde görüntülenememektedir.
════════════════════════════════════════════════════════════
```

### JSON Çıktı (`--json`)

```json
{
  "timestamp": "2024-12-06T12:00:00Z",
  "status": true,
  "queryDuration": 1950,
  "queryDurationFormatted": "1.95s",
  "domain": "discord.com",
  "aileProfili": "engelli",
  "cocukProfili": "engelli",
  "engelliMi": true,
  "parsed": true,
  "engelTarihi": "2024-10-20 22:34:15",
  "mesaj": "Bu alan adı aile ve çocuk profilinde görüntülenememektedir."
}
```

### JSON Hata Çıktısı (`--json`)

Hata durumunda makine tarafından okunabilir bir hata nesnesi döner:

```json
{
  "timestamp": "2024-12-06T12:00:00Z",
  "status": false,
  "domain": "discord.com",
  "error": "Gemini API isteği başarısız",
  "errorCode": "API_ERROR"
}
```

| errorCode             | Anlam                        |
|-----------------------|------------------------------|
| `INVALID_ARGUMENTS`   | Geçersiz argüman veya domain |
| `CONFIG_ERROR`        | Config hatası (API key eksik)|
| `NETWORK_ERROR`       | Ağ hatası                    |
| `API_ERROR`           | Gemini API hatası            |
| `API_AUTH_ERROR`      | Gemini API kimlik doğrulama  |
| `CAPTCHA_SOLVE_ERROR` | CAPTCHA çözülemedi            |
| `GENERAL_ERROR`       | Sınıflandırılamayan hata     |

## Dosya Listesi Formatı

```text
# sites.txt - Her satırda bir domain
discord.com
twitter.com
# Yorum satırları # ile başlar
google.com
```

## Exit Kodları

| Kod | Anlam                         |
|-----|-------------------------------|
| 0   | Başarılı                      |
| 1   | Genel hata                    |
| 2   | Geçersiz argüman              |
| 3   | Config hatası (API key eksik) |
| 4   | Ağ hatası                     |
| 5   | API hatası                    |

## Güvenlik Notu

- SSL sertifika doğrulaması `guvenlinet.org.tr` sertifika zinciri sorunu nedeniyle devre dışı bırakılmıştır
- API anahtarınızı `.env` dosyasında saklayın, commit etmeyin

## Geçmiş

Sorgu geçmişi `history.json` dosyasında saklanır (max 100 kayıt). TUI modunda `Tab` tuşuyla geçmişten seçim yapabilirsiniz.

## Lisans

MIT

## Kaynak

Sorgu yapılan site: [guvenlinet.org.tr/sorgula](https://www.guvenlinet.org.tr/sorgula)
