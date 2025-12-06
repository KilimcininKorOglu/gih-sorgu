# GİH Sorgu

Türkiye'deki **Güvenli İnternet Hizmeti (GİH)** üzerinden domain engellenme durumunu sorgulayan Go CLI aracı.

Google Gemini API kullanarak CAPTCHA'yı otomatik çözer. Tek dosya, cross-platform binary (~7MB).

## Kurulum

### Hazır Binary (Önerilen)

[Releases](https://github.com/KilimcininKorOglu/gih-sorgu/releases) sayfasından platformunuza uygun binary'yi indirin:

| Platform | Mimari | Dosya |
|----------|--------|-------|
| Windows | x64 | `gih-sorgu-windows-amd64.exe` |
| Windows | ARM64 | `gih-sorgu-windows-arm64.exe` |
| Linux | x64 | `gih-sorgu-linux-amd64` |
| Linux | ARM64 | `gih-sorgu-linux-arm64` |
| macOS | Intel | `gih-sorgu-darwin-amd64` |
| macOS | Apple Silicon | `gih-sorgu-darwin-arm64` |

### Kaynak Koddan Derleme

```bash
# Repoyu klonla
git clone https://github.com/KilimcininKorOglu/gih-sorgu.git
cd gih-sorgu

# Derle
go build -ldflags="-s -w" -o gih-sorgu .

# veya tüm platformlar için
./build.sh        # Linux/macOS
build.bat         # Windows
```

### Gereksinimler

- **Gemini API Key** - [Google AI Studio](https://aistudio.google.com/app/apikey) adresinden ücretsiz alınabilir

## Yapılandırma

`.env` dosyasını executable ile aynı dizine oluşturun:

```env
GEMINI_API_KEY=your_api_key_here
```

| Değişken | Zorunlu | Varsayılan | Açıklama |
|----------|---------|------------|----------|
| `GEMINI_API_KEY` | Evet | - | Google Gemini API anahtarı |
| `GEMINI_MODEL` | - | `gemini-2.5-flash` | Kullanılacak Gemini modeli |
| `GEMINI_MAX_TOKENS` | - | `256` | Maksimum çıktı token sayısı (1-8192) |
| `USER_AGENT` | - | Firefox UA | HTTP isteklerinde User-Agent |
| `RATE_LIMIT_DELAY` | - | `500` | Sorgular arası bekleme (ms, 0-10000) |

## Kullanım

### İnteraktif TUI Modu

Argümansız çalıştırınca interaktif TUI açılır (Windows'ta exe'ye çift tıklayın):

```bash
./gih-sorgu
```

**TUI Kontrolleri:**
- `Enter` - Domain sorgula
- `1-9` - Geçmişten seç ve sorgula
- `↑/↓` - Geçmişte gezin
- `Tab` - Son sorguyu kopyala
- `Esc` - Çıkış

### CLI Modu

```bash
# Tek domain sorgula
./gih-sorgu discord.com

# Birden fazla domain
./gih-sorgu discord.com twitter.com google.com

# Dosyadan liste oku
./gih-sorgu --liste sites.txt

# JSON formatında çıktı
./gih-sorgu --json discord.com

# Yardım ve versiyon
./gih-sorgu --help
./gih-sorgu --version
```

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
  "domain": "discord.com",
  "engelliMi": true,
  "aileProfili": "engelli",
  "cocukProfili": "engelli",
  "engelTarihi": "2024-10-20 22:34:15",
  "mesaj": "Bu alan adı aile ve çocuk profilinde görüntülenememektedir."
}
```

## Dosya Listesi Formatı

```text
# sites.txt - Her satırda bir domain
discord.com
twitter.com
# Yorum satırları # ile başlar
google.com
```

## Exit Kodları

| Kod | Anlam |
|-----|-------|
| 0 | Başarılı |
| 1 | Genel hata |
| 2 | Geçersiz argüman |
| 3 | Config hatası (API key eksik) |
| 4 | Ağ hatası |
| 5 | API hatası |

## Güvenlik Notu

- SSL sertifika doğrulaması `guvenlinet.org.tr` sertifika zinciri sorunu nedeniyle devre dışı bırakılmıştır
- API anahtarınızı `.env` dosyasında saklayın, commit etmeyin

## Geçmiş

Sorgu geçmişi `history.json` dosyasında saklanır (max 100 kayıt). TUI modunda `1-9` tuşlarıyla geçmişten hızlıca seçim yapabilirsiniz.

## Lisans

MIT

## Kaynak

Sorgu yapılan site: [guvenlinet.org.tr/sorgula](https://www.guvenlinet.org.tr/sorgula)
