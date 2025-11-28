# GİH Sorgu

Türkiye'deki **Güvenli İnternet Hizmeti (GİH)** üzerinden domain engellenme durumunu sorgulayan Node.js CLI aracı.

Google Gemini API kullanarak CAPTCHA'yı otomatik çözer. Sıfır bağımlılık, tek dosya.

## 🚀 Kurulum

```bash
# Repoyu klonla
git clone https://github.com/KilimcininKorOglu/gih-sorgu.git
cd gih-sorgu

# .env dosyasını oluştur
cp .env.example .env

# API anahtarını ekle
# .env dosyasında GEMINI_API_KEY değerini ayarla
```

### Gereksinimler

- **Node.js** v18+
- **Gemini API Key** - [Google AI Studio](https://aistudio.google.com/app/apikey) adresinden ücretsiz alınabilir

## 📖 Kullanım

```bash
# Tek domain sorgula
node gih-sorgu.js discord.com

# Birden fazla domain
node gih-sorgu.js discord.com twitter.com google.com

# Dosyadan liste oku
node gih-sorgu.js --liste sites.txt

# JSON formatında çıktı
node gih-sorgu.js --json discord.com

# Yardım ve versiyon
node gih-sorgu.js --help
node gih-sorgu.js --version
```

## 📋 Örnek Çıktı

```bash
╔════════════════════════════════════════════════════════════╗
║     Güvenli İnternet Hizmeti (GİH) Sorgu Aracı             ║
╚════════════════════════════════════════════════════════════╝

📋 Sorgulanacak 1 site: discord.com
🤖 Model: gemini-2.5-flash

🔗 Session başlatılıyor...
✅ Session alındı: 0 cookie
📥 CAPTCHA indiriliyor...
✅ CAPTCHA kaydedildi: captcha.jpg (6724 bytes)
🤖 Gemini API ile CAPTCHA çözülüyor...
✅ CAPTCHA çözüldü: ft3rn4g

🔍 Sorgulanıyor: discord.com

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

🧹 CAPTCHA dosyası temizlendi.
```

## ⚙️ Yapılandırma

`.env` dosyasından veya sistem ortam değişkenlerinden okunur:

| Değişken | Zorunlu | Varsayılan | Açıklama |
|----------|---------|------------|----------|
| `GEMINI_API_KEY` | ✅ | - | Google Gemini API anahtarı |
| `GEMINI_MODEL` | - | `gemini-2.5-flash` | Kullanılacak Gemini modeli |
| `GEMINI_MAX_TOKENS` | - | `256` | Maksimum çıktı token sayısı |
| `USER_AGENT` | - | Firefox UA | HTTP isteklerinde User-Agent |

## 🔧 JSON Çıktı

Otomasyon için `--json` flag'i kullanın:

```bash
node gih-sorgu.js --json discord.com
```

```json
{
  "timestamp": "2024-11-27T18:30:00.000Z",
  "status": true,
  "queryDuration": 1950,
  "queryDurationFormatted": "1.95s",
  "domain": "discord.com",
  "aileProfili": "engelli",
  "cocukProfili": "engelli",
  "engelliMi": true,
  "engelTarihi": "2024-10-20 22:34:15",
  "mesaj": "Bu alan adı aile ve çocuk profilinde görüntülenememektedir."
}
```

## 📁 Dosya Listesi

```bash
sites.txt          # Her satırda bir domain
# yorum satırı      # # ile başlayan satırlar atlanır
```

## 🔒 Güvenlik Notu

- SSL sertifika doğrulaması `guvenlinet.org.tr` sertifika zinciri sorunu nedeniyle devre dışı bırakılmıştır
- API anahtarınızı `.env` dosyasında saklayın, commit etmeyin (`.gitignore`'da tanımlı)

## 📜 Lisans

MIT

## 🔗 Kaynak

Sorgu yapılan site: [guvenlinet.org.tr/sorgula](https://www.guvenlinet.org.tr/sorgula)
