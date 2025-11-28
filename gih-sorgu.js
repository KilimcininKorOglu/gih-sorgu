/**
 * Güvenli İnternet Hizmeti (GİH) Sorgu Script v1.0.0
 * ==================================================
 * Türkiye'de Güvenli İnternet Hizmeti üzerinden alan adı engellenme durumunu sorgular.
 * Gemini API ile CAPTCHA otomatik çözümü yapar.
 * 
 * Kaynak: https://www.guvenlinet.org.tr/sorgula
 * 
 * Kullanım:
 *   node gih-sorgu.js <domain>                  Tek site sorgula
 *   node gih-sorgu.js --liste sites.txt         Liste ile sorgula
 *   node gih-sorgu.js --json <domain>           JSON formatında çıktı
 * 
 * Ortam Değişkenleri (.env dosyasından veya sistem ortamından):
 *   GEMINI_API_KEY    Google Gemini API anahtarı (ZORUNLU)
 *   GEMINI_MODEL      Gemini model adı (varsayılan: gemini-2.5-flash)
 * 
 * API Anahtarı Alma:
 *   https://aistudio.google.com/app/apikey
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// SSL sertifika doğrulamasını SADECE guvenlinet.org.tr için devre dışı bırakan agent
// Bu sayede Gemini API gibi diğer istekler güvenli kalır
const insecureAgent = new https.Agent({
  rejectUnauthorized: false
});

// ============================================================================
// .ENV DOSYASI YÜKLEME (Zero-dependency)
// ============================================================================

/**
 * .env dosyasını okur ve ortam değişkenlerine yükler
 */
function loadEnvFile() {
  const envPath = path.join(process.cwd(), '.env');

  if (!fs.existsSync(envPath)) {
    return; // .env dosyası yoksa sessizce devam et
  }

  try {
    const content = fs.readFileSync(envPath, 'utf-8');
    const lines = content.split('\n');

    for (const line of lines) {
      // Boş satırları ve yorumları atla
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // KEY=VALUE formatını parse et
      const equalIndex = trimmed.indexOf('=');
      if (equalIndex === -1) {
        continue;
      }

      const key = trimmed.substring(0, equalIndex).trim();
      let value = trimmed.substring(equalIndex + 1).trim();

      // Tırnak işaretlerini kaldır
      if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }

      // Sadece tanımlı değilse ayarla (sistem ortam değişkenleri öncelikli)
      if (!process.env[key]) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    console.error(`⚠️  .env dosyası okunamadı: ${error.message}`);
  }
}

// .env dosyasını yükle
loadEnvFile();

// ============================================================================
// YAPILANDIRMA
// ============================================================================

// Versiyon
const VERSION = '1.0.0';

// Global JSON output flag (argümanlardan ayarlanır)
let JSON_OUTPUT = false;

/**
 * Log fonksiyonu - JSON modunda sessiz, normal modda stdout'a yazar
 */
function log(message) {
  if (!JSON_OUTPUT) {
    console.log(message);
  }
}

// Varsayılan Gemini model adı
const DEFAULT_GEMINI_MODEL = 'gemini-2.5-flash';

// Varsayılan User-Agent
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0';

const CONFIG = {
  // Güvenli İnternet Ayarları
  BASE_URL: 'https://www.guvenlinet.org.tr',
  SORGU_PATH: '/ajax/sorgu/sorgula.php',
  CAPTCHA_PATH: '/captcha/get_captcha.php',
  REFERER_PATH: '/sorgula',

  HEADERS: {
    get 'User-Agent'() { return process.env.USER_AGENT || DEFAULT_USER_AGENT; },
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Origin': 'https://www.guvenlinet.org.tr',
    'Referer': 'https://www.guvenlinet.org.tr/sorgula',
    'Connection': 'keep-alive',
    'DNT': '1',
    'Sec-GPC': '1',
    'X-Requested-With': 'XMLHttpRequest',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
  },

  // Gemini API Ayarları (.env dosyasından veya varsayılan)
  get GEMINI_MODEL() {
    return process.env.GEMINI_MODEL || DEFAULT_GEMINI_MODEL;
  },
  get GEMINI_API_URL() {
    return `https://generativelanguage.googleapis.com/v1beta/models/${this.GEMINI_MODEL}:generateContent`;
  },
  get GEMINI_MAX_TOKENS() {
    return parseInt(process.env.GEMINI_MAX_TOKENS, 10) || 256;
  },
  GEMINI_PROMPT: `Read the CAPTCHA text. Reply with ONLY the characters (letters and numbers), nothing else. The CAPTCHA is usually 6 characters.`,

  // Yeniden deneme ayarları
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000,

  // HTTP timeout (ms)
  REQUEST_TIMEOUT: 30000,
};

// ============================================================================
// YARDIMCI FONKSİYONLAR
// ============================================================================

/**
 * Cookie'leri parse eder
 */
function parseCookies(setCookieHeaders) {
  if (!setCookieHeaders) return {};
  const cookies = {};
  const cookieArray = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];

  cookieArray.forEach(cookie => {
    const parts = cookie.split(';')[0].split('=');
    if (parts.length >= 2) {
      cookies[parts[0].trim()] = parts.slice(1).join('=').trim();
    }
  });

  return cookies;
}

/**
 * Cookie objesini string'e çevirir
 */
function cookiesToString(cookies) {
  return Object.entries(cookies)
    .map(([key, value]) => `${key}=${value}`)
    .join('; ');
}

/**
 * Domain adının geçerli olup olmadığını kontrol eder
 */
function isValidDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  // Basit domain regex: en az bir nokta, geçerli karakterler
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

/**
 * HTML yanıtını parse eder - Güvenli İnternet formatı
 */
function parseHTML(html, domain) {
  const result = {
    domain: domain,
    aileProfili: null,      // "engelli" veya "erisim"
    cocukProfili: null,     // "engelli" veya "erisim"
    engelliMi: false,
    mesaj: null,
    engelTarihi: null,
  };

  // Hata kontrolü - error.png içeriyorsa engellidir
  if (html.includes('error.png')) {
    result.engelliMi = true;
    result.aileProfili = 'engelli';
    result.cocukProfili = 'engelli';

    // Engel tarihini çıkar
    // title="Bu alan adı aile ve çocuk profilinde görüntülenememektedir. (2024-10-20 22:34:15)"
    const tarihMatch = html.match(/görüntülenememektedir\.\s*\((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\)/);
    if (tarihMatch) {
      result.engelTarihi = tarihMatch[1];
    }

    // Mesajı çıkar
    const mesajMatch = html.match(/<div class="error">([^<]+)<\/div>/);
    if (mesajMatch) {
      result.mesaj = mesajMatch[1].trim();
    }
  }

  // Başarılı erişim - success.png içeriyorsa erişilebilir
  if (html.includes('success.png')) {
    result.engelliMi = false;
    result.aileProfili = 'erisim';
    result.cocukProfili = 'erisim';

    // Mesajı çıkar
    const mesajMatch = html.match(/<div class="success">([^<]+)<\/div>/);
    if (mesajMatch) {
      result.mesaj = mesajMatch[1].trim();
    }
  }

  // Karma durum kontrolü (aile ve çocuk profilleri farklı olabilir)
  // Tablodaki img src değerlerine göre kontrol
  const imgMatches = html.matchAll(/<td[^>]*id="profile"[^>]*>[\s\S]*?<img src="([^"]+)"[^>]*>[\s\S]*?<\/td>/gi);
  const profiles = [];
  for (const match of imgMatches) {
    profiles.push(match[1]);
  }

  if (profiles.length >= 2) {
    result.aileProfili = profiles[0].includes('error.png') ? 'engelli' : 'erisim';
    result.cocukProfili = profiles[1].includes('error.png') ? 'engelli' : 'erisim';
    result.engelliMi = result.aileProfili === 'engelli' || result.cocukProfili === 'engelli';
  }

  return result;
}

/**
 * Bekleme fonksiyonu
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// HTTP İSTEK FONKSİYONLARI
// ============================================================================

/**
 * Sıkıştırılmış veriyi açar
 */
function decompressResponse(buffer, encoding) {
  return new Promise((resolve, reject) => {
    if (!encoding) {
      resolve(buffer);
      return;
    }

    if (encoding === 'gzip') {
      zlib.gunzip(buffer, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    } else if (encoding === 'deflate') {
      zlib.inflate(buffer, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    } else if (encoding === 'br') {
      zlib.brotliDecompress(buffer, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    } else {
      resolve(buffer);
    }
  });
}

/**
 * HTTPS GET isteği yapar (redirect destekli)
 */
function httpsGet(url, options = {}, redirectCount = 0) {
  const MAX_REDIRECTS = 5;

  return new Promise((resolve, reject) => {
    if (redirectCount > MAX_REDIRECTS) {
      reject(new Error('Maksimum redirect sayısı aşıldı'));
      return;
    }

    const urlObj = new URL(url);

    const headers = { ...CONFIG.HEADERS, ...options.headers };

    const reqOptions = {
      hostname: urlObj.hostname,
      port: 443,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: headers,
    };

    // Sadece guvenlinet.org.tr için SSL doğrulamasını devre dışı bırak
    if (urlObj.hostname.includes('guvenlinet.org.tr')) {
      reqOptions.agent = insecureAgent;
    }

    const req = https.request(reqOptions, (res) => {
      // Redirect handling (301, 302, 303, 307, 308)
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const redirectUrl = new URL(res.headers.location, url).href;
        httpsGet(redirectUrl, options, redirectCount + 1)
          .then(resolve)
          .catch(reject);
        return;
      }

      const chunks = [];

      res.on('data', chunk => chunks.push(chunk));
      res.on('end', async () => {
        try {
          const rawData = Buffer.concat(chunks);
          const encoding = res.headers['content-encoding'];
          const data = await decompressResponse(rawData, encoding);

          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            data: data,
          });
        } catch (err) {
          reject(err);
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(CONFIG.REQUEST_TIMEOUT, () => {
      req.destroy();
      reject(new Error(`İstek zaman aşımı (${CONFIG.REQUEST_TIMEOUT / 1000}s)`));
    });
    req.end();
  });
}

/**
 * HTTPS POST isteği yapar (form data)
 */
function httpsPost(url, body, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const postData = typeof body === 'string' ? body : new URLSearchParams(body).toString();

    const reqOptions = {
      hostname: urlObj.hostname,
      port: 443,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        ...CONFIG.HEADERS,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Content-Length': Buffer.byteLength(postData),
        ...options.headers,
      },
    };

    // Sadece guvenlinet.org.tr için SSL doğrulamasını devre dışı bırak
    if (urlObj.hostname.includes('guvenlinet.org.tr')) {
      reqOptions.agent = insecureAgent;
    }

    const req = https.request(reqOptions, (res) => {
      const chunks = [];

      res.on('data', chunk => chunks.push(chunk));
      res.on('end', async () => {
        try {
          const rawData = Buffer.concat(chunks);
          const encoding = res.headers['content-encoding'];
          const data = await decompressResponse(rawData, encoding);

          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            data: data.toString('utf-8'),
          });
        } catch (err) {
          reject(err);
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(CONFIG.REQUEST_TIMEOUT, () => {
      req.destroy();
      reject(new Error(`İstek zaman aşımı (${CONFIG.REQUEST_TIMEOUT / 1000}s)`));
    });
    req.write(postData);
    req.end();
  });
}

/**
 * HTTPS POST isteği yapar (JSON data)
 */
function httpsPostJSON(url, jsonBody, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const postData = JSON.stringify(jsonBody);

    const reqOptions = {
      hostname: urlObj.hostname,
      port: 443,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        ...options.headers,
      },
    };

    const req = https.request(reqOptions, (res) => {
      const chunks = [];

      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const responseData = Buffer.concat(chunks).toString('utf-8');
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data: responseData,
        });
      });
    });

    req.on('error', reject);
    req.setTimeout(CONFIG.REQUEST_TIMEOUT, () => {
      req.destroy();
      reject(new Error(`İstek zaman aşımı (${CONFIG.REQUEST_TIMEOUT / 1000}s)`));
    });
    req.write(postData);
    req.end();
  });
}

// ============================================================================
// GEMINI API FONKSİYONLARI
// ============================================================================

/**
 * Gemini API ile CAPTCHA çözer
 * @param {Buffer} imageBuffer - CAPTCHA resmi buffer'ı
 * @param {string} apiKey - Gemini API anahtarı
 * @returns {Promise<string>} - Çözülmüş CAPTCHA kodu
 */
async function solveCaptchaWithGemini(imageBuffer, apiKey) {
  log('🤖 Gemini API ile CAPTCHA çözülüyor...');

  // Base64'e çevir
  const base64Image = imageBuffer.toString('base64');

  // Gemini API isteği oluştur
  const requestBody = {
    contents: [
      {
        parts: [
          {
            text: CONFIG.GEMINI_PROMPT
          },
          {
            inline_data: {
              mime_type: 'image/jpeg',
              data: base64Image
            }
          }
        ]
      }
    ],
    generationConfig: {
      temperature: 0,
      maxOutputTokens: CONFIG.GEMINI_MAX_TOKENS,
    }
  };

  const url = CONFIG.GEMINI_API_URL;

  try {
    const response = await httpsPostJSON(url, requestBody, {
      headers: {
        'x-goog-api-key': apiKey
      }
    });

    if (response.statusCode !== 200) {
      let errorMsg = `HTTP ${response.statusCode}`;
      try {
        const errorData = JSON.parse(response.data);
        errorMsg = errorData.error?.message || errorMsg;
      } catch {
        // JSON parse hatası - yanıt muhtemelen HTML veya düz metin
        const preview = response.data.substring(0, 100);
        errorMsg = `${errorMsg} - ${preview}`;
      }

      // Spesifik hata mesajları
      if (response.statusCode === 429) {
        throw new Error(`Gemini API kota aşıldı: ${errorMsg}`);
      } else if (response.statusCode === 401 || response.statusCode === 403) {
        throw new Error(`Gemini API yetkilendirme hatası: ${errorMsg}`);
      }
      throw new Error(`Gemini API hatası: ${errorMsg}`);
    }

    const data = JSON.parse(response.data);

    // Güvenlik filtresi kontrolü
    if (data.promptFeedback?.blockReason) {
      throw new Error(`Gemini güvenlik filtresi: ${data.promptFeedback.blockReason}`);
    }

    // Yanıt kontrolü
    const candidate = data.candidates?.[0];
    if (!candidate) {
      throw new Error('Gemini API boş yanıt döndü');
    }

    // finishReason kontrolü
    if (candidate.finishReason && candidate.finishReason !== 'STOP') {
      throw new Error(`Gemini yanıt tamamlanamadı: ${candidate.finishReason}`);
    }

    const text = candidate.content?.parts?.[0]?.text;

    if (!text) {
      throw new Error('Gemini API metin yanıtı vermedi');
    }

    // Sadece alfanumerik karakterleri al (genellikle 6 karakter)
    const captchaCode = text.replace(/[^A-Za-z0-9]/g, '').toLowerCase();

    if (captchaCode.length < 4 || captchaCode.length > 8) {
      throw new Error(`Geçersiz CAPTCHA çıktısı: "${text}" -> "${captchaCode}" (${captchaCode.length} karakter)`);
    }

    log(`✅ CAPTCHA çözüldü: ${captchaCode}`);
    return captchaCode;

  } catch (error) {
    if (error.message.includes('API')) {
      throw error;
    }
    throw new Error(`Gemini API isteği başarısız: ${error.message}`);
  }
}

// ============================================================================
// GÜVENLİ İNTERNET FONKSİYONLARI
// ============================================================================

/**
 * Ana sayfadan session cookie alır
 */
async function getSessionCookies() {
  log('🔗 Session başlatılıyor...');

  const response = await httpsGet(`${CONFIG.BASE_URL}${CONFIG.REFERER_PATH}`);

  if (response.statusCode !== 200) {
    throw new Error(`Session başlatılamadı: HTTP ${response.statusCode}`);
  }

  const cookies = parseCookies(response.headers['set-cookie']);
  log(`✅ Session alındı: ${Object.keys(cookies).length} cookie`);

  return cookies;
}

/**
 * CAPTCHA resmini indirir
 * @param {Object} existingSession - Mevcut session cookie'leri (opsiyonel, yoksa yeni alınır)
 * @returns {Promise<{cookies: Object, imageBuffer: Buffer, captchaPath: string}>}
 */
async function getCaptcha(existingSession = null) {
  // Session cookie al (mevcut varsa kullan, yoksa yeni al)
  const sessionCookies = existingSession || await getSessionCookies();

  // Random sayı ile captcha URL'i oluştur
  const rnd = Math.random();
  const url = `${CONFIG.BASE_URL}${CONFIG.CAPTCHA_PATH}?rnd=${rnd}`;

  log('📥 CAPTCHA indiriliyor...');

  // Cookie header'ı oluştur (boşsa ekleme - WAF boş cookie'yi reddediyor)
  const cookieStr = cookiesToString(sessionCookies);
  const captchaHeaders = {
    'Accept': 'image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5',
    'Accept-Encoding': 'identity', // Sıkıştırma yapma, raw image al
    'Sec-Fetch-Dest': 'image',
    'Sec-Fetch-Mode': 'no-cors',
  };
  if (cookieStr) {
    captchaHeaders.Cookie = cookieStr;
  }

  const response = await httpsGet(url, { headers: captchaHeaders });

  if (response.statusCode !== 200) {
    throw new Error(`CAPTCHA indirilemedi: HTTP ${response.statusCode}`);
  }

  // Cookie'leri birleştir
  const newCookies = parseCookies(response.headers['set-cookie']);
  const cookies = { ...sessionCookies, ...newCookies };

  // Veri kontrolü
  if (!response.data || response.data.length === 0) {
    throw new Error('CAPTCHA resmi boş döndü! Sunucu yanıt vermedi.');
  }

  // JPEG kontrolü - ilk 2 byte FF D8 olmalı (WAF engeli kontrolü)
  if (Buffer.isBuffer(response.data) && (response.data[0] !== 0xFF || response.data[1] !== 0xD8)) {
    const preview = response.data.slice(0, 100).toString('utf8');
    if (preview.includes('Request Rejected')) {
      throw new Error('CAPTCHA isteği WAF tarafından engellendi. Cookie sorunu olabilir.');
    }
    throw new Error(`Geçersiz CAPTCHA yanıtı: ${preview.substring(0, 50)}...`);
  }

  log(`✅ CAPTCHA indirildi: ${response.data.length} bytes`);

  // In-memory buffer kullan, dosyaya kaydetme (race condition önlenir)
  return {
    cookies,
    imageBuffer: response.data
  };
}

/**
 * Alan adı sorgulama isteği gönderir
 */
async function sorgulaSite(domain, captchaCode, cookies) {
  log(`\n🔍 Sorgulanıyor: ${domain}`);

  const formData = {
    domain_name: domain,
    security_code: captchaCode,
  };

  // Cookie header'ı oluştur (boşsa ekleme - WAF boş cookie'yi reddediyor)
  const cookieStr = cookiesToString(cookies);
  const requestHeaders = {};
  if (cookieStr) {
    requestHeaders.Cookie = cookieStr;
  }

  const response = await httpsPost(`${CONFIG.BASE_URL}${CONFIG.SORGU_PATH}`, formData, {
    headers: requestHeaders,
  });

  if (response.statusCode !== 200) {
    throw new Error(`Sorgu başarısız: HTTP ${response.statusCode}`);
  }

  return response.data;
}

/**
 * CAPTCHA hatalı mı kontrol eder
 */
function isCaptchaError(html) {
  // Güvenli İnternet sitesi CAPTCHA hatası durumunda özel bir mesaj dönmüyor gibi görünüyor
  // Boş veya hatalı yanıt kontrolü
  return html.includes('Güvenlik kodu hatalı') ||
    html.includes('security code') ||
    html.includes('Doğrulama kodu') ||
    html.includes('Hatalı kod') ||
    (html.trim().length < 50 && !html.includes('tbl_sorgu'));
}

/**
 * Süreyi okunabilir formata çevirir
 * @param {number} ms - Milisaniye cinsinden süre
 * @returns {string} - Formatlanmış süre (örn: "2.35s" veya "1m 5.2s")
 */
function formatDuration(ms) {
  if (ms < 1000) {
    return `${ms}ms`;
  } else if (ms < 60000) {
    return `${(ms / 1000).toFixed(2)}s`;
  } else {
    const minutes = Math.floor(ms / 60000);
    const seconds = ((ms % 60000) / 1000).toFixed(1);
    return `${minutes}m ${seconds}s`;
  }
}

/**
 * Sonuçları güzel formatta yazdırır
 * @param {Object} result - Sorgu sonucu
 * @param {number} duration - Sorgu süresi (ms)
 */
function printResult(result, duration = null) {
  log('\n' + '═'.repeat(60));
  log(`📌 Domain: ${result.domain}`);
  if (duration !== null) {
    log(`⏱️ Sorgu Süresi: ${formatDuration(duration)}`);
  }
  log('═'.repeat(60));

  if (result.engelliMi) {
    log('🚫 Durum: ENGELLİ');
    log('─'.repeat(60));

    log(`👨‍👩‍👧 Aile Profili: ${result.aileProfili === 'engelli' ? '❌ Engelli' : '✅ Erişilebilir'}`);
    log(`👶 Çocuk Profili: ${result.cocukProfili === 'engelli' ? '❌ Engelli' : '✅ Erişilebilir'}`);

    if (result.engelTarihi) {
      log(`📅 Engel Tarihi: ${result.engelTarihi}`);
    }

    if (result.mesaj) {
      log('─'.repeat(60));
      log(`📝 Mesaj: ${result.mesaj}`);
    }
  } else {
    log('✅ Durum: ERİŞİLEBİLİR');
    log('─'.repeat(60));
    log(`👨‍👩‍👧 Aile Profili: ✅ Erişilebilir`);
    log(`👶 Çocuk Profili: ✅ Erişilebilir`);

    if (result.mesaj) {
      log('─'.repeat(60));
      log(`📝 Mesaj: ${result.mesaj}`);
    }
  }

  log('═'.repeat(60) + '\n');

  return result;
}

/**
 * JSON formatında çıktı verir
 * @param {Object} result - Sorgu sonucu
 * @param {number} duration - Sorgu süresi (ms)
 */
function outputJSON(result, duration = null) {
  const output = {
    timestamp: new Date().toISOString(),
    status: true,
    ...(duration !== null && { queryDuration: duration, queryDurationFormatted: formatDuration(duration) }),
    ...result,
  };

  console.log(JSON.stringify(output, null, 2));
  return output;
}

/**
 * JSON formatında hata çıktısı verir
 */
function outputJSONError(domain, message) {
  const output = {
    domain: domain || null,
    timestamp: new Date().toISOString(),
    status: false,
    error: message,
  };

  console.log(JSON.stringify(output, null, 2));
  return output;
}

/**
 * Yardım mesajını gösterir
 */
function showHelp() {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║     Güvenli İnternet Hizmeti (GİH) Sorgu Aracı             ║
╚════════════════════════════════════════════════════════════╝

v${VERSION}

Kullanım:
  node gih-sorgu.js [seçenekler] <domain>

Seçenekler:
  --liste <dosya>     Dosyadan site listesi oku
  --json              JSON formatında çıktı
  --version, -v       Versiyon bilgisini göster
  --help, -h          Bu yardım mesajını göster

Örnekler:
  node gih-sorgu.js discord.com
  node gih-sorgu.js discord.com twitter.com google.com
  node gih-sorgu.js --liste sites.txt
  node gih-sorgu.js --json twitter.com

Ortam Değişkenleri (.env dosyası veya sistem ortamı):
  GEMINI_API_KEY      Google Gemini API anahtarı (ZORUNLU)
  GEMINI_MODEL        Gemini model adı (varsayılan: gemini-2.5-flash)

.env Dosyası Örneği:
  GEMINI_API_KEY=AIzaSy...your_api_key_here
  GEMINI_MODEL=gemini-2.5-flash

API Anahtarı Alma:
  https://aistudio.google.com/app/apikey
  
Kaynak:
  https://www.guvenlinet.org.tr/sorgula
`);
}

// ============================================================================
// ANA PROGRAM
// ============================================================================

async function main() {
  // Komut satırı argümanlarını parse et
  const args = process.argv.slice(2);

  // Versiyon kontrolü
  if (args.includes('--version') || args.includes('-v')) {
    console.log(`Güvenli İnternet Sorgu Aracı v${VERSION}`);
    process.exit(0);
  }

  // Yardım kontrolü
  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    showHelp();
    process.exit(args.length === 0 ? 1 : 0);
  }

  let domains = [];
  let jsonOutput = false;

  // Önce --json flag'ini kontrol et (log fonksiyonu için)
  if (args.includes('--json')) {
    jsonOutput = true;
    JSON_OUTPUT = true;
  }

  log(`
╔════════════════════════════════════════════════════════════╗
║     Güvenli İnternet Hizmeti (GİH) Sorgu Aracı             ║
╚════════════════════════════════════════════════════════════╝
`);

  // Argümanları işle
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--liste' && args[i + 1]) {
      const listFile = args[i + 1];
      if (!fs.existsSync(listFile)) {
        if (JSON_OUTPUT) {
          outputJSONError(null, `Dosya bulunamadı: ${listFile}`);
        } else {
          console.error(`❌ Dosya bulunamadı: ${listFile}`);
        }
        process.exit(1);
      }
      const content = fs.readFileSync(listFile, 'utf-8');
      domains = content.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      i++;
    } else if (args[i] === '--json') {
      // Zaten yukarıda işlendi
    } else if (!args[i].startsWith('--')) {
      domains.push(args[i]);
    }
  }

  if (domains.length === 0) {
    if (JSON_OUTPUT) {
      outputJSONError(null, 'Sorgulanacak domain belirtilmedi');
    } else {
      console.error('❌ Sorgulanacak domain belirtilmedi!');
      console.log('   Kullanım: node gih-sorgu.js <domain>');
    }
    process.exit(1);
  }

  // Domain validasyonu
  const invalidDomains = domains.filter(d => !isValidDomain(d));
  if (invalidDomains.length > 0) {
    if (JSON_OUTPUT) {
      invalidDomains.forEach(d => log(`Geçersiz domain atlandı: ${d}`));
    } else {
      invalidDomains.forEach(d => console.warn(`⚠️  Geçersiz domain atlandı: ${d}`));
    }
    domains = domains.filter(d => isValidDomain(d));
    if (domains.length === 0) {
      if (JSON_OUTPUT) {
        outputJSONError(null, 'Geçerli domain bulunamadı');
      } else {
        console.error('❌ Geçerli domain bulunamadı!');
      }
      process.exit(1);
    }
  }

  // Gemini API key kontrolü (ZORUNLU)
  const geminiApiKey = process.env.GEMINI_API_KEY;
  if (!geminiApiKey) {
    if (JSON_OUTPUT) {
      outputJSONError(null, 'GEMINI_API_KEY ayarlanmamış');
    } else {
      console.error('❌ GEMINI_API_KEY ayarlanmamış!');
      console.log('');
      console.log('   Seçenek 1: .env dosyası oluşturun');
      console.log('   GEMINI_API_KEY=your_api_key');
      console.log('');
      console.log('   Seçenek 2: Ortam değişkeni ayarlayın');
      console.log('   Windows: set GEMINI_API_KEY=your_api_key');
      console.log('   Linux/Mac: export GEMINI_API_KEY=your_api_key');
      console.log('');
      console.log('   API anahtarı almak için: https://aistudio.google.com/app/apikey');
    }
    process.exit(1);
  }

  log(`📋 Sorgulanacak ${domains.length} site: ${domains.join(', ')}`);
  log(`🤖 Model: ${CONFIG.GEMINI_MODEL}\n`);

  const results = [];
  let retryCount = 0;
  let sharedSession = null; // Session cookie'lerini sakla
  let queryStartTime = null; // Sorgu başlangıç zamanı

  try {
    while (retryCount < CONFIG.MAX_RETRIES) {
      // Sorgu süresini ölç (ilk site için)
      queryStartTime = Date.now();

      // 1. CAPTCHA al (ilk seferde session da alınır)
      const { cookies, imageBuffer } = await getCaptcha();
      sharedSession = cookies; // Session'ı sakla

      let captchaCode;

      // Gemini ile otomatik çöz
      try {
        captchaCode = await solveCaptchaWithGemini(imageBuffer, geminiApiKey);
      } catch (error) {
        if (JSON_OUTPUT) {
          log(`CAPTCHA çözülemedi: ${error.message}`);
        } else {
          console.error(`❌ CAPTCHA çözülemedi: ${error.message}`);
        }
        retryCount++;
        if (retryCount < CONFIG.MAX_RETRIES) {
          log(`🔄 Yeniden deneniyor (${retryCount}/${CONFIG.MAX_RETRIES})...`);
          await sleep(CONFIG.RETRY_DELAY);
          continue;
        }
        throw error;
      }

      // 3. İlk siteyi sorgula (CAPTCHA doğrulama)
      const firstDomain = domains[0];
      const firstHtml = await sorgulaSite(firstDomain, captchaCode, cookies);

      // CAPTCHA hatalı mı kontrol et
      if (isCaptchaError(firstHtml)) {
        log('⚠️  CAPTCHA kodu hatalı!');
        retryCount++;
        if (retryCount < CONFIG.MAX_RETRIES) {
          log(`🔄 Yeni CAPTCHA ile deneniyor (${retryCount}/${CONFIG.MAX_RETRIES})...`);
          await sleep(CONFIG.RETRY_DELAY);
          continue;
        }
        throw new Error('CAPTCHA çözümü başarısız oldu');
      }

      // İlk sonucu işle
      const firstResult = parseHTML(firstHtml, firstDomain);
      const firstDuration = Date.now() - queryStartTime;
      if (jsonOutput) {
        results.push(outputJSON(firstResult, firstDuration));
      } else {
        results.push(printResult(firstResult, firstDuration));
      }

      // Başarılı - döngüden çık
      break;
    }

    // 4. Kalan siteleri sorgula (session'ı yeniden kullan, sadece yeni CAPTCHA al)
    for (let i = 1; i < domains.length; i++) {
      const domain = domains[i];
      let domainRetry = 0;

      while (domainRetry < CONFIG.MAX_RETRIES) {
        try {
          // Sorgu süresini ölç
          const domainStartTime = Date.now();

          // Mevcut session'ı kullanarak sadece yeni CAPTCHA al
          const { cookies: newCookies, imageBuffer: newImage } = await getCaptcha(sharedSession);

          const newCaptchaCode = await solveCaptchaWithGemini(newImage, geminiApiKey);

          const html = await sorgulaSite(domain, newCaptchaCode, newCookies);

          // CAPTCHA hatalı mı?
          if (isCaptchaError(html)) {
            domainRetry++;
            if (domainRetry < CONFIG.MAX_RETRIES) {
              log(`⚠️  CAPTCHA hatalı, yeniden deneniyor (${domainRetry}/${CONFIG.MAX_RETRIES})...`);
              // Session geçersiz olmuş olabilir, yeni session dene
              sharedSession = null;
              await sleep(CONFIG.RETRY_DELAY);
              continue;
            }
            throw new Error('CAPTCHA çözümü başarısız');
          }

          // Başarılı sorgu sonrası session'ı güncelle
          sharedSession = newCookies;

          const result = parseHTML(html, domain);
          const domainDuration = Date.now() - domainStartTime;

          if (jsonOutput) {
            results.push(outputJSON(result, domainDuration));
          } else {
            results.push(printResult(result, domainDuration));
          }

          break; // Bu domain için başarılı

        } catch (error) {
          domainRetry++;
          // Hata durumunda session'ı sıfırla, yeni denemelerde temiz başlasın
          sharedSession = null;
          if (domainRetry >= CONFIG.MAX_RETRIES) {
            if (jsonOutput) {
              results.push(outputJSONError(domain, error.message));
            } else {
              console.error(`❌ ${domain} sorgulanırken hata: ${error.message}`);
            }
          } else {
            log(`🔄 ${domain} için yeniden deneniyor...`);
            await sleep(CONFIG.RETRY_DELAY);
          }
        }
      }

      // Rate limiting
      if (i < domains.length - 1) {
        await sleep(500);
      }
    }

    // 5. Sonuç özeti
    if (!jsonOutput && domains.length > 1) {
      log('\n📊 ÖZET');
      log('═'.repeat(60));

      const blocked = results.filter(r => r?.engelliMi).length;
      const accessible = results.filter(r => r && !r.engelliMi).length;
      const failed = domains.length - results.length;

      log(`   🚫 Engelli: ${blocked}`);
      log(`   ✅ Erişilebilir: ${accessible}`);
      if (failed > 0) {
        log(`   ❓ Hatalı: ${failed}`);
      }
      log('═'.repeat(60));
    }

  } catch (error) {
    if (JSON_OUTPUT) {
      outputJSONError(null, error.message);
    } else {
      console.error(`\n❌ Hata: ${error.message}`);
    }
    process.exit(1);
  }
}

// Programı çalıştır
main().catch(error => {
  if (JSON_OUTPUT) {
    outputJSONError(null, error.message);
  } else {
    console.error(`\n❌ Beklenmeyen hata: ${error.message}`);
  }
  process.exit(1);
});
