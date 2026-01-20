# 🛡️ AI Security Scanner
> **Yapay Zeka Destekli Otomatik Güvenlik Zafiyet Tarayıcısı**

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![AI Powered](https://img.shields.io/badge/AI-Powered-Gemini%20Pro-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-SQL%20Injection-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Durum-Aktif-success?style=for-the-badge)

## 📋 Proje Hakkında
**AI Security Scanner**, geleneksel kod tarama yöntemlerinin yetersiz kaldığı durumlarda, **Büyük Dil Modellerinin (LLM)** gücünü kullanarak güvenlik açıklarını tespit eden yeni nesil bir araçtır.

Bu proje, özellikle eski (legacy) PHP kod tabanlarındaki **SQL Injection** zafiyetlerini tespit etmek için **Prompt Engineering (İstem Mühendisliği)** tekniklerini kullanır. Regex tabanlı tarayıcıların aksine, kodun bağlamını anlayarak daha düşük hata oranıyla (False Positive) çalışır.

---

## 🚀 Öne Çıkan Özellikler
* **🧠 Yapay Zeka Analizi:** Kod bloklarını anlamlandırır ve mantıksal hataları bulur.
* **⚡ Otomasyon:** Python tabanlı script ile dosyaları saniyeler içinde tarar.
* **🎨 Renkli Raporlama:** Terminal üzerinden okunabilir, renk kodlu (Yeşil/Kırmızı) çıktılar üretir.
* **🛠️ Hazır Prompt Şablonları:** LLM'e en doğru soruyu sormak için optimize edilmiş istemler içerir.
* **📄 Loglama:** Her tarama sonrası doğrulama için log dosyası (`validation_log.txt`) oluşturur.

---

## 🛠️ Kullanılan Teknolojiler
Bu proje geliştirilirken aşağıdaki araçlar ve kütüphaneler kullanılmıştır:

| Teknoloji | Amaç |
| :--- | :--- |
| **Python 3.12** | Ana otomasyon ve script dili |
| **VS Code** | Geliştirme ortamı (IDE) |
| **Git & GitHub** | Versiyon kontrolü ve proje yönetimi |
| **Prompt Engineering** | AI modelini yönlendirme stratejisi |
| **JSON** | Veri yapılandırması ve proje kimliği |

---

## 📂 Proje Mimarisi
Proje dosyaları, modüler bir yapıda organize edilmiştir:

```bash
AI-SECURITY-SCANNER/
├── 🧠 src/                 # Ana Beyin (Çalışan Kodlar)
│   └── scanner.py          # Tarama işlemini yapan Python scripti
├── 📝 prompts/             # Prompt Mühendisliği Dosyaları
│   └── sql_injection.txt   # Yapay zekaya verilen analiz talimatı
├── 📚 researchs/           # Araştırma ve Dokümantasyon
│   ├── gemini-pro/         # Gemini ile yapılan prompt deneyleri
│   └── ...
├── 🧪 tests/               # Test Ortamı
│   └── vulnerable_code.php # Zafiyet içeren örnek (hedef) dosya
├── 📄 project_info.json    # Proje Kimlik Kartı
├── 📦 requirements.txt     # Gerekli Kütüphaneler
└── 📜 README.md            # Proje Tanıtım Dosyası (Buradasınız)
```

---

## ⚙️ Kurulum ve Çalıştırma

### 1️⃣ Gereksinimler
- Python 3.8+
- Pip paket yöneticisi
- Git (opsiyonel)

### 2️⃣ Adım Adım Kurulum

```bash
# Proje dizinine gir
cd ai-security-scanner

# Gerekli kütüphaneleri kur
pip install -r requirements.txt
```

### 3️⃣ Scanner'ı Çalıştır

**Varsayılan hedef dosya ile (vulnerable_code.php):**
```bash
python src/scanner.py
```

**Özel bir dosyayı taramak için:**
```bash
python src/scanner.py path/to/your/file.php
```

---

## 📊 Örnek Çıktı

```
╔═══════════════════════════════════════╗
║                                       ║
║        🔒  AI SECURITY SCANNER  🔒    ║
║                                       ║
║     Professional Security Analysis    ║
║                                       ║
╚═══════════════════════════════════════╝

[*] Connecting to LLM Engine...
[✓] Connected to AI Engine

[*] Scanning target file: tests/vulnerable_code.php
[✓] File loaded (2677 bytes)

[*] Analyzing code patterns...

[CRITICAL] ══════════════════════════════════════════════════
[CRITICAL] CRITICAL VULNERABILITY DETECTED!
[CRITICAL] ══════════════════════════════════════════════════
[CRITICAL] Type: SQL Injection
[CRITICAL] Severity: CRITICAL
[CRITICAL] Description: Unsanitized user input detected in SQL query
[CRITICAL] Risk: Complete database compromise possible
```

---

## 🔍 Tespit Edilen Açık Türleri

| Açık Türü | Açıklama | Risk Seviyesi |
| :--- | :--- | :--- |
| **SQL Injection** | Veritabanı sorgularına geçersiz SQL kodu enjeksiyonu | 🔴 KRITIK |
| **XSS** | Web sayfasına kötü amaçlı JavaScript kodunun eklenmesi | 🟠 YÜKSEK |
| **Path Traversal** | Dosya sistemine yetkisiz erişim | 🟠 YÜKSEK |

---

## 🔧 Gelişmiş Özellikler

### Özel Dosya Taraması
```bash
python src/scanner.py /path/to/legacy_code.php
python src/scanner.py C:\Users\User\Documents\app.php
```

### Toplu Tarama (Opsiyonel)
```bash
python src/scanner.py --scan-dir ./src --output report.json
```

---

## 📈 Proje Yol Haritası

- [x] SQL Injection tespit motoru
- [x] Renkli terminal çıktısı
- [x] Zafiyet içeren test dosyası
- [ ] Birden fazla zafiyet türü desteği
- [ ] Web arayüzü (Dashboard)
- [ ] API sunucusu
- [ ] Veritabanı entegrasyonu

---

## 👨‍💻 Geliştirici Bilgileri

**Proje Adı:** AI Security Scanner  
**Amaç:** Üniversite Ödevi - Güvenlik Araştırması  
**Sürüm:** 1.0.0  
**Durum:** ✅ Aktif Geliştirme

---

## 📝 Lisans & Uyarı

⚠️ **ÖNEMLİ:** Bu projede örnek olarak sunulan PHP dosyası **kasıtlı olarak zafiyetli**dir. Sadece **eğitim amaçlı** kullanılmalıdır. Gerçek üretime asla deploy edilmemelidir.

---

## 🤝 Katkıda Bulunma

İyileştirme önerileri ve hata raporları için lütfen PR açın veya issue oluşturun.

---

## 📞 İletişim

Sorular ve öneriler için proje sahibine ulaşabilirsiniz.

---

## 🌟 Projeyi Beğendiysen

Eğer bu proje yararlı olduysa, lütfen ⭐ ile destekle!

**Happy Scanning! 🔒**

