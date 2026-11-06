# 🛡️ Security Sentinel Ultra v4.0 (Next-Gen Portable EDR)

**Autonomous Endpoint Threat Defense, Guardian Twin Self-Defense & Real-Time Behavioral Watchdog for Windows 10 / 11**  
*Zero-Dependency • Event-Driven (0% Gaming FPS Impact) • Tier 1–5 + Next-Gen v4.0 Architecture*

---

## 🌟 Overview (ภาพรวมระบบ v4.0 Next-Gen)

**Security Sentinel Ultra v4.0** คือระบบป้องกัน Endpoint ขนาดพกพา (Portable EDR / HIDS) ที่พัฒนาด้วยสถาปัตยกรรม **Native Zero-Dependency** โดยใช้เครื่องมือและ API มาตรฐานที่ติดตั้งมาพร้อมกับ Windows 10 และ Windows 11 ทั้งหมด 100% (`PowerShell 5.1`, `.NET CLR`, `WPF/XAML`, `C# P/Invoke Native API`, `FileSystemWatcher`, และ `WMI/CIM Real-Time Event Stream`) ไม่จำเป็นต้องติดตั้ง Python, Node.js หรือโปรแกรมเสริมใดๆ

### 🚀 5 โมดูลอัปเกรดใหม่ล่าสุดในเวอร์ชัน v4.0 (Next-Gen EDR Capabilities)

1. **Guardian Twin & DACL Tamper Protection (ระบบป้องกันตัวเอง 2 ชั้น):**
   * มีโปรเซสคู่แฝด (`SentinelWatchdog.ps1` + `SentinelGuardian.ps1`) เฝ้าระวัง Heartbeat กันเองตลอดเวลา พร้อมล็อก DACL Handle
   * หากมัลแวร์พยายามสั่ง Kill หรือปิดโปรเซสหลัก ตัวแฝดจะ **ชุบชีวิต (Resurrect) ตัวหลักกลับมาทำงานทันทีภายในเสี้ยววินาที** พร้อมยิงแจ้งเตือนฉุกเฉินเข้า Discord `@everyone`
2. **Real-Time WMI/CIM Kernel Process Stream (ตรวจจับโปรเซสเกิดใหม่ระดับเสี้ยววินาที):**
   * เชื่อมต่อกับ `__InstanceCreationEvent (Win32_Process)` เพื่อดักจับโปรเซสที่เพิ่งถูกสร้างขึ้นแบบ Asynchronous ทันทีโดยไม่ต้องรอรอบสแกน
3. **DLL Injection & Memory Module Guard (สกัดการแอบฝัง DLL เถื่อนในเบราว์เซอร์และเกม):**
   * ตรวจสอบ Module (`.dll`) ที่ถูกโหลดเข้าสู่หน่วยความจำของ `Chrome`, `Edge`, `Brave`, `Discord`, `Steam`, `Roblox`, และ `Riot Client` แบบแคช 0% CPU
   * หากพบ DLL ที่ไม่มีใบรับรองดิจิทัลแอบฉีดเข้ามาจาก `%TEMP%` หรือ `Downloads` ระบบจะแจ้งเตือนและสกัดกั้นทันที
4. **Automated Memory Forensic & C2 Extractor (ถอดรหัสเซิร์ฟเวอร์แฮกเกอร์อัตโนมัติ):**
   * เมื่อแช่แข็งมัลแวร์ด้วย `NtSuspendProcess` เอนจิน C# จะสแกนดึง **Discord Webhook ของแฮกเกอร์, Telegram Bot Token, Ngrok/Cloudflare Tunnel, และ IP เซิร์ฟเวอร์ C2** รวมถึงตรวจสอบ Active TCP Connections แล้วบันทึกหลักฐานลงไฟล์ `quarantine/forensic_PID_*.json` พร้อมแสดงผลบนการ์ดแจ้งเตือน Discord ทันที
5. **Local Micro-ML Heuristic & Shannon Entropy Engine (วิเคราะห์ความเสี่ยงด้วยคณิตศาสตร์ในเครื่อง):**
   * คำนวณค่า **Shannon Byte Entropy (`0.00 – 8.00`)** ด้วยโค้ด C# ความเร็วสูง เพื่อตรวจจับไฟล์มัลแวร์ที่ถูก Pack / Encrypt / Crypter อำพรางโค้ด และประเมินคะแนน **Heuristic Risk Score (`0 – 100`)** โดยไม่ต้องพึ่งพา Cloud

---

### 🎯 สถาปัตยกรรมป้องกันภัยคุกคาม 5 ระดับ (Tier 1 – Tier 5 Master Architecture)

| ระดับ (Tier) | โมดูลป้องกัน | กลไกการทำงานทางเทคนิค |
| :--- | :--- | :--- |
| **Tier 1** | **Core Watchdog & Browser Guard** | เฝ้าระวังโฟลเดอร์ `User Data` ของ Chrome, Edge, Brave, Opera แบบ Real-time ป้องกันการขโมยคุกกี้และการหย่อน DLL แปลกปลอม พร้อมเฝ้าระวัง Persistence 28+ จุด + กับดัก **Canary Honeypot** ดักจับ Game Infostealer (Roblox, Steam, Riot, Crypto) |
| **Tier 2** | **Real-Time Process & Anomaly Telemetry** | ดักจับ **Parent-Child Process Anomaly** ผ่าน WMI Event Stream (เช่น เบราว์เซอร์หรือตัวรันเกมแอบเปิด `powershell.exe`, `cmd.exe`, `mshta.exe`, `regsvr32.exe`, `certutil.exe`) และดักจับคำสั่งเข้ารหัสอำพราง (`-EncodedCommand` / `IEX`) |
| **Tier 3** | **Automated Response & Guardian Twin** | คอมไพล์โค้ด C# P/Invoke เรียกใช้ `ntdll.dll!NtSuspendProcess` แช่แข็งโปรเซสมัลแวร์ในเสี้ยววินาที, ระบบ **Guardian Twin** ชุบชีวิตอัตโนมัติ และปุ่ม **Emergency Network Killswitch** ตัดเน็ตฉุกเฉินในคลิกเดียว |
| **Tier 4** | **Zero-Trust, DLL Guard & Micro-ML** | ดักจับไฟล์ `.exe` และ `.dll` แปลกปลอมใน `%TEMP%`, คำนวณค่า **Shannon Entropy**, เปิดบันทึก **PowerShell Script Block Logging (Event ID 4104)** และปกป้องหน่วยความจำ **LSASS (`RunAsPPL`)** |
| **Tier 5** | **Forensic C2 Triage & Discord Webhook** | คำนวณค่าแฮช **SHA-256** แนบลิงก์ **VirusTotal**, สกัดลิงก์ **C2 / Webhook ของแฮกเกอร์** จากไฟล์มัลแวร์ และส่งการ์ดแจ้งเตือน **Rich Embed** เข้าห้อง **Discord Webhook** แบบเรียลไทม์ |

---

## 📂 โครงสร้างโปรเจกต์ (Project Structure)

```text
SecuritySentinel_Portable/
├── 1-Click-Install.bat                         # คลิกเดียวเพื่อติดตั้ง ตั้งค่า Hardening และเริ่มรัน Watchdog + Guardian Twin
├── 1-Click-Uninstall.bat                       # คลิกเดียวเพื่อถอนการติดตั้งและล้างไฟล์กับดักทั้งหมด
├── Sentinel-Dashboard.bat                      # เปิดหน้าต่าง Cyber-SOC GUI Command Center Dashboard (v4.0)
├── README.txt                                  # คู่มือการใช้งานภาษาไทยฉบับย่อ
├── Security_Sentinel_Master_Plan.pdf           # เอกสารแผนแม่บทสถาปัตยกรรม (Master Engineering Plan)
├── Security_Sentinel_SourceCode_and_Tools.pdf  # เอกสารสรุปโครงสร้าง Source Code และเครื่องมือที่ใช้พัฒนา
└── core/
    ├── config.json                             # ไฟล์เก็บค่าตั้งค่าและลิงก์ Discord Webhook
    ├── Install.ps1                             # สคริปต์ติดตั้งระบบ, เปิด Event 4104 / LSASS RunAsPPL, สร้าง Task & Shortcut
    ├── SentinelWatchdog.ps1                    # เอนจินป้องกันหลัก v4.0 (Tier 1-5 + WMI Stream + DLL Guard + C2 Forensics)
    ├── SentinelGuardian.ps1                    # เอนจินคู่แฝด Guardian Twin เฝ้าระวังและชุบชีวิต Watchdog อัตโนมัติ
    ├── SentinelDashboard.ps1                   # หน้าจอควบคุมหลัก WPF/XAML GUI + มาตรวัด CPU/RAM เรียลไทม์
    └── Uninstall.ps1                           # สคริปต์ถอนการติดตั้งและทำความสะอาดระบบอย่างสมบูรณ์
```

---

## 🚀 วิธีติดตั้งและใช้งาน (Quick Start)

1. ดาวน์โหลดหรือ Clone โปรเจกต์นี้ลงบนเครื่องคอมพิวเตอร์ (Windows 10 / 11)
2. ดับเบิลคลิกไฟล์ **`1-Click-Install.bat`**
   * ระบบจะทำการติดตั้งเอนจินลงใน `%LOCALAPPDATA%\SecuritySentinel`
   * เปิดเกราะป้องกัน Windows และลงทะเบียน Auto-Start ใน Task Scheduler พร้อมเปิดทำงาน **Guardian Twin**
   * สร้างไอคอน **Security Sentinel Dashboard** ไว้บนหน้า Desktop อัตโนมัติ
3. เปิดหน้าต่างควบคุมโดยดับเบิลคลิกที่ **`Sentinel-Dashboard.bat`** หรือไอคอนบนหน้าจอ Desktop
4. **(ตัวเลือกเสริม)** นำลิงก์ **Discord Webhook URL** มาวางในช่องบนหน้าจอ Dashboard แล้วกด **`[SAVE] Save Config`** และ **`[TEST] Test Notification`** เพื่อรับการแจ้งเตือนเข้ามือถือทันที!

---

## 🎮 ประสิทธิภาพและการรองรับการเล่นเกม (Gaming & Anti-Cheat Compatibility)

* **CPU Usage ขณะปกติ:** `0.0% – 0.2%` (ทำงานแบบ Event-Driven + HashSet Module Cache ตื่นเฉพาะเมื่อมีเหตุการณ์)
* **RAM Footprint:** `~30 MB (Watchdog) + ~10 MB (Guardian Twin)`
* **Anti-Cheat Safe:** รองรับการทำงานร่วมกับ **Riot Vanguard (Valorant)**, **Easy Anti-Cheat (EAC)**, **BattlEye**, และ **Wellbia** 100% เนื่องจากทำงานในโหมด User-Mode Telemetry โดยไม่แทรกแซงหน่วยความจำของเกม พร้อมระบบ Trusted Publisher Whitelist ครอบคลุมค่ายเกมสากล (`Roblox Corporation`, `KRAFTON (PUBG)`, `Overwolf`, `Riot Games`, `Valve Corp (Steam)`, `Epic Games`, `Blizzard`, `EA`, `Ubisoft`, `Discord`, `NVIDIA`, `AMD`, `Intel`, `Logitech`, `Razer`)
* **Game Infostealer Defense:** มีกับดัก Canary Honeypot ดักจับมัลแวร์ขโมยคุกกี้ Roblox (`.ROBLOSECURITY`), Steam Session (`ssfn`), และ Riot Token โดยอัตโนมัติ
