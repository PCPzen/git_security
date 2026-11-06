# 🛡️ Security Sentinel Ultra v3.2 (Portable EDR)

**Autonomous Endpoint Threat Defense & Real-Time Behavioral Watchdog for Windows 10 / 11**  
*Zero-Dependency • Event-Driven (0% Gaming FPS Impact) • Tier 1–5 Master Architecture*

---

## 🌟 Overview (ภาพรวมระบบ)

**Security Sentinel Ultra** คือระบบป้องกัน Endpoint ขนาดพกพา (Portable EDR / HIDS) ที่พัฒนาด้วยสถาปัตยกรรม **Native Zero-Dependency** โดยใช้เครื่องมือและ API มาตรฐานที่ติดตั้งมาพร้อมกับ Windows 10 และ Windows 11 ทั้งหมด 100% (`PowerShell 5.1`, `.NET CLR`, `WPF/XAML`, `C# P/Invoke Native API`, `FileSystemWatcher`, และ `WMI/CIM`) ไม่จำเป็นต้องติดตั้ง Python, Node.js หรือโปรแกรมเสริมใดๆ

### 🎯 สถาปัตยกรรมป้องกันภัยคุกคาม 5 ระดับ (Tier 1 – Tier 5 Architecture)

| ระดับ (Tier) | โมดูลป้องกัน | กลไกการทำงานทางเทคนิค |
| :--- | :--- | :--- |
| **Tier 1** | **Core Watchdog & Browser Guard** | เฝ้าระวังโฟลเดอร์ `User Data` ของ Chrome, Edge, Brave, Opera แบบ Real-time ป้องกันการแอบหย่อน DLL แปลกปลอม (เคส NIKKE / Discord Mod) พร้อมตรวจ `Authenticode Signature` และเฝ้าระวัง Persistence 28+ จุด + กับดัก Canary Honeypot |
| **Tier 2** | **Process & Parent-Child Telemetry** | ตรวจจับพฤติกรรม **Parent-Child Process Anomaly** (เช่น เบราว์เซอร์หรือตัวรันเกมแอบเปิด `powershell.exe`, `cmd.exe`, `mshta.exe`, `regsvr32.exe`, `certutil.exe`) และดักจับคำสั่งเข้ารหัสอำพราง (`-EncodedCommand` / `IEX`) |
| **Tier 3** | **Automated Incident Response** | คอมไพล์โค้ด C# P/Invoke เรียกใช้งาน `ntdll.dll!NtSuspendProcess` เพื่อแช่แข็ง (Micro-Freeze) โปรเซสมัลแวร์ในเสี้ยววินาที พร้อมปุ่ม **Emergency Network Killswitch** ตัดเน็ตฉุกเฉินในคลิกเดียว |
| **Tier 4** | **Zero-Trust & OS Hardening** | ดักจับไฟล์ `.exe` ที่ไม่มีใบรับรองดิจิทัลที่แอบรันจาก `%TEMP%`, เปิดบันทึก **PowerShell Script Block Logging (Event ID 4104)** และปกป้องหน่วยความจำ **LSASS (`RunAsPPL`)** |
| **Tier 5** | **Threat Intel & Discord Webhook** | คำนวณค่าแฮช **SHA-256** ของไฟล์ต้องสงสัยอัตโนมัติ แนบลิงก์ตรวจสอบบน **VirusTotal** และส่งการ์ดแจ้งเตือน **Rich Embed** เข้าห้อง **Discord Webhook** แบบเรียลไทม์ |

---

## 📂 โครงสร้างโปรเจกต์ (Project Structure)

```text
SecuritySentinel_Portable/
├── 1-Click-Install.bat                         # คลิกเดียวเพื่อติดตั้ง ตั้งค่า Hardening และเริ่มรันเกราะป้องกันอัตโนมัติ
├── 1-Click-Uninstall.bat                       # คลิกเดียวเพื่อถอนการติดตั้งและล้างไฟล์กับดักทั้งหมด
├── Sentinel-Dashboard.bat                      # เปิดหน้าต่าง Cyber-SOC GUI Command Center Dashboard
├── README.txt                                  # คู่มือการใช้งานภาษาไทยฉบับย่อ
├── Security_Sentinel_Master_Plan.pdf           # เอกสารแผนแม่บทสถาปัตยกรรม (Master Engineering Plan)
├── Security_Sentinel_SourceCode_and_Tools.pdf  # เอกสารสรุปโครงสร้าง Source Code และเครื่องมือที่ใช้พัฒนา
└── core/
    ├── config.json                             # ไฟล์เก็บค่าตั้งค่าและลิงก์ Discord Webhook
    ├── Install.ps1                             # สคริปต์ติดตั้งระบบ, เปิด Event 4104 / LSASS RunAsPPL, สร้าง Task & Shortcut
    ├── SentinelWatchdog.ps1                    # เอนจินป้องกันเบื้องหลัง (Daemon ทำงานตลอด 24 ชม. ครบทั้ง Tier 1-5)
    ├── SentinelDashboard.ps1                   # หน้าจอควบคุมหลัก WPF/XAML GUI + มาตรวัด CPU/RAM เรียลไทม์
    └── Uninstall.ps1                           # สคริปต์ถอนการติดตั้งและทำความสะอาดระบบ
```

---

## 🚀 วิธีติดตั้งและใช้งาน (Quick Start)

1. ดาวน์โหลดหรือ Clone โปรเจกต์นี้ลงบนเครื่องคอมพิวเตอร์ (Windows 10 / 11)
2. ดับเบิลคลิกไฟล์ **`1-Click-Install.bat`**
   * ระบบจะทำการติดตั้งเอนจินลงใน `%LOCALAPPDATA%\SecuritySentinel`
   * เปิดเกราะป้องกัน Windows และลงทะเบียน Auto-Start ใน Task Scheduler
   * สร้างไอคอน **Security Sentinel Dashboard** ไว้บนหน้า Desktop อัตโนมัติ
3. เปิดหน้าต่างควบคุมโดยดับเบิลคลิกที่ **`Sentinel-Dashboard.bat`** หรือไอคอนบนหน้าจอ Desktop
4. **(ตัวเลือกเสริม)** นำลิงก์ **Discord Webhook URL** มาวางในช่องบนหน้าจอ Dashboard แล้วกด **`[SAVE] Save Config`** และ **`[TEST] Test Notification`** เพื่อรับการแจ้งเตือนเข้ามือถือทันที!

---

## 🎮 ประสิทธิภาพและการรองรับการเล่นเกม (Gaming & Anti-Cheat Compatibility)

* **CPU Usage ขณะปกติ:** `0.0% – 0.2%` (ทำงานแบบ Event-Driven ตื่นเฉพาะเมื่อมีเหตุการณ์)
* **RAM Footprint:** `~30 MB`
* **Anti-Cheat Safe:** รองรับการทำงานร่วมกับ **Riot Vanguard (Valorant)**, **Easy Anti-Cheat (EAC)**, **BattlEye**, และ **Wellbia** 100% เนื่องจากทำงานในโหมด User-Mode Telemetry โดยไม่แทรกแซงหน่วยความจำของเกม พร้อมระบบ Trusted Publisher Whitelist ครอบคลุมค่ายเกมสากล (`Roblox Corporation`, `KRAFTON (PUBG)`, `Overwolf`, `Riot Games`, `Valve Corp (Steam)`, `Epic Games`, `Blizzard`, `EA`, `Ubisoft`, `Discord`, `NVIDIA`, `AMD`, `Intel`, `Logitech`, `Razer`)
* **Game Infostealer Defense:** มีกับดัก Canary Honeypot ดักจับมัลแวร์ขโมยคุกกี้ Roblox (`.ROBLOSECURITY`), Steam Session (`ssfn`), และ Riot Token โดยอัตโนมัติ
