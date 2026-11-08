# 🛡️ Security Sentinel Ultra v5.0 (Red-Team Hardened Portable EDR)

**Autonomous Endpoint Threat Defense, Kernel DACL Self-Protection, Live Process Memory Forensics & Real-Time Behavioral Watchdog for Windows 10 / 11**  
*Zero-Dependency • Event-Driven (0% Gaming FPS Impact) • Tier 1–5 + v5.0 Red-Team Hardened Architecture*

---

## 🌟 Overview (ภาพรวมระบบ v5.0 Red-Team Hardened Edition)

**Security Sentinel Ultra v5.0** คือระบบป้องกัน Endpoint ขนาดพกพา (Portable EDR / HIDS) ที่พัฒนาด้วยสถาปัตยกรรม **Native Zero-Dependency** โดยใช้เครื่องมือและ API มาตรฐานที่ติดตั้งมาพร้อมกับ Windows 10 และ Windows 11 ทั้งหมด 100% (`PowerShell 5.1`, `.NET CLR`, `WPF/XAML`, `C# P/Invoke Native API`, `FileSystemWatcher`, `Windows DPAPI`, และ `WMI/CIM Real-Time Event Stream`) ไม่จำเป็นต้องติดตั้ง Python, Node.js หรือโปรแกรมเสริมใดๆ

---

## 🔒 9 การอัปเกรดด้านความปลอดภัยระดับ Red-Team Hardened ในเวอร์ชัน v5.0

1. **Real Kernel DACL Writeback (`SetKernelObjectSecurity`):**
   * แก้ไขระบบป้องกันโปรเซสตัวเองให้สมบูรณ์ครบวงจร โดยสร้าง `CommonAce (AccessDenied)` สำหรับสิทธิ์ `PROCESS_TERMINATE (0x0001)`, `PROCESS_VM_OPERATION (0x0008)`, `PROCESS_VM_WRITE (0x0020)`, และ `PROCESS_SUSPEND_RESUME (0x0800)` แทรกเข้าที่ Index `0` ของ `DiscretionaryAcl` แล้วเขียนกลับลง Kernel Object จริงผ่าน `advapi32.dll!SetKernelObjectSecurity` ทั้งบนโปรเซส Watchdog และ Guardian Twin
2. **True Live Process Memory Forensics (`VirtualQueryEx` + `ReadProcessMemory`):**
   * ยกระดับจากแค่การดึง String จากไฟล์บนดิสก์ (Static Disk Strings) สู่การอ่านหน่วยความจำเสมือนของโปรเซสจริง (`MEM_COMMIT`, `PAGE_READWRITE` / `PAGE_EXECUTE_READWRITE`) ผ่าน P/Invoke `VirtualQueryEx` และ `ReadProcessMemory` เพื่อดึง URL ของเซิร์ฟเวอร์ C2, Discord Webhook ของแฮกเกอร์, และ Telegram Bot Token ที่ถูกถอดรหัส (Unpack/Decrypt) อยู่ใน RAM ขณะรันไทม์ พร้อมควบคู่กับการสแกนไฟล์ไบนารีบนดิสก์
3. **Cryptographic DPAPI Stop-Token (`graceful_stop.token`):**
   * ยกเลิกระบบไฟล์ `graceful_stop.flag` แบบข้อความธรรมดา (Plaintext) ที่มัลแวร์สามารถสร้างเลียนแบบเพื่อสั่งปิดระบบได้ เปลี่ยนเป็น **DPAPI-Encrypted Time-Bound Token (`graceful_stop.token`)** ที่เข้ารหัสด้วย `System.Security.Cryptography.ProtectedData` ผูกกับ `PID` ของ Watchdog และเวลา `UnixTimestamp` (มีอายุไม่เกิน 60 วินาที) หากมัลแวร์สร้างไฟล์ปลอมขึ้นมา ระบบจะตรวจพบว่าเป็น **Tamper Attack** และแจ้งเตือนทันที
4. **Zero Command-Line Bypass & SHA-256 Script Self-Integrity:**
   * ยกเลิกการข้ามการตรวจด้วยชื่อใน Command Line (`-match "SentinelWatchdog"`) ที่มัลแวร์ใช้หลบเลี่ยงได้ เปลี่ยนเป็นการตรวจสอบ **Exact Verified PID** ควบคู่กับการคำนวณและตรวจสอบค่าแฮช **SHA-256 ของไฟล์สคริปต์ (`SentinelWatchdog.ps1` และ `SentinelGuardian.ps1`)** ทุกครั้ง หากไฟล์สคริปต์ถูกแก้ไขหรือวางยา ระบบ Guardian Twin จะระงับการรันเพื่อป้องกันการยกระดับสิทธิ์ (Privilege Escalation)
5. **Anti-EoP NTFS ACL Locking (`icacls` Hardening):**
   * เมื่อติดตั้งด้วยสิทธิ์ Administrator สคริปต์ `Install.ps1` จะล็อกสิทธิ์ NTFS ACL ของไฟล์ `.ps1` ทั้งหมดในโฟลเดอร์ติดตั้งให้เขียนได้เฉพาะ `SYSTEM:(F)` และ `Administrators:(F)` ส่วนผู้ใช้ทั่วไปมีสิทธิ์อ่านและรันเท่านั้น (`RX`) ป้องกันมัลแวร์ระดับ User แอบแก้ไขสคริปต์เพื่อรอรับสิทธิ์สูงขึ้นตอนเปิดเครื่อง
6. **Composite Process Tracking (`PID|CreationDate`) & Automatic Dead-PID Pruning:**
   * แก้ปัญหาช่องโหว่ **PID Reuse** ของ Windows โดยเปลี่ยนคีย์การจดจำโปรเซสจาก `PID` เดี่ยวๆ เป็น `PID|CreationDate` และมีระบบล้างโปรเซสที่ปิดตัวไปแล้วออกจากหน่วยความจำอัตโนมัติในทุกรอบการตรวจ
7. **Strict Distinguished Name (DN) & Root CA Issuer Authenticode Verification:**
   * ยกระดับการตรวจใบรับรองดิจิทัล (`Test-IsTrustedBinary`) จากการเช็กคำย่อยทั่วไป เป็นการตรวจความถูกต้องของ **Root/Intermediate Certificate Authority (`Issuer`)** ควบคู่กับ Regex แบบผูกขอบเขตฟิลด์ `CN=` / `O=` อย่างรัดกุม ป้องกันการตั้งชื่อบริษัทปลอมปนคำว่า `Intel Corporation` หรือ `Microsoft`
8. **Risk-Score Gated Auto-Freeze & Wired `ScanIntervalSeconds`:**
   * ลดปัญหา **False Positive** เมื่อแอปพลิเคชันปกติ (เช่น Discord, Steam, Browser) เรียกใช้ `cmd.exe` หรือ `powershell.exe` โดยระบบจะคำนวณคะแนนความเสี่ยง **Heuristic Risk Score (`0 – 100`)** ก่อน และจะสั่ง Freeze โปรเซสอัตโนมัติเฉพาะเมื่อคะแนนความเสี่ยงสูงกว่าเกณฑ์ (`AutoFreezeMinRiskScore = 60`) เท่านั้น ส่วนกรณีคะแนนต่ำจะบันทึก Log แจ้งเตือนโดยไม่ทำให้โปรแกรมของผู้ใช้ค้าง พร้อมเชื่อมต่อตัวแปร `ScanIntervalSeconds` ใน `config.json` เข้ากับลูปสแกนจริง
9. **DPAPI Secret Storage & SACL Canary Read-Audit (Event ID 4663):**
   * เข้ารหัส `DiscordWebhookUrl` และ `VirusTotalApiKey` ในไฟล์ `config.json` ด้วย **Windows DPAPI (`DiscordWebhookEncrypted` / `VirusTotalKeyEncrypted`)** ไม่เก็บเป็น Plaintext บนดิสก์อีกต่อไป และเพิ่มการตั้งค่า **NTFS SACL ReadData Audit Rule** บนโฟลเดอร์กับดัก Canary Honeypot ร่วมกับการตรวจจับ **Windows Security Event ID 4663** เพื่อจับมัลแวร์ที่แอบ "อ่าน" (Read) ไฟล์รหัสผ่านล่อแม้ไม่ได้แก้ไขไฟล์

---

## 🎯 สถาปัตยกรรมป้องกันภัยคุกคาม 5 ระดับ (Tier 1 – Tier 5 Master Architecture)

| ระดับ (Tier) | โมดูลป้องกัน | กลไกการทำงานทางเทคนิค |
| :--- | :--- | :--- |
| **Tier 1** | **Core Watchdog & Browser Guard** | เฝ้าระวังโฟลเดอร์ `User Data` ของ Chrome, Edge, Brave, Opera แบบ Real-time ป้องกันการหย่อน DLL แปลกปลอม พร้อมเฝ้าระวัง Persistence 28+ จุด + กับดัก **Canary Honeypot** (Filesystem Watcher + SACL Event ID 4663 Read Audit) |
| **Tier 2** | **Real-Time Process & Anomaly Telemetry** | ดักจับ **Parent-Child Process Anomaly** ผ่าน WMI Event Stream (`__InstanceCreationEvent`) และดักจับคำสั่งเข้ารหัสอำพราง (`-EncodedCommand` / `IEX`) ด้วยระบบติดตามโปรเซสแบบ `PID|CreationDate` |
| **Tier 3** | **Automated Response & Guardian Twin** | คอมไพล์โค้ด C# P/Invoke เรียกใช้ `ntdll.dll!NtSuspendProcess` แช่แข็งโปรเซสมัลแวร์เมื่อ Risk Score ถึงเกณฑ์, ระบบ **Guardian Twin + Kernel DACL Protection + DPAPI Stop-Token** และปุ่ม **Emergency Network Killswitch** |
| **Tier 4** | **Zero-Trust, DLL Guard & Micro-ML** | ดักจับไฟล์ `.exe` และ `.dll` แปลกปลอมใน `%TEMP%`, ตรวจใบรับรองดิจิทัลแบบ Strict DN + Issuer, คำนวณค่า **Shannon Entropy**, เปิดบันทึก **PowerShell Script Block Logging (Event ID 4104)** และปกป้องหน่วยความจำ **LSASS (`RunAsPPL`)** |
| **Tier 5** | **Live RAM Forensics & Discord Webhook** | สแกนหน่วยความจำจริงของโปรเซส (`VirtualQueryEx` + `ReadProcessMemory`) เพื่อดึงลิงก์ **C2 / Webhook ของแฮกเกอร์**, คำนวณค่าแฮช **SHA-256** แนบลิงก์ **VirusTotal**, และส่งการ์ดแจ้งเตือน **Rich Embed** เข้าห้อง **Discord Webhook** (เก็บรักษา Webhook ด้วยการเข้ารหัส DPAPI) |

---

## ⚖️ ขอบเขตทางสถาปัตยกรรม (Architectural Scope: User-Mode Ring 3 vs Kernel-Mode Ring 0)

เพื่อให้ผู้ใช้และทีมตรวจสอบความปลอดภัยเข้าใจขีดความสามารถตามความเป็นจริงทางวิศวกรรม:
* **สิ่งที่ Security Sentinel Ultra v5.0 ทำได้จริงในระดับสูง:** ทำงานเป็น **User-Mode (Ring 3) Autonomous EDR & Behavioral Watchdog** ที่ไม่ต้องพึ่งพาไลบรารีภายนอก มีระบบป้องกันโปรเซสด้วย Kernel Object DACL, การอ่านหน่วยความจำด้วย `ReadProcessMemory`, การดักจับโปรเซสด้วย WMI Event Stream และการเข้ารหัสความลับด้วย DPAPI
* **ข้อจำกัดตามธรรมชาติของ User-Mode (Ring 3):** เนื่องจาก Windows บังคับให้ Kernel Driver (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`, Minifilter Driver) ต้องใช้ใบรับรอง **EV Code Signing Certificate ที่ผ่านการรับรอง WHQL จาก Microsoft** โปรเจกต์ Open-Source แบบสคริปต์จึงทำงานในระดับ User-Mode ซึ่งอาจมีช่วงเวลาเสี้ยววินาที (Polling/WMI Delivery Window) ก่อนที่โปรเซสจะถูกระงับ สำหรับสภาพแวดล้อมองค์กรที่ต้องการการบล็อกระดับ Inline Kernel แนะนำให้ใช้งานร่วมกับ **Windows Defender ASR Rules** หรือ **Sysmon + Sigma Rules**

---

## 📂 โครงสร้างโปรเจกต์ (Project Structure)

```text
SecuritySentinel_Portable/
├── 1-Click-Install.bat                         # คลิกเดียวเพื่อติดตั้ง ล็อกสิทธิ์ ACL, ตั้งค่า Hardening และรัน Watchdog + Guardian Twin
├── 1-Click-Uninstall.bat                       # คลิกเดียวเพื่อออก DPAPI Stop-Token ถอนการติดตั้งและล้างไฟล์กับดักทั้งหมด
├── Sentinel-Dashboard.bat                      # เปิดหน้าต่าง Cyber-SOC GUI Command Center Dashboard (v5.0)
├── README.txt                                  # คู่มือการใช้งานภาษาไทยฉบับย่อ (v5.0)
├── Security_Sentinel_Master_Plan.pdf           # เอกสารแผนแม่บทสถาปัตยกรรม (Master Engineering Plan)
├── Security_Sentinel_SourceCode_and_Tools.pdf  # เอกสารสรุปโครงสร้าง Source Code และเครื่องมือที่ใช้พัฒนา
└── core/
    ├── config.json                             # ไฟล์เก็บค่าตั้งค่า (เข้ารหัส Webhook/API Key ด้วย DPAPI อัตโนมัติ)
    ├── Install.ps1                             # สคริปต์ติดตั้งระบบ, ล็อก NTFS ACL ป้องกัน EoP, เปิด Event 4104 / AuditPol
    ├── SentinelWatchdog.ps1                    # เอนจินป้องกันหลัก v5.0 (Kernel DACL + Live RAM Forensics + Strict Authenticode)
    ├── SentinelGuardian.ps1                    # เอนจินคู่แฝด Guardian Twin v5.0 (ตรวจ SHA-256 Integrity + DPAPI Stop-Token)
    ├── SentinelDashboard.ps1                   # หน้าจอควบคุมหลัก WPF/XAML GUI v5.0 + มาตรวัด CPU/RAM เรียลไทม์
    └── Uninstall.ps1                           # สคริปต์ถอนการติดตั้งพร้อมสร้าง DPAPI Stop-Token อย่างปลอดภัย
```

---

## 🚀 วิธีติดตั้งและใช้งาน (Quick Start)

1. ดาวน์โหลดหรือ Clone โปรเจกต์นี้ลงบนเครื่องคอมพิวเตอร์ (Windows 10 / 11)
2. ดับเบิลคลิกไฟล์ **`1-Click-Install.bat`** (แนะนำให้คลิกขวา **Run as administrator** เพื่อเปิดใช้งานการล็อกสิทธิ์ NTFS ACL ป้องกัน EoP และเปิด SACL Read Audit เต็มรูปแบบ)
3. เปิดหน้าต่างควบคุมโดยดับเบิลคลิกที่ **`Sentinel-Dashboard.bat`** หรือไอคอนบนหน้าจอ Desktop
4. นำลิงก์ **Discord Webhook URL** มาวางในช่องบนหน้าจอ Dashboard แล้วกด **`[SAVE] Save Config`** ระบบจะเข้ารหัสลิงก์ของคุณด้วย **Windows DPAPI** เก็บลงเครื่องอย่างปลอดภัยทันที!
