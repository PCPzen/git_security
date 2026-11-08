# 🛡️ Security Sentinel Ultra v6.0 (Enterprise Telemetry & Behavioral EDR)

**Autonomous Endpoint Threat Defense, Deep Windows Telemetry (Event 4104 & SACL 4663), Live Process Memory Forensics, Behavioral Correlation & Red-Team Verified Watchdog for Windows 10 / 11**  
*Zero-Dependency • Event-Driven (0% Gaming FPS Impact) • v6.0 6-Pillar Enterprise Architecture*

---

## 🌟 Overview (ภาพรวมระบบ v6.0 Enterprise Telemetry Edition)

**Security Sentinel Ultra v6.0** คือระบบป้องกัน Endpoint ขนาดพกพา (Portable EDR / HIDS) ที่พัฒนาด้วยสถาปัตยกรรม **Native Zero-Dependency** โดยใช้เครื่องมือและ API มาตรฐานของ Windows 10 และ Windows 11 ทั้งหมด 100% (`PowerShell 5.1`, `.NET CLR`, `WPF/XAML`, `C# P/Invoke Native API`, `FileSystemWatcher`, `Windows DPAPI`, `WinEvent Telemetry`, และ `WMI/CIM Real-Time Event Stream`)

---

## 🏆 6 แกนหลักที่พัฒนาและยกระดับในเวอร์ชัน v6.0 (6 Enterprise Priority Pillars)

### 1. Kernel-Level & Deep Windows Event Telemetry (การตรวจจับพฤติกรรมระดับลึก)
* **PowerShell ScriptBlock Telemetry (`Event ID 4104`):** ดึงข้อมูลจาก `Microsoft-Windows-PowerShell/Operational` เพื่อตรวจสอบโค้ดสคริปต์ที่ถูกถอดรหัสแล้วในหน่วยความจำ (De-obfuscated ScriptBlock) จับพฤติกรรม Fileless Malware (`AmsiUtils`, `Invoke-Mimikatz`, `MiniDumpWriteDump`, `VirtualAlloc`, การดึง `.ROBLOSECURITY` / `Login Data`) แม้ไม่ได้ส่งผ่านพารามิเตอร์บน Command Line
* **SACL Read-Audit พร้อมระบุโปรเซสต้นตอ (`Security Event ID 4663` XML Parser):** เมื่อติดตั้งด้วยสิทธิ์ Administrator ระบบจะเปิด SACL Read Audit บนโฟลเดอร์กับดัก Canary และแยกวิเคราะห์โครงสร้าง XML ของ Event `4663` (`Parse-Event4663Xml`) เพื่อระบุ **`ProcessId` (แปลงจากฐาน 16) และ `ProcessName` ที่แอบอ่านไฟล์ล่อ** พร้อมสั่งระงับโปรเซสต้นตอทันที
* **Real-Time WMI Process Stream (`__InstanceCreationEvent`):** ดักจับการเกิดของโปรเซสใหม่พร้อมตรวจจับด้วยคีย์ผสม `PID|CreationDate` และล้างโปรเซสที่ปิดตัวแล้วทุกรอบเพื่อป้องกันช่องโหว่ PID Reuse

### 2. True Live Process Memory Forensics & Injection Scanner (วิเคราะห์หน่วยความจำจริง)
* **`AnalyzeProcessMemory` (`VirtualQueryEx` + `ReadProcessMemory`):** สแกนหน่วยความจำเสมือนของโปรเซสที่ถูก Commit (`MEM_COMMIT`, สูงสุด 16 MB ต่อโปรเซส, Region ไม่เกิน 2 MB) เพื่อดึงลิงก์เซิร์ฟเวอร์ C2, Discord Webhook และ Telegram Bot Token ที่ถูกถอดรหัสอยู่ใน RAM
* **ตรวจจับ `MEM_PRIVATE` RWX & Unbacked Reflective PE (`MITRE T1055`):** นับจำนวน Memory Page ส่วนตัวที่มีสิทธิ์ `PAGE_EXECUTE_READWRITE (0x40)` และตรวจหาส่วนหัวไฟล์ `MZ` / `PE\0\0` ที่ซ่อนอยู่ในหน่วยความจำปฏิบัติการโดยไม่มีไฟล์รองรับ (Reflective DLL Injection / Process Hollowing)

### 3. Code Integrity & Self-Defense (ความสมบูรณ์ของโค้ดและการป้องกันตัวเอง)
* **External Trust Anchor (`Registry IntegrityAnchor` + `manifest.json`):** แยกแหล่งเก็บค่าแฮช SHA-256 ที่เชื่อถือได้ออกจากตัวสคริปต์ โดยบันทึกลงใน Registry (`HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor` เมื่อติดตั้งแบบ Admin และ `HKCU:\Software\SecuritySentinel\IntegrityAnchor`) ควบคู่กับไฟล์ `manifest.json` ที่ซีลด้วย DPAPI
* **Kernel DACL Writeback พร้อมปฏิเสธ `WRITE_DAC` และ `WRITE_OWNER`:** ใช้ `SetKernelObjectSecurity` เขียนกฎ `AccessDenied` ปฏิเสธสิทธิ์ `PROCESS_TERMINATE (0x0001)`, `PROCESS_VM_OPERATION (0x0008)`, `PROCESS_VM_WRITE (0x0020)`, `PROCESS_SUSPEND_RESUME (0x0800)`, `WRITE_DAC (0x00040000)` และ `WRITE_OWNER (0x00080000)`
* **PID-Bound Custom-Entropy Stop-Token (`graceful_stop.token`):** โทเคนสั่งปิดระบบถูกเข้ารหัสด้วย Custom Application Entropy (`SENTINEL_ULTRA_V6_ENTROPY_<ComputerName>`) และบังคับตรวจสอบว่า **หมายเลข PID ข้างในโทเคนต้องตรงกับ PID ของ Watchdog ที่กำลังรันอยู่จริง** และมีอายุไม่เกิน 60 วินาที

### 4. Behavioral Detection & Cross-Signal Correlation (การเชื่อมโยงพฤติกรรม + 28 จุด Persistence จริง)
* **Base64 Command-Line Decoder (`Expand-EncodedCommandLine`):** ถอดรหัสพารามิเตอร์ `-enc` / `-EncodedCommand` (ทั้งแบบ UTF-16LE และ UTF-8) รวมถึง `FromBase64String('...')` ออกมาวิเคราะห์ก่อนให้คะแนนความเสี่ยงเสมอ
* **Unified Rule 1 & Rule 2 + Mandatory Obfuscation Alert:**
  * แก้ไขจุดบอดเมื่อเบราว์เซอร์หรือเกมเปิด `powershell.exe -enc ...`: ระบบรวมคะแนน `Base (15) + ParentChildAnomaly (25) + ObfuscatedOrFilelessCmd (35) = 75/100` (และบวกเพิ่มอีก `+35` เป็น `100/100` หากภายใน Base64 ซ่อน URL/Webhook)
  * **ไม่มีการ `return` ข้ามกฎ:** หากตรวจพบการเข้ารหัสอำพราง (`$hasObfuscation`) ระบบจะ **แจ้งเตือนระดับ `CRITICAL` เสมอ** ไม่ว่าคะแนนรวมจะเป็นเท่าไร และสั่ง Freeze ทันทีเมื่อคะแนนถึงเกณฑ์ (`>= 60`)
* **28-Vector Persistence Sensor (`Get-PersistenceSnapshot`):** ตรวจสอบจุดฝังตัวอัตโนมัติ 28 รายการจริงในโค้ด (ครอบคลุม `HKCU/HKLM Run & RunOnce` ทั้ง 64-bit และ `WOW6432Node`, `Policies\Explorer\Run`, `Winlogon Shell/Userinit`, `Session Manager BootExecute`, `AppInit_DLLs`, `HKCU\Environment UserInitMprLogonScript`, `LSA Packages`, `SharedTaskScheduler`, `ShellServiceObjectDelayLoad`, `IFEO Debugger`, UAC Hijacks `ms-settings`/`mscfile`/`exefile`, `CLSID`, Startup Folders, Scheduled Tasks ทุกโฟลเดอร์ย่อย, `WMI root\subscription` Filters/Consumers, และไฟล์ `PowerShell $PROFILE`)

### 5. Safe Automated Response (การตอบสนองอัตโนมัติอย่างปลอดภัย & Rollback)
* **Unified Risk-Score Gating & การปกป้องไฟล์ติดตั้งที่มีใบรับรองถูกต้องใน Rule 3:**
  * ใช้เกณฑ์คะแนน `AutoFreezeMinRiskScore (60)` ร่วมกันทั้ง Rule 1, Rule 2 และ Rule 3
  * ใน **Rule 3 (`%TEMP%` Execution)**: แยกแยะระหว่าง **(1) Tier-1 Major Vendor Whitelist** (28+ บริษัทใหญ่ที่ตรวจทั้ง CA Issuer และ Strict DN `CN=/O=`) และ **(2) ไฟล์ติดตั้งทั่วไปที่มีใบรับรองดิจิทัลถูกต้อง (`IsValidSigned = true`)** โดยหากเป็นตัวติดตั้งหรืออัปเดตของโปรแกรมที่มีใบรับรองดิจิทัลถูกต้องตามมาตรฐาน CA ระบบจะ **ไม่สั่ง Freeze อัตโนมัติ** (แจ้งเตือนเฉพาะเมื่อคะแนนพฤติกรรมสูงเท่านั้น) เพื่อป้องกันปัญหา False Positive กับตัวติดตั้งโปรแกรมทั่วไป
* **Real `NtResumeProcess` Thaw & Quarantine Rollback:** ปุ่ม **`[RESUME / ROLLBACK]`** บน Dashboard เรียกใช้ `ntdll.dll!NtResumeProcess` เพื่อปลดแช่แข็งโปรเซสกลับคืนทำงานจริง และรองรับการกู้คืนไฟล์จาก `quarantine_manifest.json`

### 6. Built-In Red Team & MITRE ATT&CK Audit Suite (`core/Invoke-RedTeamAudit.ps1`)
* มีสคริปต์จำลองการโจมตีและตรวจสอบตัวเองอัตโนมัติ 6 ชุดทดสอบ (`T1059.001`, `T1027`, `T1055`, `T1562.001`, `T1547`, `T1555`) เพื่อยืนยันว่ากฎตรวจจับ การถอดรหัส Base64 การสแกน RAM และการป้องกัน Stop-Token ทำงานได้ครบถ้วน 100%

---

## ⚖️ ขอบเขตทางสถาปัตยกรรมและความโปร่งใสทางเทคนิค (Security Boundaries)

เพื่อให้ผู้ใช้และทีมตรวจสอบความปลอดภัยทราบขอบเขตตามความเป็นจริงของโค้ด:
1. **การติดตั้งแบบ Administrator (`Program Files` + ACL Lock) vs การติดตั้งแบบ User ทั่วไป (`%LOCALAPPDATA%`):**
   * **เมื่อคลิกขวา `Run as administrator` ตอนติดตั้ง (`1-Click-Install.bat`):** ระบบจะติดตั้งเอนจินลงใน `C:\Program Files\SecuritySentinel`, ล็อกสิทธิ์ไฟล์ `.ps1` ด้วย `icacls` ให้แก้ไขได้เฉพาะ `SYSTEM` และ `Administrators`, บันทึก Trust Anchor ลงใน `HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor`, และเปิด `auditpol` สำหรับ SACL Event 4663 Read Audit
   * **เมื่อติดตั้งด้วยสิทธิ์ User ธรรมดา (ไม่กด Run as Admin):** ระบบจะทำงานในโหมดพกพาที่ `%LOCALAPPDATA%\SecuritySentinel` ซึ่งช่วยตรวจจับและสกัดกั้นมัลแวร์ทั่วไปได้ดี แต่ **มัลแวร์ที่รันภายใต้สิทธิ์ User เดียวกัน** จะยังมีสิทธิ์ตามธรรมชาติของ Windows ในการถอดรหัส `DPAPI CurrentUser` (แม้จะมี Custom Entropy หากมัลแวร์อ่านค่า Entropy จากไฟล์สคริปต์ได้) หรือแก้ไข DACL ของโปรเซสที่ตนเป็นเจ้าของ (Owner) ดังนั้น **แนะนำให้ติดตั้งด้วยสิทธิ์ Administrator เสมอสำหรับการใช้งานจริง**
2. **User-Mode (Ring 3) vs Kernel Driver (Ring 0):**
   * ระบบนี้ทำงานในระดับ User-Mode โดยอาศัย WMI Event Stream (`__InstanceCreationEvent`) และ Windows Event Log (`4104` / `4663`) ซึ่งมีความหน่วงระดับเสี้ยววินาทีถึงไม่กี่วินาที หากต้องการบล็อกระดับ Inline Kernel (0 ms) แนะนำให้เปิดใช้งานร่วมกับ **Windows Defender Attack Surface Reduction (ASR)** หรือ **Sysmon**

---

## 🚀 วิธีติดตั้ง ใช้งาน และรันชุดทดสอบ Red-Team Audit

1. **การติดตั้ง:** คลิกขวาที่ไฟล์ **`1-Click-Install.bat`** แล้วเลือก **Run as administrator**
2. **การเปิดหน้าจอควบคุม:** ดับเบิลคลิกไฟล์ **`Sentinel-Dashboard.bat`** หรือไอคอน **Security Sentinel Dashboard** บนหน้าจอ Desktop
3. **การรันชุดทดสอบ Red-Team & MITRE ATT&CK Audit:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\core\Invoke-RedTeamAudit.ps1
   ```
