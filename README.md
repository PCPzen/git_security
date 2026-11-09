# 🛡️ Security Sentinel Ultra v8.0 (Enterprise EDR & Threat Defense)

**Autonomous Endpoint Threat Defense, Work & Gaming Safe-Mode, Authenticode Code Signing, DPAPI Secret Vault, Phishing Parent Matrix, 64MB Memory Injection Forensics & Real E2E Tested Watchdog for Windows 10 / 11**  
*Zero-Dependency • 0% Gaming FPS Impact • Zero Work/IDE Disruption • v8.0 Enterprise EDR Architecture*

---

## 🌟 Overview (ภาพรวมระบบ v8.0 Enterprise EDR Edition)

**Security Sentinel Ultra v8.0** คือระบบป้องกัน Endpoint ขนาดพกพา (Portable EDR / HIDS) ระดับ Enterprise ที่ออกแบบมาเพื่อเครื่องที่ต้องใช้งานหนักทั้ง **การทำงาน (Coding / Dev / Office) และการเล่นเกม (Gaming) บน Windows 10 / 11** 

ในเวอร์ชัน 8.0 ได้ผ่านการปรับปรุงสถาปัตยกรรมความปลอดภัยตามข้อเสนอแนะจากการทดสอบและ Security Code Audit เชิงลึก ครบทั้งการเข้ารหัสความลับด้วย DPAPI, การเซ็นสัญญาดิจิทัล Authenticode, การบันทึก Log ลง Windows Event Viewer, การอุดช่องโหว่การปลอมชื่อโปรเซส (Name-Spoofing), การป้องกันการ Bypass ข้อยกเว้น Dashboard, และการเพิ่มเกณฑ์ตรวจจับ Phishing Macro จากชุดโปรแกรม Office และ PDF

---

## 🚀 ไฮไลท์การอัปเกรดใน Security Sentinel Ultra v8.0

### 1. 🔏 Authenticode Code Signing (`core/Sign-Scripts.ps1`)
* สร้างใบรับรองดิจิทัลแบบ SHA-256 (อายุ 5 ปี) และเซ็น Digital Signature ลงในสคริปต์ `.ps1` ทุกตัวในระบบ
* รองรับการเปิดใช้งานนโยบายความปลอดภัยสูงสุดของ Windows:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope CurrentUser
  ```
* ป้องกันไม่ให้สคริปต์ถูกดัดแปลง (Tamper-Proof) และป้องกันการบล็อกโดย Windows SmartScreen

### 2. 🔐 DPAPI Secret Vault (`System.Security.Cryptography.ProtectedData`)
* ข้อมูลความลับทั้งหมด เช่น **Discord Webhook URL, API Keys, และโทเคนระบบ** จะถูกเข้ารหัสผ่าน Windows Data Protection API (DPAPI)
* เข้ารหัสผูกกับ Windows User Account และกุญแจสุ่ม Entropy 256-bit CSPRNG เฉพาะเครื่อง
* ในไฟล์ `config.json` จะไม่เก็บ Secret แบบ Plaintext อีกต่อไป โดยจะบันทึกในฟิลด์ `DiscordWebhookEncrypted`

### 3. 📜 Windows Event Viewer Integration (Application Log Channel)
* ส่งต่อ Log เหตุการณ์ความปลอดภัยเข้า Windows Event Viewer โดยตรง (Log: `Application`, Source: `SecuritySentinel`)
* กำหนด Event IDs มาตรฐาน:
  * **Event 4000**: Critical Threat / Ransomware / Honeypot Triggered
  * **Event 4001**: Tier 3 Kernel Micro-Freeze Executed
  * **Event 4002**: Work & Gaming Safe-Mode Warning / Anomaly
  * **Event 4003**: Behavioral Telemetry & Information Log
  * **Event 4004**: System Initialized & Watchdog Running
  * **Event 4005**: File Quarantined & Rollback Operation
* ป้องกันผู้โจมตีจากการลบหรือดัดแปลงหลักฐานไฟล์ Text บนดิสก์

### 4. 🎣 Phishing Parent Process Matrix (+50 Risk Score & Immediate Freeze)
* เพิ่มเมทริกซ์ตรวจจับโปรเซสต้นทางกลุ่มเสี่ยงสูง (High-Risk Phishing Parents):
  * **Microsoft Office**: `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `msaccess.exe`, `eqnedt32.exe`
  * **PDF Readers**: `acrord32.exe`, `acrobat.exe`, `foxitreader.exe`
  * **Archivers**: `winrar.exe`, `7zfm.exe`, `peazip.exe`
  * **Script Hosts**: `wscript.exe`, `cscript.exe`, `mshta.exe`
* เมื่อตรวจพบโปรแกรมกลุ่มนี้พยายามสร้าง Shell (`powershell.exe`, `cmd.exe`, `pwsh.exe`) หรือ LOLBin ระบบจะบวกคะแนนความเสี่ยงทันที **+50 คะแนน** ทำให้คะแนนรวมทะลุเกณฑ์ Freeze (>= 85) ทันทีตั้งแต่ Process ถูกสร้าง!

### 5. 🛡️ Dashboard Anti-Bypass & Zero-Trust Verification
* อุดช่องโหว่การต่อท้ายคำสั่งด้วยชื่อสคริปต์เพื่อหลบการตรวจจับ (เช่น `powershell -enc <payload> SentinelDashboard.ps1`)
* ฟังก์ชัน `Test-IsVerifiedSentinelScript` ตรวจสอบอย่างเข้มงวด:
  1. ปฏิเสธทันทีหากมีพารามิเตอร์ Encode (`-enc`, `-encodedcommand`) หรือ Inline Command (`-c`, `-command`, `iex`)
  2. ตรวจสอบพารามิเตอร์ `-File "<path>"` และตรวจสอบว่าไฟล์นั้นอยู่จริงในโฟลเดอร์ที่ได้รับอนุญาต
  3. คำนวณ SHA-256 ของไฟล์นั้นจริงเทียบกับ Trust Anchor
  4. ปฏิเสธคำสั่งที่มี Chaining Operators (`&&`, `||`, `;`, `|`)

### 6. 🛑 Safe-Mode Zero-Trust Name-Spoofing Immunity
* ตัดการตรวจสอบชื่อไฟล์ฝั่ง Child Process (`$cName`) ออกจาก Safe-Mode
* ป้องกันมัลแวร์ที่ไม่มีลายเซ็นใน `%TEMP%` แต่ตั้งชื่อเลียนแบบเครื่องมือ Dev เช่น `node.exe`, `python.exe`, `git.exe`
* บังคับตรวจสอบลายเซ็นและพาธจริงของ Parent เท่านั้น และแจ้งเตือนระดับ `WARN` เสมอ

### 7. 🧠 64 MB Live Memory Forensics & Injection Hunter
* ขยายเพดานการสแกน RAM จาก 16 MB เป็น **64 MB** และอ่านสูงสุด **1 MB ต่อ Memory Region**
* ตรวจสอบหน้าหน่วยความจำ `PAGE_EXECUTE_READWRITE` (RWX) และ `PAGE_EXECUTE_READ` ที่ไม่มีไฟล์รองรับบนดิสก์ (Unbacked Memory)
* ดึง Injected C2 URL, Reflective PE Headers (`MZ`/`PE`), และ Shellcode ออกมาวิเคราะห์แบบ Real-Time

### 8. 🚦 Dashboard 3-State Traffic Light & One-Click Rollback
* ปรับปรุงหน้าต่างควบคุม GUI ให้มีไฟสถานะ 3 สี:
  * 🟢 **SECURE / OPTIMAL**: ระบบทำงานปกติ ไม่มีภัยคุกคาม
  * 🟡 **SUSPICIOUS / ELEVATED**: มีการตรวจพบ Anomaly หรือเฝ้าระวัง Safe-Mode
  * 🔴 **ACTIVE THREAT / BLOCKED**: ตรวจพบมัลแวร์หรือมีการ Micro-Freeze
* ปุ่ม **`[RESUME / ROLLBACK]`**: สั่งปลดล็อก (Thaw) โปรเซสและกู้คืนไฟล์จาก Quarantine กลับสู่ตำแหน่งเดิมได้ในคลิกเดียว

---

## 🧪 การทดสอบระบบ (Test Suites)

ระบบมาพร้อมชุดทดสอบอัตโนมัติ 2 ชุดที่ผ่านการทดสอบ 100%:

### 1. Standalone Unit Tests (`tests/Run-Tests.ps1`)
รันการทดสอบ Unit Test 17 รายการ ครอบคลุม DPAPI, Anti-Bypass, Phishing, Name-Spoofing, และ Canary:
```powershell
powershell -ExecutionPolicy Bypass -File tests/Run-Tests.ps1
```
*ผลลัพธ์:* **17 / 17 TESTS PASSED (0 FAILED)**

### 2. Live End-to-End Red-Team Audit (`core/Invoke-RedTeamAudit.ps1`)
รันการทดสอบฟังก์ชันจริงบนระบบ Windows 11 ครอบคลุม Memory Injection, DACL Lock, Quarantine Rollback:
```powershell
powershell -ExecutionPolicy Bypass -File core/Invoke-RedTeamAudit.ps1
```
*ผลลัพธ์:* **9 / 9 TESTS PASSED (0 FAILED)**

---

## 📦 คำแนะนำการแจกจ่ายและการใช้งาน (Distribution & False-Positive Prevention)

> [!IMPORTANT]
> **เหตุใด Cloud Drive (เช่น Google Drive) หรือ Antivirus ถึงแจ้งเตือนไฟล์สคริปต์ความปลอดภัย?**
> ระบบ Cloud Scanner เช่น Google Drive และ Mail Gateway ใช้ระบบ AI/Static Heuristic ในการตรวจไฟล์ `.ps1` ดิบๆ ที่มีคำสั่งระดับลึก (เช่น การเรียก P/Invoke, การสั่ง Killswitch, หรือการจัดการ Process) และอาจจัดหมวดหมู่ผิดพลาดว่าเป็น **False Positive** (มัลแวร์ที่คล้ายกัน)

### แนวทางปฏิบัติในการแชร์หรือติดตั้ง:
1. **การดาวน์โหลด / แชร์ผ่าน GitHub**: แนะนำให้ Clone หรือดาวน์โหลดจาก GitHub Repository โดยตรง
2. **การแชร์เป็นไฟล์บีบอัด**: ให้บีบอัดเป็น `.zip` หรือ `.7z` โดย **ตั้งรหัสผ่านป้องกัน (Password-Protected)** เช่น รหัส `1234` เพื่อไม่ให้ Cloud AI สแกนตรวจจับผิดพลาด
3. **การแปลงเป็นตัวติดตั้งสำหรับ User ทั่วไป (Enterprise Installer)**:
   * ใช้เครื่องมืออย่าง **Inno Setup** หรือ **Advanced Installer** แพ็กโฟลเดอร์ทั้งหมดเป็นไฟล์ติดตั้งไฟล์เดียว (`Setup.exe` หรือ `.msi`)
   * เซ็น Digital Certificate ลงบนไฟล์ `.exe` ตัวติดตั้ง เพื่อให้ติดตั้งได้ง่ายและผ่าน Windows SmartScreen อย่างราบรื่น

---

## 📜 โครงสร้างไฟล์ในโครงการ

```
D:\Hotel\SecuritySentinel_GitRepo/
├── 1-Click-Install.bat            # ตัวติดตั้งสิทธิ์ Administrator อัตโนมัติ
├── 1-Click-Uninstall.bat          # ตัวถอนการติดตั้งและกู้คืนสถานะเครื่อง
├── Sentinel-Dashboard.bat         # ชอร์ตคัทเปิด GUI Dashboard
├── README.md                      # เอกสารคู่มือฉบับสมบูรณ์ (v8.0)
├── README.txt                     # สรุปภาพรวมแบบพกพา
├── core/
│   ├── SentinelWatchdog.ps1       # แกนหลัก EDR ตรวจจับภัยคุกคามแบบ Real-Time (v8.0)
│   ├── SentinelGuardian.ps1       # ตัวเฝ้าระวังคู่แฝด ควบคุม Integrity & DACL (v8.0)
│   ├── SentinelDashboard.ps1      # GUI Command Center (WPF/XAML) ไฟ 3 สี + One-Click Rollback
│   ├── Sign-Scripts.ps1           # สคริปต์สร้างใบรับรองและเซ็น Authenticode ให้ไฟล์ทั้งหมด
│   ├── Invoke-RedTeamAudit.ps1    # ชุดทดสอบ Live E2E Audit ครบ 9 ด้าน
│   ├── Install.ps1                # สคริปต์ติดตั้งระบบและตั้งค่า HKLM Trust Anchor
│   ├── Uninstall.ps1              # สคริปต์ถอนการติดตั้ง
│   └── config.json                # ไฟล์ตั้งค่าระบบ (รองรับ DPAPI Encrypted Webhook)
└── tests/
    ├── Run-Tests.ps1              # ตัวรัน Unit Test แบบ Zero-Dependency
    └── SecuritySentinel.Tests.ps1 # Pester Unit Test Suite
```

---
*Security Sentinel Ultra v8.0 - Autonomous Enterprise Threat Defense Engine*
