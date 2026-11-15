# 🛡️ Security Sentinel Ultra v8.0 (User-Mode EDR & Endpoint Telemetry)

**User-Mode (Ring 3) Endpoint Threat Defense, Work & Gaming Safe-Mode, Authenticode Code Signing, DPAPI Secret Vault, Phishing Parent Matrix, Tamper-Evident HMAC Logging & Short-Lived Process Telemetry for Windows 10 / 11**  
*Zero-Dependency • Low Resource Footprint • Work/IDE Safe-Mode • Automated Windows CI Verified*

---

## 🌟 Overview (ภาพรวมระบบ v8.0)

**Security Sentinel Ultra v8.0** คือเครื่องมือตรวจจับและตอบโต้ภัยคุกคามระดับ User-Mode (Ring 3 EDR / HIDS) สำหรับ Windows 10 / 11 ที่ออกแบบให้ทำงานควบคู่กับการทำงาน (Coding / Dev / Office) และการเล่นเกม (Gaming) โดยใช้ทรัพยากรต่ำและไม่กระทบกับระบบ Anti-Cheat ระดับ Kernel

ในเวอร์ชัน 8.0 ได้ปรับปรุงสถาปัตยกรรมตามผลการตรวจสอบด้านความปลอดภัย (Red-Team & Code Audit):
- **A1 (Authenticated & Elevated Stop Flow):** การหยุด/พักการทำงานผ่าน `Stop-Shield.ps1`, เมนู System Tray หรือปุ่มบน Dashboard บังคับสิทธิ์ Administrator (UAC) พร้อมการยืนยันจากผู้ใช้ ส่งสัญญาณผ่าน Authenticated Stop Token ให้ Watchdog และ Guardian หยุดตัวเองอย่างปลอดภัย (ไม่มีการ `Stop-Process -Force` ทับ) บันทึก Windows Event Log (`EventID 4006`) ทุกครั้ง และตั้งเวลาเปิดกลับอัตโนมัติ (Auto-Resume 15 นาที)
- **A2 (Registry Trust Anchor ACL):** ล็อกสิทธิ์ `HKLM:\SOFTWARE\SecuritySentinel` แบบ `SetAccessRuleProtection($true, $false)` โดยอนุญาตเฉพาะ `NT AUTHORITY\SYSTEM` และ `BUILTIN\Administrators` (`Allow FullControl`) โดยไม่ใส่กฎ `Deny` บน `BUILTIN\Users` เพื่อไม่ให้บล็อกผู้ดูแลระบบที่ยกระดับสิทธิ์แล้ว (เนื่องจาก Admin เป็นสมาชิกของกลุ่ม Users ด้วย)
- **A3 (Unified CSPRNG Secret & Fail-Closed Token):** ใช้กลไกอ่านกุญแจความลับชุดเดียวกันทุกคอมโพเนนต์ (`HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor\InstallSecret` เป็นหลัก และไฟล์ DPAPI `vault.sec` ขนาด 256-bit CSPRNG สำหรับโหมดผู้ใช้) พร้อมตัดค่าคงที่สาธารณะ (`SENTINEL_ULTRA_V6_ENTROPY_...`) ออกทั้งหมด
- **A4 (Safe-Mode Parent Path Hardening):** ยกเลิกการเชื่อถือโฟลเดอร์ที่ผู้ใช้เขียนเองได้ (`AppData\Local\Programs`) จากเกณฑ์ตรวจพาธของ Safe-Mode Parent โดยอนุญาตเฉพาะพาธภายใต้ `Program Files` / `Windows` หรือไฟล์ที่มีลายเซ็นดิจิทัล Authenticode ถูกต้องเท่านั้น
- **B1–B5 (10-Script Trust Anchor, Safe Start Verification & Authenticode Pinning):**
  - รวมสคริปต์หลักครบทั้ง 10 ไฟล์ (`SentinelWatchdog.ps1`, `SentinelGuardian.ps1`, `SentinelDashboard.ps1`, `SentinelTray.ps1`, `Start-Shield.ps1`, `Stop-Shield.ps1`, `Sign-Scripts.ps1`, `Install.ps1`, `Uninstall.ps1`, `Invoke-RedTeamAudit.ps1`) ไว้ใน Trust Anchor
  - เมื่อติดตั้งด้วยสิทธิ์ Admin ลง `C:\Program Files\SecuritySentinel` ระบบจะเก็บเฉพาะโค้ดไว้ใน `Program Files` และแยกไฟล์สถานะ/Log ไว้ใน `%LOCALAPPDATA%\SecuritySentinel`
  - `Start-Shield.ps1` ตรวจสอบค่า SHA-256 กับ Trust Anchor ก่อนรัน และรอตรวจสอบว่าโปรเซส Watchdog/Guardian ทำงานจริงก่อนแจ้งสถานะ `ACTIVE & PROTECTING`
  - `Sign-Scripts.ps1` ใช้ใบรับรองตัวเดิมซ้ำโดยอัตโนมัติ ล้างใบรับรองเก่าที่ซ้ำซ้อน บันทึก `TrustedCertThumbprint` ลง Trust Anchor และทำลาย CNG Private Key Container จริงเมื่อระบุ `-PurgePrivateKey`
- **C1 (Tamper-Evident Log HMAC Chain & Event Log Primary):** บันทึกเหตุการณ์หลักลง Windows Event Viewer (`Application` Log, Source `SecuritySentinel`) และต่อท้ายบรรทัดใน `sentinel.log` ด้วยลูกโซ่ `[HMAC:<16-hex>]` (HMAC-SHA256) พร้อมฟังก์ชัน `Test-SentinelLogIntegrity` เพื่อตรวจจับการแก้ไขหรือลบบรรทัดย้อนหลัง
- **C3 (Short-Lived Process Telemetry):** รองรับการอ่าน Security Event ID `4688` (พร้อม CommandLine Auditing) และ Sysmon Event ID `1` เพื่อตรวจจับโปรเซสอายุสั้นที่ทำงานและจบลงก่อนรอบการสแกนของ WMI
- **C4 (PID-Verified Dashboard Tracking):** ติดตามสถานะหน้าต่าง Dashboard ด้วย `dashboard.pid` และตรวจสอบ CommandLine จริงแทนการเทียบชื่อไตเติลหน้าต่าง

---

## ⚠️ ขอบเขตสถาปัตยกรรมและข้อจำกัด (Ring 3 User-Mode vs Ring 0 Kernel-Mode Scope)

เพื่อให้เข้าใจขอบเขตการป้องกันตามความเป็นจริง (Honest Threat Model):

1. **ทำงานในระดับ User-Mode (Ring 3) เท่านั้น:**
   - โปรแกรมนี้ทำงานเป็นโปรเซส PowerShell/.NET ในระดับ User-Mode **ไม่ใช่** Kernel Driver (Ring 0), ELAM Driver หรือบริการ Protected Process Light (PPL)
   - การล็อก Kernel Object DACL (`HardenCurrentProcessDacl`) ที่จำกัด `OWNER RIGHTS (S-1-3-4)` ช่วยป้องกันโปรเซสในระดับผู้ใช้ทั่วไป (Unprivileged User-Mode) ไม่ให้สั่ง `OpenProcess(PROCESS_TERMINATE | WRITE_DAC)` ได้โดยตรง
2. **ขอบเขตเมื่อผู้โจมตีได้สิทธิ์ Administrator หรือ SYSTEM แล้ว:**
   - หากมัลแวร์หรือผู้โจมตีได้รับสิทธิ์ **Administrator (Elevated)** หรือ **SYSTEM** แล้ว ผู้โจมตีสามารถใช้สิทธิ์ `SeDebugPrivilege` / `SeTakeOwnershipPrivilege` เพื่อหยุดโปรเซสระดับ Ring 3, อ่านค่า `InstallSecret` จาก `HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor`, หรือแก้ไข Scheduled Task ได้
3. **ขอบเขตของ DPAPI (`CurrentUser`) ในโหมดไม่ได้ติดตั้งด้วยสิทธิ์ Admin:**
   - หากรันในโหมดผู้ใช้ทั่วไปโดยไม่ได้ติดตั้ง `HKLM` Trust Anchor กุญแจความลับใน `vault.sec` และค่าใน `config.json` จะถูกปกป้องด้วย DPAPI (`DataProtectionScope::CurrentUser`) ซึ่งป้องกันการคัดลอกไฟล์ไปถอดรหัสในเครื่องอื่นหรือบัญชีอื่น แต่ไม่สามารถป้องกันมัลแวร์ที่รันภายใต้บัญชีผู้ใช้เดียวกันได้ ดังนั้นจึงแนะนำให้ติดตั้งผ่าน `1-Click-Install.bat` ด้วยสิทธิ์ Administrator เสมอ
4. **ความเร็วในการตรวจจับโปรเซส (Process Creation Telemetry):**
   - เมื่อรันด้วยสิทธิ์ Administrator ระบบจะลงทะเบียน `Win32_ProcessStartTrace` (ETW) ควบคู่กับการอ่าน Security Event ID `4688` (CommandLine Auditing) เพื่อลดช่องว่างของโปรเซสที่เกิดและจบเร็ว (Sub-second processes) อย่างไรก็ตาม การระงับโปรเซส (`NtSuspendProcess`) ยังคงเป็นการตอบสนองแบบ Asynchronous ใน User-Mode ไม่ใช่การบล็อกแบบ Inline Pre-Execution ในระดับ Kernel (`PsSetCreateProcessNotifyRoutineEx`)

---

## 🧪 การทดสอบระบบ (Automated Test Suites & CI)

ระบบมาพร้อมชุดทดสอบอัตโนมัติ 2 ชุด และเวิร์กโฟลว์ GitHub Actions (`.github/workflows/ci.yml`) บน `windows-latest`:

### 1. Standalone Unit Tests (`tests/Run-Tests.ps1`)
ทดสอบ DPAPI, การปฏิเสธ Static Entropy (A3), Registry ACL แบบไม่มี Deny Users (A2), การป้องกัน Spoofed Parent ใน `AppData\Local\Programs` (A4), การตรวจจับการแก้ไฟล์ Log ด้วย HMAC Chain (C1), และการแปลง XML ของ Event 4663 / 4688 (C3):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/Run-Tests.ps1
```

### 2. Live End-to-End Red-Team Audit (`core/Invoke-RedTeamAudit.ps1`)
ทดสอบฟังก์ชันจริงของ `SentinelWatchdog.ps1` และ `SentinelGuardian.ps1` บน Windows 10/11:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File core/Invoke-RedTeamAudit.ps1
```

---

## 📜 โครงสร้างไฟล์ในโครงการ

```
git_security/
├── 1-Click-Install.bat            # ตัวติดตั้งระบบ (แนะนำให้คลิกขวา Run as administrator)
├── 1-Click-Uninstall.bat          # ตัวถอนการติดตั้งและกู้คืนสถานะเครื่อง
├── Start-Shield.bat               # ตัวสั่งเปิดการทำงานพร้อมตรวจสอบสถานะจริง
├── Stop-Shield.bat                # ตัวสั่งพักการทำงานชั่วคราว (บังคับ UAC Admin + Auto-Resume)
├── Sentinel-Dashboard.bat         # ชอร์ตคัทเปิด GUI Dashboard
├── Sentinel-Tray.bat              # ชอร์ตคัทเปิดไอคอน System Tray
├── README.md                      # เอกสารคู่มือและขอบเขตสถาปัตยกรรม
├── README.txt                     # สรุปวิธีใช้งานและขอบเขตความปลอดภัย
├── .github/workflows/ci.yml       # GitHub Actions Windows CI
├── core/
│   ├── SentinelWatchdog.ps1       # แกนหลักตรวจจับภัยคุกคาม (User-Mode EDR)
│   ├── SentinelGuardian.ps1       # โปรเซสคู่แฝดตรวจสอบ Trust Anchor & DACL
│   ├── SentinelDashboard.ps1      # GUI Command Center (WPF/XAML)
│   ├── SentinelTray.ps1           # System Tray Agent
│   ├── Start-Shield.ps1           # สคริปต์ตรวจสอบ Hash และเริ่มการทำงานของระบบ
│   ├── Stop-Shield.ps1            # สคริปต์พักการทำงานแบบยืนยันตัวตนระดับ Admin
│   ├── Sign-Scripts.ps1           # สคริปต์จัดการใบรับรองและเซ็น Authenticode
│   ├── Invoke-RedTeamAudit.ps1    # ชุดทดสอบ Live E2E Audit
│   ├── Install.ps1                # สคริปต์ติดตั้งระบบและตั้งค่า HKLM Trust Anchor
│   ├── Uninstall.ps1              # สคริปต์ถอนการติดตั้ง
│   └── config.json                # ไฟล์ตั้งค่าระบบเริ่มต้น
└── tests/
    ├── Run-Tests.ps1              # ตัวรัน Unit Test แบบ Zero-Dependency
    └── SecuritySentinel.Tests.ps1 # Pester Unit Test Suite
```
