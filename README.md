# 🛡️ Security Sentinel Ultra v7.0 (Work & Gaming Safe-Mode + Enterprise EDR)

**Autonomous Endpoint Threat Defense, Work & Gaming Safe-Mode, `OWNER RIGHTS` Kernel DACL, Fail-Closed Trust Anchor, Live Memory Injection Forensics & Real E2E Tested Watchdog for Windows 10 / 11**  
*Zero-Dependency • 0% Gaming FPS Impact • Zero Work/IDE Disruption • v7.0 Windows 11 Verified Architecture*

---

## 🌟 Overview (ภาพรวมระบบ v7.0 Work & Gaming Safe-Mode Edition)

**Security Sentinel Ultra v7.0** คือระบบป้องกัน Endpoint ขนาดพกพา (Portable EDR / HIDS) ที่ออกแบบมาสำหรับ **เครื่องที่ใช้ทั้งทำงาน (Coding / Dev / Office) และเล่นเกม (Gaming) บน Windows 10 / 11** โดยแก้ไขจุดบกพร่องจากการตรวจสอบ Red-Team Audit ครบทั้ง 3 รอบ พร้อมชุดทดสอบ **Live End-to-End Automated Test Suite (`core/Invoke-RedTeamAudit.ps1`)** ที่เรียกใช้ฟังก์ชันจริงของระบบ 100%

---

## 🎮 1. ระบบ Work & Gaming Safe-Mode (ทำงานและเล่นเกมลื่นไหล 0% False Positive บน Windows 11)

1. **ยกเลิกการเหมารวม `-WindowStyle Hidden` และยกเว้นสคริปต์ของระบบที่ผ่านการตรวจ SHA-256:**
   * นำ `-WindowStyle Hidden` ออกจาก Regex ตรวจการเข้ารหัสอำพราง (`$script:ObfuscatedCmdRegex`) และเพิ่มฟังก์ชัน [`Test-IsVerifiedSentinelScript`](file:///E:/git_security/core/SentinelWatchdog.ps1#L451-L479) ตรวจสอบค่าแฮช SHA-256 เทียบกับ Trust Anchor ทำให้การเปิด `Sentinel-Dashboard.bat` หรือสคริปต์ทำงานปกติที่ใช้ `-WindowStyle Hidden` **ไม่แจ้งเตือนผิดพลาดใส่ตัวเองอีกต่อไป**
2. **Browser Watcher Safe-Mode (ไม่ทำลาย Browser Extension หรือโมดูลเสริมที่ถูกต้อง):**
   * แก้ไข Browser Watcher ไม่ให้กักกันไฟล์ `.dll`/`.exe` ใน `User Data` แบบเหมารวม: ระบบจะกักกันอัตโนมัติ **เฉพาะโฟลเดอร์มัลแวร์ที่ยืนยันแล้ว (`PlatformExperienceHelper`) หรือไฟล์ที่ไม่มีลายเซ็นดิจิทัลซึ่งมีค่า `Shannon Entropy >= 7.2` (ถูก Pack/Encrypt) หรือตรวจพบลิงก์เซิร์ฟเวอร์แฮกเกอร์ (`C2/Webhook`) ภายในไฟล์เท่านั้น** ส่วน Extension ปกติจะถูกบันทึก Log เฝ้าระวังโดยไม่ทำให้เบราว์เซอร์พัง
3. **ปกป้องโปรแกรมทำงาน (IDE / Compiler) และเกมใน `%TEMP%` (`SafeWorkGamingMode = true`, `AutoFreezeMinRiskScore = 85`):**
   * ปรับเกณฑ์คะแนน Auto-Freeze ขึ้นเป็น **`85 / 100`** และเพิ่มรายการปกป้องเครื่องมือพัฒนาซอฟต์แวร์และเกม (`VS Code`, `Visual Studio`, `Rider`, `Node.js`, `Git`, `Python`, `Rust/Cargo`, `.NET/MSBuild`, `GCC/Clang`, `CMake`, `Docker`, `Steam`, `Riot Client`, `Roblox`, `Epic Games`, `Overwolf`):
     * ไฟล์ `.exe` ที่ไม่มีใบรับรองใน `%TEMP%` เพียงอย่างเดียว (`15 Base + 25 Unsigned + 20 Temp = 60 คะแนน`) จะ **แจ้งเตือนและเก็บ Log เท่านั้น ไม่ถูกสั่ง Freeze** ทำให้การคอมไพล์โค้ด การลงโปรแกรม หรือการอัปเดตเกมไม่สะดุด
     * ระบบจะสั่ง **Freeze (`NtSuspendProcess`) ทันที** เมื่อพบพฤติกรรมอันตรายชัดเจน (`คะแนน >= 85`) เช่น เบราว์เซอร์แอบรัน PowerShell เข้ารหัส (`15 + 25 + 45 = 85` ถึง `100`), พบ **C2 Webhook/Telegram ใน RAM หรือไฟล์ (`+35`)**, หรือพบ **Reflective PE Injection ในหน่วยความจำ (`+35`)**
4. **สกัดกั้นมัลแวร์ที่ซื้อใบรับรองดิจิทัล (Signed Malware Catch):**
   * ใน Rule 3 แม้ไฟล์ `.exe` ใน `%TEMP%` จะมีใบรับรองดิจิทัลถูกต้อง (`IsValidSigned = true`) แต่หากระบบตรวจพบหลักฐานชัดเจนว่ามี **ลิงก์ C2 ใน RAM/ไฟล์ หรือมี Unbacked Reflective PE Injection (`คะแนน >= 85`)** ระบบจะสั่ง Freeze และแจ้งเตือนระดับ `CRITICAL` ทันที

---

## 🔒 2. การยกระดับความปลอดภัยตามผล Red-Team Audit รอบที่ 3

1. **`OWNER RIGHTS (S-1-3-4)` Kernel DACL (บล็อก `WRITE_DAC` และ `PROCESS_TERMINATE` แม้จาก User เดียวกัน):**
   * ใน [`HardenCurrentProcessDacl`](file:///E:/git_security/core/SentinelWatchdog.ps1#L131-L167) ได้เพิ่ม `CommonAce` สำหรับ **`OWNER RIGHTS` (`S-1-3-4`)** โดยจำกัดสิทธิ์ของเจ้าของโปรเซส (Owner) ให้เหลือเฉพาะ `QueryInformation | VM_Read | Synchronize` เท่านั้น
   * **ผลลัพธ์ที่พิสูจน์แล้วบน Windows 11:** แม้โปรเซสอื่นที่รันภายใต้ชื่อผู้ใช้เดียวกัน (Same User) พยายามเรียก `OpenProcess(WRITE_DAC)` (`0x00040000`) เพื่อแก้ DACL หรือเรียก `OpenProcess(PROCESS_TERMINATE)` (`0x0001`) เพื่อสั่งปิดโปรเซส Windows Kernel จะปฏิเสธการเข้าถึงทันที (`Handle = 0 / Access Denied`)!
2. **Fail-Closed External Trust Anchor (ตัด Fallback ที่เชื่อไฟล์บนดิสก์ทิ้ง 100%):**
   * ใน [`Get-TrustedWatchdogHash`](file:///E:/git_security/core/SentinelGuardian.ps1#L103-L125) ของ Guardian Twin ได้ **ลบโค้ด Fallback ที่อ่าน Hash จากไฟล์ `SentinelWatchdog.ps1` บนดิสก์ทิ้งทั้งหมด** หากไม่พบ Trust Anchor ใน Registry หรือ `manifest.json` ระบบจะเข้าสู่โหมด **Fail-Closed (ปฏิเสธการรันไฟล์ที่ไม่ผ่านการยืนยันทันที)**
3. **รหัสลับสุ่ม 256-bit เฉพาะเครื่อง (`CSPRNG InstallSecret`) แทนค่าคงที่ใน Repo:**
   * ยกเลิกการใช้ข้อความ Entropy คงที่ เปลี่ยนเป็นการสร้างกุญแจสุ่ม **256-bit CSPRNG (`32 bytes` จาก `RandomNumberGenerator`)** ตอนติดตั้ง (`InstallSecret`) เก็บไว้ใน `HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor` (เมื่อติดตั้งด้วยสิทธิ์ Admin) พร้อมเชื่อมต่อกับ Named Kernel Event (`Local\SecuritySentinelStopSignal`)
4. **Kernel ETW `Win32_ProcessStartTrace` & 29-Vector Persistence (รวม Windows Services):**
   * เชื่อมต่อกับ `Win32_ProcessStartTrace` (Kernel Process ETW Provider) เมื่อรันด้วยสิทธิ์ Admin (พร้อม Fallback ไปยัง WMI Event Stream และ Event ID `4104`/`4663`)
   * เพิ่ม **Vector ที่ 29: การตรวจสอบ Windows Services (`HKLM\SYSTEM\CurrentControlSet\Services` ImagePath)** เข้าไปใน [`Get-PersistenceSnapshot`](file:///E:/git_security/core/SentinelWatchdog.ps1#L995-L1014)

---

## 🧪 3. ชุดทดสอบอัตโนมัติที่เรียกฟังก์ชันจริง 100% (`core/Invoke-RedTeamAudit.ps1`)

สคริปต์ [`Invoke-RedTeamAudit.ps1`](file:///E:/git_security/core/Invoke-RedTeamAudit.ps1) ในเวอร์ชัน v7.0 ทำการ Dot-source โค้ดจริงของ `SentinelWatchdog.ps1` และ `SentinelGuardian.ps1` (`-LibraryOnly`) และรันการทดสอบจริง 6 ข้อบน Windows 11:
1. **Live Test 1:** เรียกใช้ฟังก์ชัน `Inspect-SingleProcess` จริงกับเคส `chrome.exe ➔ powershell.exe -enc <Base64>` ยืนยันการถอดรหัส Base64 และการให้คะแนน `100/100` (มี URL) และ `85/100` (ไม่มี URL) พร้อมแจ้งเตือน `CRITICAL`
2. **Live Test 2:** เรียกใช้ฟังก์ชัน `Inspect-SingleProcess` จริงกับ `SentinelDashboard.ps1 -WindowStyle Hidden`, สคริปต์ทำงานปกติที่ใช้ `-WindowStyle Hidden`, และ `Code.exe` ที่รันไฟล์ `.exe` ไม่มีลายเซ็นใน `%TEMP%` ยืนยัน **0 False Positives (`Frozen = False`)**
3. **Live Test 3:** จองหน่วยความจำจริงด้วย `VirtualAlloc` (`PAGE_EXECUTE_READWRITE 0x40`) เขียนส่วนหัว `MZ`/`PE\0\0` จำลอง Reflective DLL Injection และลิงก์ C2 ลงใน RAM แล้วเรียก `AnalyzeProcessMemory($PID)` จริง ยืนยันว่าตรวจพบทั้ง `RWX Region`, `Unbacked Reflective PE` และดึงลิงก์ C2 ออกมาจาก RAM ได้จริง
4. **Live Test 4:** สร้างโปรเซสลูกที่เปิดใช้ `HardenCurrentProcessDacl()` แล้วโจมตีจากโปรเซสผู้ใช้เดียวกันด้วย `OpenProcess(PROCESS_TERMINATE)` และ `OpenProcess(WRITE_DAC)` ยืนยันว่า Kernel บล็อกทั้งคู่ (`Handle = 0`) และเรียก `Test-GuardianStopToken` จริงเพื่อยืนยันการปฏิเสธโทเคนปลอม
5. **Live Test 5:** สร้างไฟล์จำลองแล้วเรียก `Move-ToQuarantine` จริงตามด้วย `Restore-QuarantinedFile` จริง ยืนยันการกู้คืนไฟล์กลับมาที่เดิมพร้อมเช็กค่าแฮช SHA-256 ตรงกัน 100%
6. **Live Test 6:** เรียก `Get-PersistenceSnapshot` จริง (ตรวจสอบครบ 29 หมวดหมู่รวมถึง Windows Services กว่า 200+ รายการ) และเรียก `Parse-Event4663Xml` จริง

---

## ⚖️ ขอบเขตทางสถาปัตยกรรม (Architectural Boundaries)

* **แนะนำให้ติดตั้งด้วยสิทธิ์ Administrator (`คลิกขวา Run as administrator ที่ 1-Click-Install.bat`):** เพื่อให้ระบบติดตั้งลงใน `C:\Program Files\SecuritySentinel`, ล็อกสิทธิ์ไฟล์ด้วย `icacls`, เก็บ `InstallSecret` และ `IntegrityAnchor` ไว้ใน `HKLM` ที่ผู้ใช้ทั่วไปแก้ไขไม่ได้, และเปิดใช้ `Win32_ProcessStartTrace` (Kernel ETW) ร่วมกับ SACL Event `4663`
* **หากติดตั้งด้วยสิทธิ์ User ธรรมดา (ไม่กด Run as Admin):** ระบบจะทำงานใน `%LOCALAPPDATA%\SecuritySentinel` และเก็บค่าใน `HKCU` ซึ่งช่วยป้องกันมัลแวร์ทั่วไปและล็อก DACL (`OWNER RIGHTS`) ป้องกันการสั่งปิดโปรเซสได้ แต่จะไม่สามารถแยกสิทธิ์ Registry ออกจากโปรเซสที่รันด้วย User เดียวกันได้เทียบเท่าโหมด Admin
