========================================================================
   SECURITY SENTINEL ULTRA v7.0 - Work & Gaming Safe-Mode Enterprise EDR
========================================================================

แพ็กเกจชุดป้องกันมัลแวร์ระดับ EDR แบบ "Portable 100%" ออกแบบมาให้ปลอดภัยสูงสุด
โดย "ไม่รบกวนเวลาทำงาน (Coding/Office) หรือเวลาเล่นเกม (Gaming)" บน Windows 10/11!

------------------------------------------------------------------------
[วิธีติดตั้ง] (แนะนำให้คลิกขวา Run as administrator):
------------------------------------------------------------------------
1. คลิกขวาที่ไฟล์ "1-Click-Install.bat" -> เลือก "Run as administrator"
   - ติดตั้งลง C:\Program Files\SecuritySentinel และล็อกสิทธิ์ด้วย icacls
   - สร้างกุญแจสุ่ม 256-bit CSPRNG InstallSecret และเก็บ Trust Anchor ใน HKLM
   - เปิดทำงาน Work & Gaming Safe-Mode อัตโนมัติ (ไม่ทำให้เกมหรือโปรแกรมทำงานค้าง!)

2. เปิดหน้าต่างควบคุม Command Center Dashboard:
   -> ดับเบิ้ลคลิกไอคอนบน Desktop หรือกด "Sentinel-Dashboard.bat"

3. การรันชุดทดสอบจำลองการโจมตีจริง (Live E2E Red-Team Audit):
   -> รันไฟล์ core\Invoke-RedTeamAudit.ps1 ด้วย PowerShell

------------------------------------------------------------------------
[ไฮไลท์การอัปเกรดใน v7.0 Work & Gaming Safe-Mode Edition]:
------------------------------------------------------------------------
1. Work & Gaming Safe-Mode (ทำงานและเล่นเกมไม่มีสะดุด 0% False Positive):
   - ยกเลิกการเหมารวม -WindowStyle Hidden และยกเว้นสคริปต์ของ Sentinel ที่ผ่านเช็ก SHA-256
   - ปกป้องโปรแกรมทำงาน (VS Code, Visual Studio, Node, Git, Python, Rust, Docker)
     และตัวรันเกม (Steam, Riot, Roblox, Epic, Overwolf) เวลาสร้างไฟล์ใน %TEMP%
   - Browser Watcher กักกันเฉพาะไฟล์มัลแวร์ที่ถูก Pack (Entropy >= 7.2) หรือมีลิงก์ C2
     ทำให้ Browser Extension และโมดูลเสริมทำงานได้ปกติ 100%

2. OWNER RIGHTS (S-1-3-4) Kernel DACL Self-Defense:
   - บล็อกทั้งสิทธิ์ PROCESS_TERMINATE (สั่งปิด) และ WRITE_DAC (สั่งแก้สิทธิ์)
     แม้แต่โปรเซสที่รันด้วยชื่อ User เดียวกันก็ไม่สามารถแก้ DACL หรือสั่งปิด Watchdog ได้!

3. Fail-Closed Trust Anchor & 256-bit CSPRNG Secret:
   - ยกเลิก Fallback ที่เชื่อไฟล์บนดิสก์ และเปลี่ยนมาใช้กุญแจสุ่ม 256-bit เฉพาะเครื่อง

4. Real End-to-End Automated Test Suite (Invoke-RedTeamAudit.ps1):
   - เรียกใช้ฟังก์ชันจริงของ Watchdog และ Guardian ทดสอบครบทั้ง 6 ด้านบน Windows 11
========================================================================
