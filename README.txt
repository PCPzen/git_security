========================================================================
   SECURITY SENTINEL ULTRA v8.0 - User-Mode EDR & Endpoint Defense
========================================================================

เครื่องมือตรวจจับและตอบโต้ภัยคุกคามระดับ User-Mode (Ring 3 EDR) สำหรับ Windows 10/11
ออกแบบให้ทำงานร่วมกับการทำงาน (Coding/Dev/Office) และการเล่นเกม (Gaming) ได้อย่างราบรื่น

------------------------------------------------------------------------
[วิธีติดตั้งและใช้งาน] (แนะนำให้คลิกขวา Run as administrator):
------------------------------------------------------------------------
1. คลิกขวาที่ไฟล์ "1-Click-Install.bat" -> เลือก "Run as administrator"
   - ติดตั้งสคริปต์หลักทั้ง 10 ไฟล์ลง C:\Program Files\SecuritySentinel
   - แยกไฟล์สถานะและ Log ไว้ที่ %LOCALAPPDATA%\SecuritySentinel
   - สร้างกุญแจสุ่ม 256-bit CSPRNG InstallSecret ใน HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor
   - ตั้งค่า ACL บน HKLM ให้อนุญาตเฉพาะ SYSTEM และ Administrators (Allow FullControl)
     โดยไม่ใช้กฎ Deny บน BUILTIN\Users เพื่อไม่ให้ผู้ดูแลระบบที่ Elevate แล้วถูกล็อกตัวเอง
   - เปิดการบันทึก Security Event ID 4688 (พร้อม CommandLine) เพื่อช่วยตรวจจับโปรเซสอายุสั้น

2. การเปิดหน้าต่างควบคุมและ System Tray:
   - ดับเบิ้ลคลิก "Sentinel-Dashboard.bat" เพื่อเปิดหน้าต่างควบคุมหลัก
   - ดับเบิ้ลคลิก "Sentinel-Tray.bat" เพื่อแสดงไอคอนสถานะมุมขวาล่าง

3. การหยุด/พักการทำงานชั่วคราว (Stop-Shield.bat):
   - บังคับยืนยันตัวตนด้วยสิทธิ์ Administrator (UAC) และถามยืนยันจากผู้ใช้ทุกครั้ง
   - ส่งโทเคนที่เข้ารหัสด้วย Secret ของระบบเพื่อให้ Watchdog และ Guardian หยุดตัวเองอย่างปลอดภัย
   - บันทึกเหตุการณ์ลง Windows Event Viewer (EventID 4006) และตั้งเวลาเปิดกลับอัตโนมัติใน 15 นาที

4. การรันชุดทดสอบระบบ (Automated Tests & Red-Team Audit):
   - powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1
   - powershell -NoProfile -ExecutionPolicy Bypass -File core\Invoke-RedTeamAudit.ps1

------------------------------------------------------------------------
[ขอบเขตสถาปัตยกรรมและข้อจำกัดตามความเป็นจริง (Ring 3 vs Ring 0)]:
------------------------------------------------------------------------
- ระบบนี้ทำงานในระดับ User-Mode (Ring 3) เท่านั้น ไม่ใช่ Kernel Driver (Ring 0) หรือ PPL
- การป้องกัน DACL (OWNER RIGHTS S-1-3-4) และ HKLM Trust Anchor ออกแบบมาเพื่อกั้น
  มัลแวร์หรือโปรเซสที่รันด้วยสิทธิ์ผู้ใช้ทั่วไป (Non-Elevated User)
- หากผู้โจมตีหรือมัลแวร์ได้สิทธิ์ Administrator หรือ SYSTEM บนเครื่องแล้ว ผู้โจมตีสามารถอ่านค่า
  ใน HKLM หรือหยุดโปรเซสระดับ User-Mode ได้ตามกลไกสิทธิ์ของระบบปฏิบัติการ Windows
========================================================================
