========================================================================
   SECURITY SENTINEL ULTRA v5.0 - Red-Team Hardened Portable EDR
========================================================================

แพ็กเกจชุดป้องกันมัลแวร์ระดับ EDR แบบ "Portable 100%" สามารถนำไปติดตั้งลงเครื่องอื่นผ่าน Flash Drive
หรือใช้กู้ชีพ/ป้องกันเครื่องตัวเอง โดยไม่ต้องต่ออินเทอร์เน็ตในการบล็อกมัลแวร์!

------------------------------------------------------------------------
[วิธีติดตั้ง] (ทำงานใน 1 คลิก):
------------------------------------------------------------------------
1. ดับเบิ้ลคลิก (หรือคลิกขวา Run as administrator):
   -> "1-Click-Install.bat"
   ระบบจะติดตั้งเอนจิน v5.0 (Tier 1-5 + Guardian Twin + Kernel DACL + NTFS ACL Lock),
   ตั้งค่าเปิดทำงานพร้อม Windows, และสร้างไอคอน "Security Sentinel Dashboard" ไว้บน Desktop ทันที

2. เปิดหน้าต่างควบคุม Command Center Dashboard:
   -> ดับเบิ้ลคลิกไอคอนบน Desktop หรือกด "Sentinel-Dashboard.bat"

3. ตั้งค่าการแจ้งเตือน Discord Webhook (เข้ารหัสด้วย DPAPI อัตโนมัติ):
   -> ใน Dashboard จะมีช่อง "[WEBHOOK] Notification URL:"
   -> นำ Webhook URL จากห้อง Discord ของคุณมาวาง แล้วกด "[SAVE] Save Config"
   -> ระบบจะเข้ารหัส Webhook ด้วย Windows DPAPI ทันที (ไม่เก็บเป็น Plaintext)
   -> กดปุ่ม "[TEST] Test Notification" เพื่อทดสอบการแจ้งเตือนทันที!

4. การถอนการติดตั้งอย่างสมบูรณ์:
   -> ดับเบิ้ลคลิก "1-Click-Uninstall.bat"

------------------------------------------------------------------------
[9 การอัปเกรดระดับ Red-Team Hardened ใน v5.0]:
------------------------------------------------------------------------
1. Real Kernel DACL Self-Defense (SetKernelObjectSecurity):
   - เขียนกฎปฏิเสธการสั่งปิดโปรเซส (Deny Terminate / Suspend / VM Write) ลงใน Kernel Handle จริง
   - ป้องกันมัลแวร์ระดับ User สั่งปิด Watchdog และ Guardian Twin

2. True Live Process RAM Forensics (VirtualQueryEx + ReadProcessMemory):
   - สแกนหน่วยความจำเสมือน (Virtual Memory) ของโปรเซสต้องสงสัยโดยตรง
   - ดึงลิงก์เซิร์ฟเวอร์แฮกเกอร์ (C2), Discord Webhook และ Telegram Token ที่ถูกถอดรหัสอยู่ใน RAM

3. Cryptographic DPAPI Stop-Token (graceful_stop.token):
   - ยกเลิกไฟล์ graceful_stop.flag แบบเก่า เปลี่ยนเป็นโทเคนเข้ารหัส DPAPI ผูกกับเวลาและ PID
   - มัลแวร์ไม่สามารถสร้างไฟล์หลอกเพื่อสั่งปิดระบบได้อีกต่อไป

4. Zero Command-Line Bypass & SHA-256 Integrity Check:
   - ยกเลิกการข้ามการตรวจด้วยชื่อใน Command Line เปลี่ยนเป็นตรวจ PID จริงและเช็กแฮช SHA-256 ของสคริปต์

5. Anti-EoP NTFS ACL Hardening:
   - ล็อกสิทธิ์ไฟล์ .ps1 ด้วย icacls เมื่อติดตั้งด้วยสิทธิ์ Admin ป้องกันมัลแวร์แอบแก้สคริปต์เพื่อยกระดับสิทธิ์

6. Composite PID|CreationDate Tracking & Dead-PID Pruning:
   - ป้องกันช่องโหว่ PID Reuse เมื่อ Windows นำเลข PID เก่ากลับมาใช้ซ้ำ

7. Strict Distinguished Name (DN) & CA Issuer Authenticode Check:
   - ตรวจสอบใบรับรองดิจิทัลทั้งชื่อเต็ม (CN=/O=) และผู้ออกใบรับรอง (Root/Intermediate CA)

8. Risk-Score Gated Auto-Freeze & ScanIntervalSeconds:
   - คำนวณคะแนนความเสี่ยง (Heuristic Risk Score) ก่อนตัดสินใจ Freeze ลดปัญหา False Positive กับเกมและ Discord

9. DPAPI Secret Encryption & SACL Canary Read-Audit (Event ID 4663):
   - เข้ารหัส Discord Webhook / VirusTotal Key ใน config.json ด้วย DPAPI และตรวจจับการแอบอ่านไฟล์กับดัก
========================================================================
