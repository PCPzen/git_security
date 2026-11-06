========================================================================
   SECURITY SENTINEL ULTRA v4.0 - Next-Gen Autonomous Endpoint Defense
========================================================================

แพ็กเกจชุดป้องกันมัลแวร์ระดับ EDR แบบ "Portable 100%" สามารถนำไปติดตั้งลงเครื่องอื่นผ่าน Flash Drive
หรือใช้กู้ชีพ/ป้องกันเครื่องตัวเอง โดยไม่ต้องต่ออินเทอร์เน็ตในการบล็อกมัลแวร์!

------------------------------------------------------------------------
[วิธีติดตั้ง] (ทำงานใน 1 คลิก):
------------------------------------------------------------------------
1. ดับเบิ้ลคลิก:
   -> "1-Click-Install.bat"
   ระบบจะติดตั้งเอนจิน v4.0 (Tier 1-5 + Guardian Twin), ตั้งค่าเปิดทำงานพร้อม Windows,
   และสร้างไอคอน "Security Sentinel Dashboard" ไว้บน Desktop ทันที

2. เปิดหน้าต่างควบคุม Command Center Dashboard:
   -> ดับเบิ้ลคลิกไอคอนบน Desktop หรือกด "Sentinel-Dashboard.bat"

3. ตั้งค่าการแจ้งเตือน Discord Webhook:
   -> ใน Dashboard จะมีช่อง "Discord Webhook URL:"
   -> นำ Webhook URL จากห้อง Discord ของคุณมาวาง แล้วกด "[SAVE] Save Webhook"
   -> กดปุ่ม "[TEST] Test Discord & Toast" เพื่อทดสอบการแจ้งเตือนทันที!

4. การถอนการติดตั้งอย่างสมบูรณ์:
   -> ดับเบิ้ลคลิก "1-Click-Uninstall.bat"

------------------------------------------------------------------------
[5 โมดูลอัปเกรดใหม่ใน v4.0 Next-Gen EDR]:
------------------------------------------------------------------------
1. Guardian Twin & Tamper Protection (ระบบป้องกันตัวเอง 2 ชั้น):
   - มีโปรเซสคู่แฝด (SentinelWatchdog + SentinelGuardian) เฝ้ากันเองตลอดเวลา
   - หากมัลแวร์สั่งปิดตัวหลัก ตัวแฝดจะชุบชีวิตขึ้นมาใหม่ทันทีและยิงแจ้งเตือนเข้า Discord

2. Real-Time WMI/CIM Kernel Process Stream:
   - ดักจับการสร้างโปรเซสใหม่แบบเรียลไทม์ระดับเสี้ยววินาที

3. DLL Injection & Memory Module Guard:
   - สแกนโมดูล (.dll) ที่ถูกฉีดเข้าเบราว์เซอร์และเกม (Chrome, Edge, Discord, Steam, Roblox)
   - ใช้ระบบ HashSet Cache ทำให้กิน CPU 0.0% ไม่กระทบ FPS เวลาเล่นเกม

4. Automated Memory Forensic & C2 Extractor:
   - สกัดลิงก์ Discord Webhook, Telegram Bot, และ IP ของแฮกเกอร์ออกมาจากไฟล์มัลแวร์อัตโนมัติ
   - บันทึกหลักฐานลงโฟลเดอร์ quarantine/forensic_PID_*.json

5. Local Micro-ML Heuristic & Shannon Entropy Engine:
   - คำนวณค่าความซับซ้อนของไบต์ (Shannon Entropy 0.0-8.0) เพื่อจับมัลแวร์ที่ถูกเข้ารหัส/Pack
   - ประเมินคะแนนความเสี่ยง (Risk Score 0-100) แสดงผลบน Discord Alert ทันที
========================================================================
