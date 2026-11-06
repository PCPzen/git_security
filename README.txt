========================================================================
   SECURITY SENTINEL ULTRA v3.2 - Autonomous Endpoint Defense & EDR
========================================================================

แพ็กเกจชุดป้องกันมัลแวร์แบบ "Portable 100%" สามารถนำไปติดตั้งลงเครื่องอื่นผ่าน Flash Drive
หรือใช้กู้ชีพ/ป้องกันเครื่องตัวเอง โดยไม่ต้องต่ออินเทอร์เน็ตในการบล็อกมัลแวร์!

------------------------------------------------------------------------
[วิธีติดตั้ง] (ทำงานใน 1 คลิก):
------------------------------------------------------------------------
1. ดับเบิ้ลคลิก:
   -> "1-Click-Install.bat"
   ระบบจะติดตั้งระบบ Tier 1-5, ตั้งค่าเปิดทำงานพร้อม Windows อัตโนมัติ,
   และสร้างไอคอน "Security Sentinel Dashboard" ไว้บน Desktop ทันที

2. เปิดหน้าต่างควบคุม Command Center Dashboard:
   -> ดับเบิ้ลคลิกไอคอนบน Desktop หรือกด "Sentinel-Dashboard.bat"

3. ตั้งค่าการแจ้งเตือน Discord Webhook (รองรับ v3.0+):
   -> ใน Dashboard จะมีช่อง "Discord Webhook URL:"
   -> นำ Webhook URL จากห้อง Discord ของคุณมาวาง แล้วกด "[SAVE] Save Webhook"
   -> กดปุ่ม "[TEST] Test Discord & Toast" เพื่อทดสอบการแจ้งเตือนทันที!

4. การถอนการติดตั้งอย่างสมบูรณ์:
   -> ดับเบิ้ลคลิก "1-Click-Uninstall.bat"

------------------------------------------------------------------------
[สถาปัตยกรรมการป้องกัน 5 ระดับ] (Tier 1 - Tier 5 Master Plan):
------------------------------------------------------------------------
* Tier 1: Core Watchdog & Browser Hijack Guard
  - ล็อกโฟลเดอร์ Chrome, Edge, Brave, Opera ป้องกันโทรจันขโมยรหัสผ่าน/เซสชัน (คุกกี้)
  - ตรวจจับ Persistence ทุกจุด (HKCU/HKLM Run, Startup, Scheduled Tasks, CLSID)
  - วางกับดัก Canary Honeypot ดักจับ Ransomware และ Game Infostealer ทันทีที่แตะต้อง

* Tier 2: Real-Time Process & Parent-Child Telemetry Engine
  - ตรวจจับความผิดปกติของ Process Tree แบบเรียลไทม์ (เบราว์เซอร์หรือเกมแอบเปิด CMD, PowerShell, MSHTA)
  - สกัดกั้นคำสั่ง Obfuscated / Encoded PowerShell (-EncodedCommand / IEX) ทันที

* Tier 3: Native NTAPI Kernel Freeze & Network Killswitch
  - ใช้ ntdll.dll!NtSuspendProcess สั่ง "แช่แข็ง Process มัลแวร์ในระดับเคอร์เนล" ทันที ไม่ให้ทำงานต่อ
  - ตัดการเชื่อมต่อมัลแวร์กับ Server ของแฮกเกอร์ทันที

* Tier 4: Zero-Trust Authenticode & Memory Hardening
  - บล็อกและแช่แข็งไฟล์แปลกปลอมใน Temp / AppData ที่ไม่มีลายเซ็นดิจิทัล
  - รองรับ Whitelist ผู้พัฒนาเกมและซอฟต์แวร์สากล (Overwolf, KRAFTON/PUBG, Roblox, Valve, Epic, Riot, Discord ฯลฯ)
  - ตรวจสอบ LSASS RunAsPPL ป้องกันการดัมป์รหัสผ่านจากหน่วยความจำ

* Tier 5: Threat Intelligence & Incident Response
  - คำนวณ SHA-256 แบบเรียลไทม์ และผูกกับ VirusTotal v3 API
  - ส่งแจ้งเตือนฉุกเฉินพร้อมแท็ก @everyone บน Discord ทันทีที่มีภัยคุกคาม
========================================================================
