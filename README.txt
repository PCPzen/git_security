========================================================================
   SECURITY SENTINEL ULTRA v3.0 - ระบบป้องกัน Endpoint ระดับ EDR (Tier 1-5)
========================================================================

ไฟล์ชุดนี้ออกแบบมาให้เป็น "Portable 100%" สามารถก๊อปปี้ทั้งโฟลเดอร์นี้ใส่ Flash Drive
หรือส่งให้เพื่อน/เครื่องคอมพิวเตอร์เครื่องอื่นใช้งานได้ทันที โดยไม่ต้องลงโปรแกรมเสริมใดๆ!

------------------------------------------------------------------------
📌 วิธีใช้งาน (ง่ายมาก 1 คลิก):
------------------------------------------------------------------------
1. ดับเบิลคลิกไฟล์:
   👉 "1-Click-Install.bat"
   ระบบจะอัปเกรด/ติดตั้งเอนจิน Tier 1-5, เปิดเกราะป้องกัน Windows, และสร้างไอคอน
   "Security Sentinel Dashboard" ไว้บนหน้า Desktop ให้ทันที

2. เปิดหน้าจอ Command Center Dashboard:
   👉 ดับเบิลคลิกไอคอนบน Desktop หรือกด "Sentinel-Dashboard.bat"

3. วิธีเชื่อมต่อ Discord Webhook (ใหม่ใน v3.0!):
   👉 เปิดหน้าจอ Dashboard ขึ้นมา จะมีช่อง "🔔 Discord Webhook URL:" อยู่บนหน้าจอทันที!
   👉 วางลิงก์ Webhook ของห้อง Discord ลงไป -> กด "[SAVE] Save Webhook"
   👉 กดปุ่ม "[TEST] Test Discord & Toast" เพื่อทดสอบส่งการ์ด Rich Embed เข้ามือถือได้ทันที!

4. หากต้องการถอนการติดตั้งในอนาคต:
   👉 ดับเบิลคลิก "1-Click-Uninstall.bat"

------------------------------------------------------------------------
🛡️ สถาปัตยกรรมความปลอดภัยทั้ง 5 ระดับ (Tier 1 – Tier 5 Master Plan):
------------------------------------------------------------------------
🔹 Tier 1: Core Watchdog & Browser Hijack Guard
   - เฝ้าระวัง Chrome, Edge, Brave, Opera ป้องกันการแอบหย่อนไฟล์ DLL แปลกปลอม (เคส NIKKE / Mod)
   - ตรวจสอบ Digital Signature (Authenticode) อัตโนมัติ ไม่บล็อกมั่ว (Zero False-Positive)
   - เฝ้าระวัง Persistence 28+ จุด (HKCU/HKLM Run, RunOnce, Startup, Scheduled Tasks, CLSID)
   - วางกับดัก Canary Honeypot ใน AppData และ Documents ดักจับมัลแวร์สาย Infostealer

🔹 Tier 2: Real-Time Process & Parent-Child Telemetry Engine
   - ตรวจจับพฤติกรรม Parent-Child Anomaly เช่น เบราว์เซอร์หรือตัวรันเกมแอบเปิด PowerShell, CMD,
     MSHTA, Regsvr32 หรือ Certutil เบื้องหลัง
   - ดักจับการรันคำสั่ง PowerShell แบบเข้ารหัสอำพราง (-EncodedCommand / IEX / DownloadString)

🔹 Tier 3: Automated Incident Response (NtSuspendProcess & Network Killswitch)
   - ฝังโมดูล C# Native API (ntdll.dll!NtSuspendProcess) แช่แข็งโปรเซสมัลแวร์ในเสี้ยววินาที (Micro-Freeze)
   - ปุ่ม "[KILLSWITCH] Emergency Cut Network" ตัดการเชื่อมต่ออินเทอร์เน็ตฉุกเฉินในคลิกเดียว และกดกู้คืนได้ทันที

🔹 Tier 4: Zero-Trust Execution & Memory Hardening
   - ดักจับการรันไฟล์ .exe ที่ไม่มีใบรับรองดิจิทัลจากโฟลเดอร์อันตราย (%TEMP%, User Data)
   - เปิด PowerShell Script Block Logging (Event ID 4104) และ LSASS Memory Protection (RunAsPPL)

🔹 Tier 5: Autonomous Threat Intelligence & Discord Rich Webhook
   - คำนวณค่าแฮช SHA-256 ของไฟล์แปลกปลอมทุกชิ้น พร้อมแนบลิงก์ตรวจสอบ VirusTotal อัตโนมัติ
   - ส่งการ์ดแจ้งเตือน Rich Embed แยกสีตามความรุนแรงเข้า Discord พร้อมแท็ก @everyone เมื่อเกิดเหตุวิกฤต
========================================================================
