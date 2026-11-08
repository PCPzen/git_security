========================================================================
   SECURITY SENTINEL ULTRA v6.0 - Enterprise Telemetry & Behavioral EDR
========================================================================

แพ็กเกจชุดป้องกันมัลแวร์ระดับ EDR แบบ "Portable 100%" พัฒนาตามกรอบ 6 Pillars:
Kernel/Event Telemetry, Live Memory Forensics, External Code Integrity,
Behavioral Correlation, Safe Automated Response และ Red-Team Audit Suite

------------------------------------------------------------------------
[วิธีติดตั้ง] (แนะนำให้คลิกขวา Run as administrator):
------------------------------------------------------------------------
1. คลิกขวาที่ไฟล์ "1-Click-Install.bat" -> เลือก "Run as administrator"
   - เมื่อรันด้วยสิทธิ์ Admin ระบบจะติดตั้งลง C:\Program Files\SecuritySentinel
   - ล็อกสิทธิ์ไฟล์ .ps1 ด้วย icacls (ป้องกัน User Malware แก้ไขสคริปต์)
   - บันทึกค่าแฮช Trust Anchor ลงใน HKLM Registry และเปิด SACL Event 4663

2. เปิดหน้าต่างควบคุม Command Center Dashboard:
   -> ดับเบิ้ลคลิกไอคอนบน Desktop หรือกด "Sentinel-Dashboard.bat"

3. การรันชุดทดสอบจำลองการโจมตี (Red-Team Self-Audit):
   -> รันไฟล์ core\Invoke-RedTeamAudit.ps1 ด้วย PowerShell

------------------------------------------------------------------------
[6 แกนหลักที่อัปเกรดใน v6.0 Enterprise Edition]:
------------------------------------------------------------------------
1. Deep Event Telemetry (Event ID 4104 & SACL 4663 XML Attribution):
   - ตรวจจับ PowerShell ScriptBlock ในหน่วยความจำ (Event 4104)
   - แยกวิเคราะห์ XML ของ Event 4663 ระบุชื่อโปรเซสและ PID ที่แอบอ่านไฟล์ Canary

2. Live Memory Forensics & Injection Scanner:
   - สแกน RAM ด้วย VirtualQueryEx + ReadProcessMemory ดึงลิงก์ C2/Webhook
   - ตรวจจับ MEM_PRIVATE RWX Pages และส่วนหัวไฟล์ MZ/PE ที่ซ่อนใน RAM (Reflective PE)

3. External Code Integrity & Hardened DACL:
   - ปฏิเสธสิทธิ์ WRITE_DAC (0x00040000) และ WRITE_OWNER (0x00080000) ใน DACL
   - ตรวจสอบแฮช SHA-256 เทียบกับ Registry IntegrityAnchor และ manifest.json
   - โทเคนสั่งปิดระบบผูกกับ Custom Entropy และต้องตรงกับหมายเลข PID ของ Watchdog จริง

4. Behavioral Correlation & Base64 Command Decoder + 28 Persistence Vectors:
   - ถอดรหัส Base64 (-enc / FromBase64String) ก่อนคำนวณคะแนนความเสี่ยงเสมอ
   - แก้ไขกฎ Rule 1 + Rule 2: หากเบราว์เซอร์เปิด PowerShell แบบเข้ารหัส จะได้คะแนน >= 75/100
     แจ้งเตือน CRITICAL เสมอ และสั่ง Freeze ทันทีโดยไม่ข้ามกฎ
   - ตรวจสอบ Persistence จริงครบ 28 จุด (Run/RunOnce, Winlogon, IFEO, WMI, Tasks, PSProfile ฯลฯ)

5. Safe Automated Response (NtResumeProcess & Signed Binary Safety):
   - ปกป้องตัวติดตั้งโปรแกรมที่มีใบรับรองดิจิทัลถูกต้องใน %TEMP% ไม่ให้ถูก Freeze ผิดพลาด
   - ปุ่ม [RESUME / ROLLBACK] เรียกใช้ NtResumeProcess ปลดแช่แข็งโปรเซสจริงและกู้คืนไฟล์กักกัน

6. Red-Team Testing (Invoke-RedTeamAudit.ps1):
   - ชุดทดสอบอัตโนมัติ 6 ข้อตามกรอบ MITRE ATT&CK ยืนยันความถูกต้องของทุกกลไก
========================================================================
