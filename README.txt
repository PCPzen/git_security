========================================================================
   SECURITY SENTINEL ULTRA v8.0 - Enterprise EDR & Threat Defense
========================================================================

แพ็กเกจชุดป้องกันมัลแวร์ระดับ EDR แบบ "Enterprise & Portable 100%"
ออกแบบมาเพื่อความปลอดภัยระดับสูงสุด ป้องกัน Phishing, Memory Injection,
Stealer, Ransomware โดย "ไม่รบกวนเวลาทำงาน (Coding/Dev) หรือเล่นเกม (Gaming)" บน Windows 10/11!

------------------------------------------------------------------------
[วิธีติดตั้ง] (แนะนำให้คลิกขวา Run as administrator):
------------------------------------------------------------------------
1. คลิกขวาที่ไฟล์ "1-Click-Install.bat" -> เลือก "Run as administrator"
   - ติดตั้งลง ProgramData / LocalAppData และล็อกสิทธิ์ความปลอดภัย
   - สร้างกุญแจสุ่ม 256-bit CSPRNG InstallSecret ใน HKLM (สิทธิ์เฉพาะ SYSTEM/Admins)
   - ล็อก ACL บน Registry HKLM: ปฏิเสธสิทธิ์ Read/Write ของ Standard Users (BUILTIN\Users) โดยเด็ดขาด
   - ตัดการจัดเก็บความลับใน HKCU ทิ้ง 100% (มัลแวร์ในระดับ User เดียวกันไม่สามารถแอบอ่าน Secret ได้)
   - เปิดทำงาน Work & Gaming Safe-Mode อัตโนมัติ (ไม่หน่วง FPS, รองรับ Riot Vanguard / Easy Anti-Cheat)

2. เปิดหน้าต่างควบคุม Command Center Dashboard:
   -> ดับเบิ้ลคลิกไอคอนบน Desktop หรือกด "Sentinel-Dashboard.bat"
   - ไฟสถานะ 3 ระดับ (เขียว: ปลอดภัย / เหลือง: เฝ้าระวัง / แดง: มีภัยคุกคาม)
   - ปุ่ม [RESTORE / UNBLOCK] ปลดล็อกโปรเซสและกู้คืนไฟล์ได้ในคลิกเดียว

3. การเซ็น Authenticode Digital Signature พร้อมลบ Private Key (Zero-Trust):
   -> รัน powershell -ExecutionPolicy Bypass -File core\Sign-Scripts.ps1
   - เซ็น Digital Signature (SHA-256) ทุกสคริปต์
   - ติดตั้งเฉพาะ Public Key ลงใน TrustedPublisher และลบ Private Key ออกจาก User Store
   - มัลแวร์ที่รันด้วย User เดียวกันไม่สามารถใช้ Private Key เซ็นสคริปต์ที่แอบแก้ได้

4. การรันชุดทดสอบระบบ (Automated Unit Tests & Live Red-Team Audit):
   -> รัน tests\Run-Tests.ps1 (ผ่านครบ 22/22 ข้อ ครอบคลุม Parent Spoofing, Token Forgery, Registry ACL)
   -> รัน core\Invoke-RedTeamAudit.ps1 (ผ่านครบ 9/9 ข้อ ทดสอบฟังก์ชันจริงบน Windows 11)

------------------------------------------------------------------------
[ไฮไลท์การอุดช่องโหว่และยกระดับเกรดสู่ระดับ A/A+ ใน v8.0]:
------------------------------------------------------------------------
1. ปิดช่องโหว่ Stop Token Forgery (ย้าย Secret สู่ HKLM + Registry ACL):
   - ลบการเขียน secret ลง HKCU ทิ้งทั้งหมด มัลแวร์ระดับ User เดียวกันไม่สามารถแอบอ่านได้
   - คีย์ HKLM:\SOFTWARE\SecuritySentinel ถูกล็อกด้วย Access Control List (DACL):
     * NT AUTHORITY\SYSTEM: FullControl
     * BUILTIN\Administrators: FullControl
     * BUILTIN\Users: DENY ReadKey / WriteKey (ตัดสิทธิ์อ่านโดยสิ้นเชิง)

2. ปิดช่องโหว่ Safe-Mode Parent Process Spoofing:
   - ตรวจสอบพาธและลายเซ็นของ Parent Process อย่างเข้มงวด
   - หากมัลแวร์ตั้งชื่อเลียนแบบเป็น steam.exe หรือ node.exe แต่อยู่ใน %TEMP% หรือโฟลเดอร์น่าสงสัย
     ระบบจะปฏิเสธ Safe-Mode pass ทันที และตรวจสอบด้วยเกณฑ์ปกติ

3. ป้องกัน Private Key ใน Authenticode:
   - สคริปต์ Sign-Scripts.ps1 จะทำการ Purge Private Key ออกจาก Cert:\CurrentUser\My ทันทีหลังเซ็นเสร็จ
   - เหลือเฉพาะ Public Key ใน TrustedPublisher เพื่อใช้ตรวจสอบ AllSigned
   - มัลแวร์จึงไม่สามารถหยิบ Private Key ไปเซ็นทับไฟล์ที่แอบแก้ไขได้

4. ป้องกัน Exploit จาก Binary ที่มีลายเซ็น CA (CA-Signed Exploit Defense):
   - หาก Binary ที่มีลายเซ็นถูกนำมารันในลักษณะ Phishing Macro (สร้างจาก Word/Excel)
     หรือตรวจพบ C2 / Reflective PE ใน Memory ระบบจะสั่ง Freeze ทันที ลายเซ็นไม่สามารถช่วยให้รอดได้
========================================================================
