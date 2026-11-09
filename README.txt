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
   - เปิดทำงาน Work & Gaming Safe-Mode อัตโนมัติ (ไม่หน่วง FPS, รองรับ Riot Vanguard / Easy Anti-Cheat)

2. เปิดหน้าต่างควบคุม Command Center Dashboard:
   -> ดับเบิ้ลคลิกไอคอนบน Desktop หรือกด "Sentinel-Dashboard.bat"
   - ไฟสถานะ 3 ระดับ (เขียว: ปลอดภัย / เหลือง: เฝ้าระวัง / แดง: มีภัยคุกคาม)
   - ปุ่ม [RESTORE / UNBLOCK] ปลดล็อกโปรเซสและกู้คืนไฟล์ได้ในคลิกเดียว

3. การเซ็น Authenticode Digital Signature ให้กับสคริปต์ทั้งหมด:
   -> รัน powershell -ExecutionPolicy Bypass -File core\Sign-Scripts.ps1
   - รองรับ Execution Policy แบบ AllSigned เพื่อความน่าเชื่อถือสูงสุด

4. การรันชุดทดสอบระบบ (Automated Unit Tests & Live Red-Team Audit):
   -> รัน tests\Run-Tests.ps1 (ผ่าน 17/17 ข้อ)
   -> รัน core\Invoke-RedTeamAudit.ps1 (ผ่าน 9/9 ข้อ)

------------------------------------------------------------------------
[คำแนะนำการแจกจ่าย / อัปโหลดไฟล์เพื่อป้องกัน False Positive]:
------------------------------------------------------------------------
* คำเตือน: ระบบคลาวด์เช่น Google Drive และ Antivirus สแกนไฟล์ .ps1 ดิบๆ
  ที่มีคำสั่งควบคุมระบบและอาจเข้าใจผิดว่าเป็นมัลแวร์ (False Positive)
* วิธีการที่ถูกต้อง:
  1. บีบอัดเป็นไฟล์ ZIP แบบใส่รหัสผ่าน (Password-Protected ZIP / 7z)
  2. แจกจ่ายผ่าน GitHub Releases หรือ Git Clone โดยตรง
  3. คอมไพล์เป็นตัวติดตั้ง .exe / .msi (Inno Setup) พร้อมเซ็น Authenticode

------------------------------------------------------------------------
[ไฮไลท์การอัปเกรดใน v8.0 Enterprise EDR Edition]:
------------------------------------------------------------------------
1. Authenticode Code Signing:
   - เพิ่ม Sign-Scripts.ps1 เพื่อเซ็น Digital Signature (SHA-256) ทุกสคริปต์
   - บังคับใช้ Execution Policy แบบ AllSigned ได้ 100%

2. DPAPI Secret Vault:
   - เข้ารหัสความลับ (Discord Webhook, API Keys) ด้วย System.Security.Cryptography.ProtectedData
   - ผูกกับ Windows Account + Entropy Key เฉพาะเครื่อง ป้องกันมัลแวร์ขโมย Token

3. Windows Event Viewer Integration:
   - ส่งต่อ Log ความปลอดภัยเข้า Application Log (Source: SecuritySentinel, Event ID 4000-4005)
   - ป้องกันการดัดแปลงหรือลบหลักฐานในไฟล์ Text ทั่วไป

4. Dashboard Anti-Bypass & Zero-Trust Architecture:
   - อุดช่องโหว่การต่อท้ายคำสั่งด้วยชื่อสคริปต์เพื่อหลบการตรวจจับ
   - ตรวจสอบพารามิเตอร์ -File, Full Path, และแฮช SHA-256 กับ Trust Anchor
   - ปฏิเสธคำสั่งที่มีการ Encode (-enc), Inline (-Command), หรือ Chaining (&&, ;, |) ทันที

5. Zero-Trust Name-Spoofing Immunity ใน Safe-Mode:
   - ตัดการตรวจสอบชื่อไฟล์ฝั่ง Child ($cName) ออกจาก Safe-Mode
   - ป้องกันมัลแวร์ไม่ให้หลบการตรวจจับด้วยการตั้งชื่อเลียนแบบ node.exe หรือ python.exe ใน %TEMP%

6. Phishing Parent Process Matrix (+50 Risk Score):
   - เพิ่มเกณฑ์ตรวจจับ Macro Exploit จาก Office (Word, Excel, PowerPoint, Outlook), PDF Readers (Acrobat), และโปรแกรมบีบอัดไฟล์ (WinRAR, 7-Zip)
   - สั่ง Freeze ทันทีเมื่อโปรแกรมกลุ่มนี้พยายามสร้าง Shell หรือ LOLBin

7. Memory Forensics 64 MB Budget:
   - ขยายขอบเขตการสแกน Live RAM เป็น 64 MB และ Region ละ 1 MB
   - ตรวจจับ Injected C2 Strings, RWX Private Regions, และ Unbacked PE Headers แม่นยำยิ่งขึ้น

8. Dashboard 3-State Traffic Light & Safe Rollback:
   - แสดงไฟสถานะ 3 สี (เขียว / ส้ม / แดง)
   - ปุ่มกู้คืนและปลดบล็อกในคลิกเดียว (One-Click Process Thaw & Quarantine Recovery)
========================================================================
