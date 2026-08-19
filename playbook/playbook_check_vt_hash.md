# Playbook Kiểm tra Hash trên VirusTotal

## Mục đích
Đánh giá mức độ độc hại của file hash dựa trên dữ liệu VirusTotal. Playbook này được dùng **độc lập** — không cần thông tin đường dẫn, user, hay context bên ngoài.

---

## Các bước kiểm tra

### Bước 1: Đánh giá thông tin chung (General Info)
* Kiểm tra Community Score (reputation): Số càng âm → file càng đáng ngờ.
* Kiểm tra số lượng Security Vendor đánh dấu Malicious:
    * Nếu >= 30 AV báo Malicious => Là mã độc.
    * Nếu >= 5 AV báo Malicious và có ít nhất 1 trong 3 vendor nổi tiếng (Kaspersky, Bit Defender, Microsoft) cũng báo Malicious:
        * Nếu Popular Threat Label hoặc Threat Categories xác định rõ loại mã độc (trojan, ransomware, backdoor, worm, exploit, spyware, ...) => Là mã độc.
        * Nếu Popular Threat Label là riskware, hacktool, crack, PUP, adware hoặc không rõ ràng => Có thể là độc, tuỳ ngữ cảnh.
    * Nếu <= 5 và > 0 AV báo Malicious => Tỉ lệ độc thấp (có thể do trùng pattern, tuỳ vào việc các AV phân loại).
    * Nếu = 0 => Không phải file độc (Chú ý nếu là file .EXE có thể là DLL Sideloading).

### Bước 2: Đánh giá thông tin Detail
* **First Submission**: Thời gian lần đầu submit. Càng gần thời điểm hiện tại thì file càng mới, tỉ lệ bị mã độc bypass càng cao.
* **Names**: Chú ý các tên có thể được thay đổi. Thường các tên này sẽ na ná nhau, nếu tên thay đổi liên tục với nhiều loại khác nhau => Có thể là mã độc.
* **Signature verification**: File có được ký số hay không. Nếu không được ký số => Có thể là mã độc, tuỳ thuộc vào số lượng AV đánh giá.

### Bước 3: Đánh giá thông tin Relations
* **Contacted URLs/IPs/Domains**: Nếu ít nhất 1 trong 3 loại (URL/IP/Domain) có số lượng >= 3 với số lượng AV >= 5 báo Malicious => Có thể là CnC của mã độc.
    * **⛔ Relations = telemetry TỔNG HỢP của VirusTotal trên MỌI submission của hash, KHÔNG phải hành vi mạng của host/execution hiện tại.** Với binary phổ biến/hợp pháp (OS tool, interpreter: `net.exe`, `powershell.exe`, `svchost.exe`, `systemctl`, `bash`…), Contacted/Relations chứa RẤT NHIỀU domain — gồm cả domain hợp pháp (vd CDN Microsoft `*.onecdn.static.microsoft`, `*.windowsupdate.com`). CHỈ coi là CnC khi Bước 1 đã malicious (AV detection cao) VÀ phần lớn relations là malicious. KHÔNG kết luận file malicious, và KHÔNG khẳng định "file/process đã liên hệ domain X", chỉ dựa trên relations.
* **Dropped Files**: Nếu các file được thả xuống có số lượng AV >= 5 báo Malicious => File gốc là mã độc hoặc dropper.
* Nếu toàn bộ thông tin liên quan (URLs, IPs, Dropped Files) đều được đánh dấu độc hại => Khả năng rất cao đây là mã độc.

### Bước 4: Đánh giá thông tin Behavior (Sandbox)
* Thông tin dùng để phân tích nhanh mã độc, lấy các thông tin liên quan đến:
    * Loại mã độc liên quan
    * IP/Domain request đến
    * Các hành vi liên quan đến File, Registry Key, Process, Service, …
* Nếu sandbox verdicts báo malicious => File là mã độc.
* Nếu có hành vi tạo process, ghi registry, kết nối mạng đáng ngờ => Tăng khả năng là mã độc.

### Bước 5: Tổng hợp kết luận
* Tổng hợp các thông tin từ Bước 1-4 và đưa ra kết luận.
* BẮT BUỘC phải ghi rõ: **Đây là phần mềm gì** (nếu xác định được từ meaningful_name, names, signature_info), phục vụ mục đích gì.

---

## QUY TẮC TỔNG HỢP KẾT LUẬN
* Mỗi bước phải đánh giá ĐỘC LẬP dựa trên tiêu chí riêng của bước đó. KHÔNG được trộn dữ liệu/kết quả từ bước khác vào.
* Status cuối cùng:
    * **True Positive**: Ít nhất 1 bước kết luận Malicious dựa trên ĐÚNG tiêu chí (ví dụ: Bước 1 có >= 30 AV báo malicious, hoặc >= 5 AV + popular_threat_label rõ ràng).
    * **False Positive**: Tất cả các bước đều sạch (0 AV, signature hợp lệ, không có contacted/dropped malicious).
    * **Need Enrichment**: Chưa đủ cơ sở kết luận, cần kiểm tra thêm.

---

## YÊU CẦU ĐẦU RA
Bạn là chuyên gia SOC Analyst. Phân tích chi tiết từng bước theo Playbook dựa trên dữ liệu VirusTotal được cung cấp.

**Định dạng `Detailed_Analysis` (bắt buộc):** viết multi-line (mỗi ý xuống dòng `\n`), mỗi dòng dạng `- <Nhãn>: <giá trị>` (vd `- VT: 46/74 malicious`, `- Threat label: trojan.x`, `- First submission: 2021-...`, `- Signature: ...`); KHÔNG viết thành đoạn văn xuôi dài, KHÔNG để dòng header rỗng kiểu `- Evidence:`. Kết thúc mỗi step bằng dòng `- Kết luận step: <kết luận của bước>`.

BẮT BUỘC trả về kết quả JSON theo cấu trúc sau (không được bỏ qua bất kỳ bước nào):
{
  "Status": "True Positive" | "False Positive" | "Need Enrichment",
  "Confidence": <0-100>,
  "Software_Info": "Mô tả ngắn phần mềm: tên, hãng, mục đích (VD: 'PerfWatson2.exe - Microsoft Visual Studio Performance Watson, thu thập crash/telemetry data'). Ghi 'Unknown' nếu không xác định được.",
  "Audit_Report": {
      "Step_1": {
          "Step_Title": "Đánh giá thông tin chung",
          "Detailed_Analysis": "TRÍCH DẪN RÕ SỐ LIỆU: bao nhiêu AV báo malicious/tổng, vendor nào báo, threat label là gì. KHÔNG chung chung.",
          "Result": "malicious/clean/unknown/suspicious"
      },
      "Step_2": {
          "Step_Title": "Đánh giá thông tin Detail",
          "Detailed_Analysis": "First submission date, danh sách names, signature info. Trích dẫn cụ thể.",
          "Result": "malicious/clean/unknown/suspicious"
      },
      "Step_3": {
          "Step_Title": "Đánh giá thông tin Relations",
          "Detailed_Analysis": "Contacted URLs/IPs/Domains: bao nhiêu entry, bao nhiêu malicious. Dropped files: bao nhiêu, bao nhiêu malicious.",
          "Result": "malicious/clean/unknown/suspicious"
      },
      "Step_4": {
          "Step_Title": "Đánh giá thông tin Behavior",
          "Detailed_Analysis": "Sandbox name, verdicts, hành vi đáng ngờ. Ghi 'Unknown: Không có dữ liệu Behavior' nếu VT không có.",
          "Result": "malicious/clean/unknown/suspicious"
      },
      "Step_5": {
          "Step_Title": "Tổng hợp kết luận",
          "Detailed_Analysis": "Tổng hợp kết quả tất cả các bước, đưa ra kết luận cuối cùng.",
          "Result": "malicious/clean/unknown/suspicious"
      },
      "Summary": "Tổng kết ngắn gọn tại sao chọn Status này"
  }
}
