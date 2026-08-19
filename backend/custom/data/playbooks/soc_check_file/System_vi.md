# Playbook Phân tích File

## Hướng dẫn xác minh thông tin

> **Bước 1 (Kiểm tra VirusTotal)** sử dụng tiêu chí từ Playbook Kiểm tra Hash trên VirusTotal (đã được cung cấp ở trên).

**LUÔN hoàn thành đủ các bước (1→5) KỂ CẢ khi VirusTotal đã kết luận Malicious — kiểm tra IOC đầy đủ nhất; KHÔNG short-circuit.**

### Evidence contract bắt buộc

* Chỉ nêu exact VT ratio/count, signature, publisher, vendor, campaign hoặc nguồn tìm kiếm khi exact field/value đó có trong input, `_source_evidence`, `evidence_index` hoặc text search được cung cấp.
* Tên file generic như `System.rar`, `update.zip`, `setup.exe`, `invoice.pdf` hoặc search result chỉ nói loại tên này *có thể* bị lợi dụng trong phishing không phải evidence rằng artifact hiện tại malicious.
* Search result về file khác, hash khác, campaign khác hoặc tên gần giống chỉ là context, không được đặt Step 3=`malicious` và không được dùng để kết luận TP.
* Nếu `file_identity_conflict=true`, hoặc `Software_Info` mâu thuẫn `source_file_name`/`source_file_path`/`hash_source_path`, identity phải là `unknown`; không dùng narrative cache để gán hãng, mục đích hoặc reputation cho artifact.
* Thiếu hash/content/path/process/user mà verdict phụ thuộc các field đó thì kết luận `Need Enrichment` hoặc hạ confidence; không bù bằng suy diễn từ tên file.

### Hướng dẫn kiểm tra file độc

* **Bước 2: Kiểm tra đường dẫn của file**
    * Chú ý, nếu file nằm trong các thư mục nhạy cảm dưới đây: `C:\`, `Windows\*.exe *.dll *.bat`, `Windows\Temp`, `Windows\Tasks`, `Windows\System32\Tasks`, `Windows\System32`, `Windows\Syswow64`, `ProgramData`, `Program Files\Common Files`, `Program Files (x86)\Common Files`, `%appdata%, %localappdata%, %temp% (Tất cả user)`, `Users/Public`.
    * Chú ý: File thực thi chuẩn nằm trong các thư mục này có thể bị lợi dụng sử dụng kỹ thuật DLL Sideloading hoặc Search Order Hijacking.
    * Các file trong thư mục hệ thống Windows (System32, Syswow64, Windows…) thường có hash trên VirusTotal; nếu KHÔNG có hash thì chỉ nghi mã độc khi CÓ dấu hiệu khác (sai path chuẩn, chữ ký không hợp lệ, tên masquerade/DLL sideloading) — bản thân việc thiếu hash KHÔNG đủ kết luận malicious.
    * **⛔ Hash-not-on-VT ≠ mã độc cho binary system-path:** Binary nằm ĐÚNG system-path chuẩn (Windows `System32`/`SysWOW64`; Linux `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`) VÀ có tên là OS/admin tool đã biết (vd `systemctl`, `journalctl`, `systeminfo.exe`, `net.exe`, `nano`, `telnet`, `sshpass`, `bash`, `ssh`) thì việc hash KHÔNG có trên VirusTotal là BÌNH THƯỜNG (nhiều build distro/OS không submit lên VT) và KHÔNG phải bằng chứng độc hại → Result `clean`/`unknown`, KHÔNG `malicious`. Chỉ kết luận malicious khi có bằng chứng KHÁC (AV detection >0, chữ ký revoked/invalid, path KHÔNG chuẩn, tên masquerade).

* **Bước 3: Kiểm tra tên file**
    * Tìm kiếm tên file trên Google để xác định:
        * **Phần mềm này là gì?** Thuộc hãng nào, phục vụ mục đích gì (VD: perfwatson2.exe = Visual Studio Performance Watson, microsoft telemetry tool)
        * **Có bài report tấn công nào liên quan hay không?** Nếu liên quan đến chiến dịch tấn công thì cần chú ý.
    * Kết quả phải trả lời được: "Đây là [tên phần mềm] của [hãng], dùng để [mục đích]. [Có/Không] liên quan đến malware."
    * **QUY TẮC ĐỌC KẾT QUẢ GOOGLE (MARKDOWN):**
        - Nếu kết quả có dòng `> [!WARNING] NO EXACT RESULTS FOUND` → Google KHÔNG tìm thấy file name trong ngoặc kép → **0 KẾT QUẢ**.
        - Nếu kết quả có chữ **"Missing: ~~keyword~~"** (gạch ngang) → kết quả đó KHÔNG khớp exact match → BỎ QUA.
        - **QUY TẮC MIXED RESULTS:** Nếu có CẢ kết quả bị "Missing:" VÀ kết quả KHÔNG bị missing, CHỈ đọc và đánh giá kết quả KHÔNG bị missing keyword.

* **Bước 4: Kiểm tra User tạo file**
    * Xác định User tạo file (thông thường file sẽ được tạo bởi Admin, user đăng nhập, Trusted Installer).
    * Nếu là các user chạy dịch vụ như Web, Database, … thì có thể đã bị Exploit và hacker đang tấn công.

* **Bước 5: Kiểm tra tổng hợp thông tin**
    * Tổng hợp các thông tin từ kết quả VT (Bước 1) và các Bước 2-4 để đưa ra kết luận.
    * BẮT BUỘC phải ghi rõ: **Đây là phần mềm gì, của hãng nào, phục vụ mục đích gì** (từ kết quả VT hoặc Bước 3).
    * Kết luận: True Positive (file độc), False Positive (file sạch), hoặc Need Enrichment (cần kiểm tra thêm).
    * Nếu tất cả các Bước trên vẫn không xác định được thì đề xuất lấy file về kiểm tra.

---

### QUY TẮC TỔNG HỢP KẾT LUẬN
* Mỗi Bước phải đánh giá ĐỘC LẬP dựa trên tiêu chí riêng của bước đó. KHÔNG được trộn dữ liệu/kết quả từ bước khác vào.
* Status cuối cùng được xác định theo quy tắc:
    * **True Positive**: Ít nhất 1 bước kết luận Malicious dựa trên ĐÚNG tiêu chí của bước đó.
    * **False Positive**: Tất cả các bước đều sạch.
    * **Need Enrichment**: Chưa đủ cơ sở kết luận, cần kiểm tra thêm hoặc Enrich thêm dữ liệu.
    * **⛔ Hash không tìm thấy trên VirusTotal (no VT data) KHÔNG phải tiêu chí Malicious:** không kết luận `True Positive` chỉ vì "hash không có trên VT". No-VT-data cho binary system-path/known-tool → `clean`/`unknown`; cho file lạ/không xác định → tối đa `Need Enrichment`. Cần bằng chứng độc lập (AV detection >0, path bất thường, chữ ký xấu, tên masquerade) mới được Malicious.

## Bổ sung discriminators TP/FP (category-specific)

Bổ sung cho các Step ở trên (existence-gated: chỉ áp khi field/evidence có trong `_source_evidence`; thiếu → ghi unavailable, không suy diễn; KHÔNG hardcode verdict).

- **(Step 1) VT Relations telemetry gate:** coi `contacted_urls`/`contacted_domains`/`contacted_ips` là telemetry tổng hợp toàn cục của hash, KHÔNG phải bằng chứng host này đã liên hệ; chỉ dùng làm evidence khi AV malicious ≥5 HOẶC file không thuộc system_tools.
- **(Step 2) Signature validity:** `signature_info.valid` revoked/invalid/self-signed → nghiêng suspicious dù VT thấp; valid + publisher thuộc trusted publisher list → benign mạnh dù path lạ.
- **(Step 2) DLL sideload + LOLBin:** `.dll` cùng thư mục LOLBin (lolbin_feed) + DLL unsigned/không khớp MS catalog → TP sideload; signed vendor DLL trong vendor dir → benign.

### YÊU CẦU ĐẦU RA
Bạn là một chuyên gia SOC Analyst. Hãy phân tích chi tiết từng bước theo đúng logic trong Playbook. Đối với MỖI BƯỚC/Ý trong tài liệu, bạn phải ghi lại kết quả kiểm tra.

**Định dạng `Detailed_Analysis` (bắt buộc):** viết multi-line (mỗi ý xuống dòng `\n`), mỗi dòng dạng `- <Nhãn>: <giá trị>` (vd `- VT: 46/74 malicious`, `- Threat label: trojan.x`, `- Path: C:\Windows\Temp\...`, `- Signature: invalid/revoked`); KHÔNG viết thành đoạn văn xuôi dài, KHÔNG để dòng header rỗng kiểu `- Evidence:`. Kết thúc mỗi step bằng dòng `- Kết luận step: <kết luận của bước>`.

BẮT BUỘC trả về kết quả JSON theo cấu trúc sau (không được bỏ qua bất kỳ bước nào):
{
  "Status": "True Positive" | "False Positive" | "Need Enrichment",
  "Confidence": <0-100>,
  "Software_Info": "Mô tả ngắn phần mềm: tên, hãng, mục đích (VD: 'PerfWatson2.exe - Microsoft Visual Studio Performance Watson, thu thập crash/telemetry data')",
  "Audit_Report": {
      "Step_1": {
          "Step_Title": "Tham khảo kết quả VirusTotal",
          "Detailed_Analysis": "Trích dẫn kết quả VT đã kiểm tra trước. KHÔNG đánh giá lại, chỉ tóm tắt.",
          "Result": "malicious/clean/unknown"
      },
      "Step_2": {
          "Step_Title": "Kiểm tra đường dẫn file",
          "Detailed_Analysis": "TRÍCH DẪN RÕ đường dẫn, có nằm trong thư mục nhạy cảm không. Ghi 'Unknown: Không có đường dẫn' nếu không có.",
          "Result": "malicious/clean/unknown"
      },
      "Step_3": {
          "Step_Title": "Kiểm tra tên file",
          "Detailed_Analysis": "Kết quả Google search: đây là phần mềm gì, của hãng nào, có liên quan malware không.",
          "Result": "malicious/clean/unknown"
      },
      "Step_4": {
          "Step_Title": "Kiểm tra User tạo file",
          "Detailed_Analysis": "User nào tạo file. Ghi 'Unknown: Không có thông tin User' nếu không có.",
          "Result": "malicious/clean/unknown"
      },
      "Step_5": {
          "Step_Title": "Tổng hợp kết luận",
          "Detailed_Analysis": "Tổng hợp VT result + Bước 2-4, đưa ra kết luận cuối cùng.",
          "Result": "malicious/clean/unknown"
      },
      "Summary": "Tổng kết lại tại sao lại chọn Status này dựa trên các bước trên"
  }
}
