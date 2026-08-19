# Prompt — Phân Tích Domain

Hãy phân tích domain sau theo TẤT CẢ các bước trong Playbook.

Domain cần kiểm tra: {{domain}}

Dữ liệu VirusTotal:
{{vt_json}}

Dữ liệu truy cập domain:
{{probe_json}}

{{page_components_section}}
{{chain_domains_section}}
{{google_text_section}}
{{image_section}}

GOOGLE EXACT DOMAIN RULES:
- Đọc `Google search: exact` trước phần threat search và screenshot.
- Nếu exact search không xác nhận đúng domain đang kiểm tra, hoặc kết quả chủ yếu là domain cùng brand nhưng khác TLD/registrable domain, coi đây là suspicious/lookalike evidence; không được coi domain đang kiểm tra là Clean.
- Không dùng domain/brand hợp lệ khác để hợp thức hóa observed domain.
- `creation date` là trường `virustotal.info.creation_date`. Nếu suspicious/lookalike evidence đi kèm `virustotal.info.creation_date` trong vòng 30 ngày gần nhất, coi là Malicious evidence.
- Nếu suspicious/lookalike evidence đi kèm login/credential behavior hoặc tín hiệu M365 suspicious/removal, coi là Malicious evidence hỗ trợ TP.
- Nếu chỉ có mismatch nhưng thiếu page behavior/ownership proof, dùng Unknown/Need Enrichment thay vì False Positive.

YÊU CẦU:
- Phân tích TỪNG BƯỚC (1→5) theo đúng Playbook. Mỗi bước đánh giá ĐỘC LẬP.
- Bước 2: CHỈ phân tích tên domain '{{domain}}', KHÔNG dùng dữ liệu VT.
- Bước 3: Đọc text kết hợp screenshot Google — chú ý phân biệt NGUỒN PHÁT TÁN vs chỉ được NHẮC ĐẾN.
- Status cuối cùng theo QUY TẮC TỔNG HỢP trong Playbook.
- Với mỗi bước, trích dẫn dữ liệu cụ thể để chứng minh.
