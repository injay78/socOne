# Prompt — Kiểm tra Hash trên VirusTotal

Phân tích hash theo TẤT CẢ các bước trong Playbook (Bước 1→5).

Hash: {{file_hash}}
Tên file (nếu có): {{file_name}}

Dữ liệu VirusTotal:
{{vt_json}}

YÊU CẦU:
- Đánh giá TỪNG BƯỚC (1→5) theo đúng Playbook.
- Trích dẫn số liệu cụ thể cho mỗi bước.
- Trường Software_Info: xác định từ meaningful_name, names, signature_info trong VT data. Ghi "Unknown" nếu không xác định được.
