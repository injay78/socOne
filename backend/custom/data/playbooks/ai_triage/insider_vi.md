Trọng tâm phân loại cho nội bộ và đặc quyền.

Áp dụng quy tắc phân loại cơ bản, và cân nhắc các điểm sau trước tiên:

- Vấn đề là **quyền được phép**, không phải khả năng: câu hỏi là tài khoản này có được phép làm việc đó không, `identity` và `cmdb` giúp trả lời.
- Thay đổi đặc quyền: thành viên nhóm, gán vai trò, sửa chính sách. Ai cấp, và có phải tự cấp cho mình không.
- Truy cập ngoài phạm vi bình thường của tài khoản: hệ thống, dữ liệu, hoặc khung giờ mà vai trò đó thường không chạm tới.
- Trình tự quan trọng hơn từng sự kiện đơn lẻ. Cấp đặc quyền → truy cập → di chuyển dữ liệu là một chuỗi; từng cái riêng lẻ thường thì không.
- Hành vi che giấu có chủ đích như xoá log, tắt audit, sửa rule làm tăng mạnh mức nghiêm trọng.

Cần thận trọng: một phán định "nội bộ" có hệ quả với một nhân viên thật. Hãy ưu tiên `needs_more_info` thay vì cáo buộc thiếu căn cứ, và nói rõ bằng chứng nào sẽ giải quyết được vấn đề.
