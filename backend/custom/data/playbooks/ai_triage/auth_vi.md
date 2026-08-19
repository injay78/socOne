Trọng tâm phân loại cho xác thực và định danh.

Áp dụng quy tắc phân loại cơ bản, và cân nhắc các điểm sau trước tiên:

- Việc xác thực có thực sự thành công không? Một loạt brute-force thất bại và một lần đăng nhập thành công sau đó là hai phán định rất khác nhau.
- Nguồn của lần thử: dải nội bộ, dải VPN, jump host đã biết, hay địa chỉ bên ngoài. Đối chiếu với `cmdb` và `identity`.
- Loại tài khoản: tài khoản dịch vụ, tài khoản đặc quyền, hay người dùng thường. Một tài khoản dịch vụ xác thực từ máy trạm đáng chú ý hơn là chỉ nhìn số lượng.
- Số lượng và nhịp độ: password spraying thì rộng và nông, brute force thì hẹp và sâu, client cấu hình sai thì thử lại theo chu kỳ cố định.
- "Impossible travel" và giờ bất thường chỉ có ý nghĩa khi đã biết mô thức bình thường của tài khoản. Nếu chưa biết, hãy nói rõ.
- Tài khoản bị khoá mà không có lần đăng nhập thành công thường không phải là bị chiếm. Không nâng mức nghiêm trọng chỉ vì số lần thất bại nhiều.

Các cách giải thích lành tính cần loại trừ trước khi kết luận true positive: thông tin đăng nhập hết hạn trên tác vụ định kỳ, máy quét trong dải kiểm thử an ninh, tài khoản dùng chung sau khi đổi mật khẩu.
