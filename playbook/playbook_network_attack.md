# Playbook Phân tích Tấn công lớp Network

## Global Evidence Rules
1. Chỉ dùng evidence được cung cấp. Không tự bịa IP reputation, payload, scan count, SIEM, firewall, EDR.
2. Missing/unavailable/truncated data là `unknown`.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. `Close_Note` và `Escalate_Note` bắt buộc cho mọi verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.

**⛔⛔ GATE 0 — Public DNS resolver KHÔNG phải đích thật (đánh giá TRƯỚC mọi bước, VÔ HIỆU HÓA mọi lập luận benign phía sau):**
Khi `destination_port` = 53 (hoặc alert thuộc lớp C2/DNS — rule name chứa `C2`, `DNS`, `Malicious C2 Engine`, `ndr_msg` dạng `c2 hit: <domain>`) **VÀ** `destination_ip` là DNS resolver công cộng (1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 208.67.222.222, Cloudflare 173.245.x/198.41.x, hoặc resolver nội bộ của khách):
- **IP đích là hạ tầng phân giải tên, KHÔNG phải đối tượng cần chấm.** Reputation sạch của resolver là hiển nhiên và **KHÔNG phải bằng chứng quyết định**.
- ⛔ **CẤM tuyệt đối** lập luận "IP đích 1.1.1.1/8.8.8.8 sạch nên False Positive".
- **Đối tượng phải chấm là DOMAIN đã truy vấn** (`destination_domain`, `domain_resolved`, hoặc domain nhúng trong `ndr_msg`).
- **Thiếu domain → trần verdict là `Need Enrichment`** + `Enrichment_Requests` xin DNS/proxy log. **CẤM `False Positive`.**

7. Firewall/WAF/reverse proxy/NAT có thể là forwarder. Phải xác định client/source thực nếu verdict phụ thuộc source.
8. Blocked traffic vẫn có thể là TP attack attempt. Không dùng action block để FP.
9. Historical context chỉ là supporting context.
10. Không public tên công nghệ sinh nội dung, nhà cung cấp, nền tảng hoặc endpoint nội bộ trong kết quả.

---

## Định nghĩa trạng thái

| Trạng thái | Ý nghĩa |
|------------|---------|
| **True Positive** | Có evidence scan/exploit/lateral movement/network attack thật sự |
| **False Positive** | Traffic benign/authorized/health check/scanner approved và rule bắt nhầm |
| **Need Enrichment** | Thiếu source thực, payload, tần suất, process, owner hoặc authorization |

---

## Dữ liệu enrichment

| Trường JSON | Nội dung |
|-------------|----------|
| `alert_info` | rule_name, category, siem_type, alert_time |
| `alert_details` | source_ip, destination_ip, ip_observations, source_port, destination_port, protocol, service, payload, connection_count, hostname, user, process |
| `ip:{ip}` | Phân tích ĐẦY ĐỦ mỗi IP (verdict riêng `Status`/`Confidence`/`Audit_Report`) + `_source_evidence`: `virustotal` (malicious, country, as_owner), `abuseipdb` (abuse_confidence_score, total_reports), `ip2location` (country_code, isp, asn, is_proxy, proxy_type), `rdap` nếu có |
| `_historical_context` | Ticket cũ tham khảo |

---

## Hướng dẫn phân tích

### Bước 1: Xác định thông tin cảnh báo và attack surface
Trích xuất:
- Thời điểm, rule, description, log source.
- Source IP/host/user và destination IP/host/service/port/protocol.
- Nếu có `ip_observations`, dùng `role`/`source_field` để xác định source_ip, destination_ip, forwarded_client_ip, observed_source_ip hoặc NAT/proxy IP; không kết luận forwarder là attacker khi role/source chưa rõ.
- Loại tấn công: scan, SMB/RDP/SSH/WinRM/VPN brute, exploit, lateral movement, reconnaissance.
- Payload/pattern nếu có.
- Action allow/block/reset.
- Hoạt động phát sinh trên log gì và của thiết bị nào.

**Đánh giá Rule Intent Match:**
- **Rule bắt khi nào?** Phát hiện scan / exploit / lateral movement / brute / reconnaissance ở lớp network.
- **Tại sao alert này phát sinh?** Payload / port-sequence / protocol / tần suất / vai trò source-dest nào khớp signature rule.
- **Rule Intent Match:** scope khớp pattern tấn công (RDP scan→brute, SMB lateral) → MATCH; chỉ probe cổng generic / health-check → MISMATCH → nghiêng FP.
- **FP/TP scenario:** TP khi payload/lateral pattern rõ hoặc exploit success; FP khi tool/scanner approved có scope/window.
- **Dữ liệu đủ chưa?** Thiếu payload / tần suất / scope / source thật → Need Enrichment.

**Result:** `informational`

### Bước 2: Xác định source thực và source reputation
- Public IP: mỗi IP có verdict riêng ở `ip:{ip}` (`Status`/`Confidence`) — dùng làm điểm tựa. Đọc reputation (abuseipdb/ip2location) theo Shared Rule §"IP reputation reading (1b)".
- Private IP: xác định host/user/owner. Nếu private host scan/tấn công nhiều dịch vụ không có authorization -> nghi compromised.
- Firewall/WAF/Reverse Proxy/NAT: nếu source là forwarder, cần client IP thực; không kết luận forwarder là attacker nếu thiếu evidence. Nếu tất cả source IP đều phát sinh từ một IP nội bộ duy nhất, đó có thể là firewall/WAF/reverse proxy — cần log X-Forwarded-For/client IP thật nếu có.
- Security scanner/monitoring/asset discovery chỉ là FP khi có evidence approved scope/window/tool/owner rõ.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 3: Đánh giá hành vi, payload và tần suất
- Scan nhiều IP/port/service trong thời gian ngắn, ví dụ trên 30 event/5 phút cho network scan -> `suspicious` hoặc `malicious` tùy source.
- Gom nhóm theo IP đích và port đích để xác định tấn công một mục tiêu hay nhiều mục tiêu, một dịch vụ hay nhiều dịch vụ.
- Payload exploit/recon/credential attack rõ -> `malicious`.
- Inbound public scan tần suất lớn hoặc dai dẳng nhiều giờ -> `malicious`.
- Private source scan nội bộ, SMB/RDP/WinRM/SSH lateral pattern -> `malicious` nếu không có authorization.
- Health check, backup, monitoring, vulnerability scanner approved -> `clean`.
- Thiếu payload/count/scope -> `unknown` hoặc `Need Enrichment`.
- **⭐ HÀNH VI FLOW (gated theo data có sẵn):** nếu có `connection_count`+`time_window` → tính tần suất; kết nối NHỎ + ĐỀU theo chu kỳ tới cùng đích/port = nghi **C2 beaconing**. Nếu có `bytes_out` lớn (nhất là outbound tới public) = nghi **exfil**. THIẾU các field này → KHÔNG suy diễn, ghi missing evidence.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 4: Kiểm tra process/host nguồn nếu có
- Nếu source là endpoint/server nội bộ, tìm process quanh thời điểm scan.
- Attack tool, script, command line scan/brute/exploit, credential dump/lateral movement -> `malicious`.
- Tool cần cài đặt để sử dụng như scanner/admin tool chỉ FP khi xác minh được nghiệp vụ và scope.
- Process nghiệp vụ rõ, owner/maintenance/change rõ -> `clean`.
- **⭐ PROCESS KHÔNG HỢP LÝ MỞ KẾT NỐI:** nếu process khởi tạo kết nối KHÔNG có chức năng đó (vd web server `nginx`/`httpd`, DB `sqlservr` lại mở RDP/SMB/SSH ra ngoài) → tín hiệu mạnh host bị chiếm quyền (app compromise → lateral/C2); nâng `malicious`/`suspicious` dù IP đích chưa có reputation.
- Không có process trên source nội bộ khi hành vi suspicious -> `Need Enrichment`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 5: Kiểm tra tác động lên dịch vụ đích
- Xác định service bị nhắm: SMB, RDP, SSH, WinRM, SMTP, POP3, database, VPN, custom service.
- Nếu có login success, exploit success, file/process change, service crash, success response hoặc follow-on activity -> `malicious`.
- Nếu bị block/drop và chỉ là scan đơn lẻ từ IP sạch -> có thể `suspicious`/`clean` tùy rule intent.
- Không có response/status/tác động -> `unknown`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 6: Tổng hợp và kết luận
Kết luận `True Positive` khi:
- Public IP malicious/unknown thực hiện scan/exploit tần suất lớn/dai dẳng.
- Private source thực hiện scan/lateral movement/exploit không authorized.
- Payload attack rõ, login/exploit success, hoặc process attack tool.
- IP độc + behavior attack nhất quán.

Kết luận `False Positive` chỉ khi:
- Source/owner/tool approved rõ, scope/window hợp lệ.
- Payload/tần suất phù hợp health check/monitoring/scanner được phê duyệt.
- Không có payload/tác động malicious và rule intent mismatch.

Kết luận `Need Enrichment` khi:
- Chưa xác định client IP thực.
- Thiếu payload/tần suất/scope/source owner/process.
- Public IP suspicious tần suất nhỏ, không rõ attack hay benign probe.
- Private source suspicious cần EDR/process/owner confirmation.

`Enrichment_Requests` phải gồm: client IP thực, full event list +/-1h, group by destination/port, payload sample, allow/block status, EDR source process, owner/change/scan approval.

---

## Confidence guideline

| Confidence | Điều kiện |
|------------|-----------|
| 90-100 | Source thực, payload/tần suất, service/tác động rõ |
| 80-89 | Source và behavior rõ, thiếu một context phụ |
| 70-79 | < 80 → Need Enrichment (chưa đủ tin cho TP/FP) |
| 40-60 | Need Enrichment |

FP thiếu source thực/authorization → Need Enrichment (không đạt sàn 80). TP/FP chỉ hợp lệ khi Confidence >= 80; < 80 → Need Enrichment.
`Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

---

## Bổ sung discriminators TP/FP (category-specific)

Bổ sung cho các Bước ở trên (existence-gated: chỉ áp khi field/evidence có trong `alert_details`/`_source_evidence`; thiếu → ghi unavailable, không suy diễn; KHÔNG hardcode verdict).

- **(Bước 2) True-client-IP:** khi `ip_observations[].source_field` là header chuyển tiếp (XFF/X-Real-IP/CF-Connecting-IP) → chạy reputation trên client IP thật, không trên WAF/proxy/NAT.
- **(Bước 3) Port-sequence:** danh sách dst port tuần tự (22,23,24...) hoặc cụm dịch vụ (135/139/445/3389 trong ~5s) = recon/lateral; lặp một port = brute; chỉ khi có port list/timing.
- **(Bước 3) Exfil thresholds:** `bytes_out` > 500MB/1h HOẶC >10 kết nối tới cùng external dest/1h → exfil-support; đối chiếu approval/known-backup trước khi nghiêng TP.
- **(Bước 5) TCP/response-state:** handshake thành công + payload/credential attempt = exploitation thật (TP); refused/timeout/blocked = attempt bị chặn (TP confidence thấp hơn); chỉ khi có connection_state/tcp_flags/http_status/firewall_action.

### YÊU CẦU ĐẦU RA

BẮT BUỘC trả về JSON thuần:

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Xác định thông tin cảnh báo và attack surface", "Detailed_Analysis": "- Evidence: rule, source, destination, service, payload, action.\n- Rule intent: rule bắt scan/exploit/lateral movement hay network anomaly nào.\n- Kết luận step: attack surface chính và dữ liệu còn thiếu.", "Result": "informational"},
    "Step_2": {"Step_Title": "Xác định source thực và reputation", "Detailed_Analysis": "- Evidence: public/private, forwarder/NAT, scanner/owner, reputation.\n- Missing/Conflict: ghi rõ khi chưa xác định source thực hoặc provenance.\n- Kết luận step: source đáng ngờ, hợp lệ hay unknown. Bảng per-IP (từng IP + reputation) hiển thị tự động ở report — KHÔNG liệt kê từng IP trong text, chỉ nêu kết luận + số liệu tổng.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_3": {"Step_Title": "Đánh giá hành vi, payload và tần suất", "Detailed_Analysis": "- Evidence: scan/exploit/lateral movement, frequency, payload.\n- Missing/Conflict: ghi rõ khi thiếu payload, count hoặc time window.\n- Kết luận step: hành vi có đủ dấu hiệu tấn công không.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_4": {"Step_Title": "Kiểm tra process/host nguồn", "Detailed_Analysis": "- Evidence: EDR process, command line, tool, authorization.\n- Missing/Conflict: ghi rõ khi thiếu host/process context.\n- Kết luận step: source host có dấu hiệu công cụ/hành vi bất thường không.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_5": {"Step_Title": "Kiểm tra tác động lên dịch vụ đích", "Detailed_Analysis": "- Evidence: service, success/failure, response, follow-on activity.\n- Missing/Conflict: ghi rõ khi thiếu response hoặc impact telemetry.\n- Kết luận step: có tác động thành công hay chỉ là attempt.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_6": {"Step_Title": "Tổng hợp và kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các step quyết định TP/FP/NE.\n- Missing/Conflict: dữ liệu thiếu hoặc conflict còn ảnh hưởng confidence.\n- Kết luận step: lý do cuối cùng; historical context chỉ để tham khảo.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Tóm tắt lý do kết luận"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["TP/NE: chặn source, điều tra host nguồn/đích, query tần suất"],
  "Investigation_Requests": [{"intent": "Mục đích query", "why_raises_confidence": "đang X → lên Y nếu log cho thấy ...", "action": "search_network|search_process", "target_field": "source_ip|destination_ip|destination_port|bytes_out|tcp_flags|process_name", "target_value": "value từ alert", "time_range_hours": 1}],
  "Enrichment_Requests": ["NE HOẶC Confidence < 90: thứ KHÔNG query SIEM được (payload sample, owner/approval, dữ liệu ngoài); log SIEM đặt ở Investigation_Requests; [] chỉ khi Confidence >= 90 và không phải NE"],
  "Close_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Close_Note; không viết liền một dòng.",
  "Escalate_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Escalate_Note; không viết liền một dòng."
}
```
