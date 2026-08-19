# Playbook Phân tích Bruteforce tài khoản nội bộ

## Global Evidence Rules
1. Chỉ dùng evidence được cung cấp. Không tự bịa EventID, source host, password status, process, owner, business justification.
1b. **⛔ KHÔNG suy diễn quan hệ/số lượng:** Số lượng target account, danh sách account bị tấn công, mapping `source_ip`→host, hay role (admin/service account) PHẢI xuất hiện nguyên văn trong `alert_details`/`ip_observations`. Một giá trị (account, IP, host) CÓ trong raw KHÔNG có nghĩa được phép khẳng định chúng thuộc về nhau, đếm chúng, hay xếp chúng vào một danh sách. Nếu quan hệ/số đếm/role KHÔNG được nêu rõ → ghi `unknown`/Need Enrichment, không tự gán (vd: không viết "21 target accounts" nếu raw không nêu rõ đếm; không viết "IP X thuộc host Y" nếu mapping không có).
2. Missing/unavailable/truncated data là `unknown`.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. `Close_Note` và `Escalate_Note` bắt buộc cho mọi verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.

**⛔⛔ GATE 0 — Fail-only deterministic (đánh giá TRƯỚC mọi bước, KHÓA verdict, VÔ HIỆU HÓA lập luận "bruteforce rõ / rule khớp / nhiều lần fail → TP" phía sau):**
Áp khi `success_count`=0 (KHÔNG có 4624-success / `success_after_failure` trong `auth_events[]`) VÀ KHÔNG có source attack-process (Bước 5) VÀ KHÔNG có benign substatus (`0xC0000071/72/193/224/234`). Verdict quyết CHỈ theo class + reputation của source IP (sau khi có `ip:{source_ip}`):
- source IP **public VÀ malicious** (AbuseIPDB score cao + reports / VT nhiều vendor / threat-intel rõ) → **True Positive, Confidence 85** ("bruteforce từ nguồn độc, chưa thấy compromise").
- source IP **nội bộ RFC1918** (`10.`/`172.16-31.`/`192.168.`) **HOẶC public clean/unknown** → **Need Enrichment, Confidence 70** cố định + `Investigation_Requests` đòi source-host owner/process. ⛔ "23 lần login fail / rule intent khớp bruteforce / substatus bad-username-or-password (`0xC0000064`/`0xC000006A`/`0xC000006D`)" **KHÔNG phải lý do TP** khi source nội bộ/sạch — không phân biệt được bruteforce thật với cron/service dùng stale password. **failure_count (23, 38…) KHÔNG được nâng TP** — cùng cấu hình fail-only PHẢI cùng verdict.
- Chỉ lên `True Positive` khác khi có ≥1 corroboration: **success-after-failure** với timing, **source attack-process**, hoặc **follow-on bất thường**.
Đây là verdict CUỐI cho cấu hình fail-only; các bước dưới chỉ điền chi tiết, KHÔNG được lật lại verdict bằng "hành vi khớp bruteforce".

7. Expired/disabled/locked account chỉ được coi là FP khi exact error/substatus và timing có trong input.
8. Máy chủ/máy trạm xác thực sang máy chủ/máy trạm khác là suspicious nếu không có nghiệp vụ rõ.
9. Historical context chỉ là supporting context.
10. Không public tên công nghệ sinh nội dung, nhà cung cấp, nền tảng hoặc endpoint nội bộ trong kết quả.

---

## Định nghĩa trạng thái

| Trạng thái | Ý nghĩa |
|------------|---------|
| **True Positive** | Có evidence bruteforce/password spray/credential attack nội bộ hoặc compromised source |
| **False Positive** | Failed auth do expired password, password change, service misconfig hoặc nghiệp vụ rõ |
| **Need Enrichment** | Thiếu source host/user/service/error/process/timeline |

---

## Dữ liệu enrichment

| Trường JSON | Nội dung |
|-------------|----------|
| `alert_info` | rule_name, category, siem_type, alert_time |
| `alert_details` | source_ip, destination_ip/host, ip_observations, username, service, port, failure_count, success_count, event_id, sub_status, logon_type |
| `ip:{ip}` | Phân tích ĐẦY ĐỦ mỗi IP public (verdict riêng `Status`/`Confidence`/`Audit_Report`) + `_source_evidence`: `virustotal` (malicious, country, as_owner), `abuseipdb` (abuse_confidence_score, total_reports), `ip2location` (country_code, isp, asn, is_proxy, proxy_type), `rdap` nếu có |
| `_historical_context` | Ticket cũ tham khảo |

---

## Hướng dẫn phân tích

### Bước 1: Xác định thông tin hành vi bruteforce
Trích xuất:
- Thời điểm, rule, source IP/host/user, destination host/service/port.
- Nếu có `ip_observations`, dùng `role`/`source_field` để phân biệt source_ip, destination_ip, source_hostname và destination_host; không coi IP public/private là quyết định verdict nếu thiếu auth pattern.
- Account bị tấn công, failure count, success after failures, event IDs/substatus nếu có.
- **⛔ Đếm/mapping account↔IP↔host:** chỉ ghi ĐÚNG như `alert_details` nêu, không suy diễn quan hệ/số lượng/role (Rule 1b); chưa rõ → `unknown`.
- Service: AD, SQL, SSH, RDP, VPN, file share, mail, app.
- Rule intent có khớp brute/password spray không.

**Đánh giá Rule Intent Match:**
- **Rule bắt khi nào?** Phát hiện brute (1 account ↔ N password) / spray (1 password ↔ N account) / enumeration nội bộ.
- **Tại sao alert này phát sinh?** Failure count / target diversity / time window / error code nào khớp điều kiện rule.
- **Rule Intent Match:** chuỗi fail→success cùng user/IP, hoặc 1 IP → nhiều account → MATCH; fail do expired/disabled/locked (`0xC0000071/72/234`) → MISMATCH → nghiêng FP/noise.
- **FP/TP scenario:** TP khi brute/spray rõ + (process tấn công / source xấu / follow-on); FP khi error code giải thích + nghiệp vụ rõ.
- **Dữ liệu đủ chưa?** Thiếu success/fail breakdown / mapping source→target / substatus → Need Enrichment.

**Result:** `informational`

### Bước 2: Xác định source host và nghiệp vụ
- Source IP public: đọc reputation theo Shared Rule §"IP reputation reading (1b)" (verdict riêng ở `ip:{ip}`; abuse/VT malicious → source tấn công ngoài). IP private/nội bộ không có reputation public.
- Tìm source host/user qua EDR/SIEM/proxy/PAM nếu có trong input; tìm kiếm 3-7 ngày: xác thực thành công với source IP (EventID `4624`) và xác thực thất bại (EventID `4625`, `4776`) để xác định user/workstation.
- Source là NAC/monitoring/asset discovery/approved scanner có evidence rõ -> có thể `clean`.
- Source là web/app/PAM/database cần auth tới destination theo nghiệp vụ rõ -> có thể `clean` nếu failure explained.
- Source là workstation/server xác thực nhiều dịch vụ/nhiều account không rõ nghiệp vụ -> `suspicious`.
- Source là internal host xác thực admin/domain admin bất thường -> `suspicious` cao.

**Result:** `suspicious | clean | unknown`

### Bước 3: Kiểm tra account, service và error reason
- **⭐ Nếu có `auth_events` (chuỗi per-event):** TỰ tính từ chuỗi — spray (1 source_ip → nhiều `target_user`), enumeration (nhiều `0xC0000064`), fail-then-success cùng user/IP, nhịp độ tự động (timestamp đều/port tuần tự). Nếu CHỈ có `failure_count` gộp (không có chuỗi + không có mapping source→target nguyên văn) → KHÔNG khẳng định quan hệ; cap confidence + `Need Enrichment`.
- Expired password exact evidence: EventID `4625` substatus `0xC0000071`, EventID `4776` ErrorCode `0xC0000071`, hoặc EventID `535` -> supporting FP/user action.
- Disabled account exact evidence: `0xC0000072` -> supporting FP/noise nhưng vẫn cần scope.
- Expired account exact evidence: `0xC0000193` -> supporting FP/noise.
- Change Password at Next Logon exact evidence: `0xC0000224` -> supporting FP/noise.
- Account locked exact evidence: `0xC0000234` -> supporting FP/noise, cần xem nguyên nhân lock.
- Account admin/domain admin/`Admin Domain`/service account/first seen on source -> `suspicious`.
- Failure followed by success -> `suspicious`. **⛔ Riêng pattern "success after failure" KHÔNG đủ TP confidence cao** — chỉ nâng `malicious`/TP khi có corroboration (EDR/log chi tiết): process attack trên source (Bước 5), source host/IP reputation xấu, follow-on bất thường sau auth, hoặc context tấn công rõ; thiếu → hạ confidence hoặc `Need Enrichment`.
- Many users one password pattern -> password spray, `malicious`.
- One user many password attempts -> bruteforce, `suspicious`/`malicious`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 4: Kiểm tra password change/expired timeline
- Password changed/reset quanh thời điểm alert -> supporting FP nếu failures bắt đầu ngay sau đó và không có success suspicious.
- Expired trước alert -> supporting FP.
- Không có password timeline -> `unknown`.
- Password reset sau suspicious success có thể là attacker action nếu actor/source lạ -> `suspicious`.

**Result:** `suspicious | clean | unknown | informational`

### Bước 5: Kiểm tra process trên source và follow-on
- Process trên source thực hiện auth/scan/script/tool attack -> `malicious`.
- Không có process bất thường nhưng behavior server-to-server uncommon -> `Need Enrichment`.
- Sau auth có file/process/config/resource change bất thường -> `malicious`.
- Thiếu EDR/process/follow-on -> `unknown`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 6: Tổng hợp và kết luận

**⛔ Cấu hình fail-only (success_count=0, không benign substatus, không source attack-process): verdict ĐÃ KHÓA ở GATE 0** (public+độc→TP/85; nội bộ hoặc public-clean→NE/70; ≥1 corroboration→TP) — các nhánh dưới KHÔNG lật lại bằng "hành vi khớp bruteforce" hay failure_count.

Kết luận `True Positive` khi:
- Password spray/bruteforce rõ, especially success after failures.
- Source host có process/tool tấn công.
- Admin/domain admin bị xác thực sai liên tục từ source lạ.
- Server/workstation auth sang server/workstation rồi có follow-on suspicious.

Kết luận `False Positive` chỉ khi:
- Exact expired/disabled/locked/password change evidence giải thích failures.
- Source/service/owner/nghiệp vụ rõ và không có success/follow-on suspicious.
- Approved scanner/monitoring có scope/window rõ.

Kết luận `Need Enrichment` khi:
- Thiếu source host owner, service, event/substatus, success/fail breakdown, password timeline, process.
- Behavior suspicious nhưng chưa đủ evidence TP/FP.
- Admin account/service account liên quan nhưng thiếu follow-on/process.

`Enrichment_Requests` phải gồm: logs 4624/4625/4776 +/-24h, group by event_id/user/source/destination, password change/reset/expired logs, source EDR process, owner/service mapping, success after failure.

---

## Confidence guideline

| Confidence | Điều kiện |
|------------|-----------|
| 90-100 | Source/account/service/error/process/follow-on rõ |
| 80-89 | Đủ auth timeline và source owner, thiếu một context phụ |
| 70-79 | < 80 → Need Enrichment (chưa đủ tin cho TP/FP) |
| 40-60 | Need Enrichment |

FP thiếu exact substatus/password timeline/owner → Need Enrichment (không đạt sàn 80 — Shared Rule §"Verdict floor").
`Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

---

### YÊU CẦU ĐẦU RA

## Bổ sung discriminators TP/FP (category-specific)

Bổ sung cho các Bước ở trên (existence-gated: chỉ áp khi field/evidence có trong `alert_details`/`_source_evidence`; thiếu → ghi unavailable, không suy diễn; KHÔNG hardcode verdict).

- **(Bước 3) Success-after-failure timing:** `success_after_failure`=true + khoảng cách hợp lý sau loạt fail (theo `auth_events` timing) = credential compromise TP; thiếu timing → ghi unavailable.
- **(Bước 3) Service-account source-process:** `service`/`source_process` là app-to-app hợp lệ (khớp baseline) = FP; service account fail từ process/host bất thường = TP-support.
- **(Bước 4) Password-reset actor:** EID 4724/4738 — self/admin hợp lệ vs unknown/SYSTEM/actor lạ reset = nghi chiếm tài khoản.
- **(Bước 5) Post-success persistence:** sau success, `action_events` khớp pattern persistence/tooling (command_patterns/tool_taxonomy) = TP mạnh.
- **(Bước 5) Lateral-movement chain:** source→dest 4624 success rồi tới host thứ 3 trong ~6h → bổ sung top-level `Investigation_Requests` (target_field hợp lệ) xác nhận lateral.

BẮT BUỘC trả về JSON thuần:

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Xác định thông tin hành vi bruteforce", "Detailed_Analysis": "- Evidence: source, destination, user, service, failure/success, event/substatus.\n- Rule intent: rule bắt brute/spray/login anomaly nào và có khớp không.\n- Kết luận step: hành vi chính và dữ liệu còn thiếu.", "Result": "informational"},
    "Step_2": {"Step_Title": "Xác định source host và nghiệp vụ", "Detailed_Analysis": "- Evidence: source owner, scanner/monitoring/app/service context.\n- Missing/Conflict: ghi rõ khi chưa biết owner hoặc source role.\n- Kết luận step: source hợp lệ, suspicious hay unknown.", "Result": "suspicious|clean|unknown"},
    "Step_3": {"Step_Title": "Kiểm tra account, service và error reason", "Detailed_Analysis": "- Evidence: admin/service account, expired/disabled/locked, failure pattern.\n- Missing/Conflict: ghi rõ khi thiếu error/substatus hoặc account baseline.\n- Kết luận step: brute/spray pattern có được hỗ trợ không.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_4": {"Step_Title": "Kiểm tra password timeline", "Detailed_Analysis": "- Evidence: password change/reset/expired quanh thời điểm alert.\n- Missing/Conflict: ghi rõ khi timeline không khả dụng.\n- Kết luận step: password context giải thích hay làm tăng nghi ngờ.", "Result": "suspicious|clean|unknown|informational"},
    "Step_5": {"Step_Title": "Kiểm tra process trên source và follow-on", "Detailed_Analysis": "- Evidence: EDR process, tools, later changes after auth.\n- Missing/Conflict: ghi rõ khi thiếu process/follow-on telemetry.\n- Kết luận step: có dấu hiệu compromise sau auth hay không.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_6": {"Step_Title": "Tổng hợp và kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các step quyết định TP/FP/NE.\n- Missing/Conflict: dữ liệu còn thiếu có thể đổi verdict/confidence.\n- Kết luận step: lý do cuối cùng; historical context chỉ để tham khảo.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Tóm tắt lý do kết luận"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["TP/NE: lock/reset account, điều tra source, query auth/follow-on logs nếu cần"],
  "Investigation_Requests": [{"intent": "Mục đích query", "why_raises_confidence": "đang X → lên Y nếu log cho thấy ...", "action": "search_auth|search_process", "target_field": "user|source_ip|event_id|error_code|sub_status|process_name", "target_value": "value từ alert", "time_range_hours": 1}],
  "Enrichment_Requests": ["NE HOẶC Confidence < 90: thứ KHÔNG query SIEM được (source owner, dữ liệu ngoài); log SIEM đặt ở Investigation_Requests; [] chỉ khi Confidence >= 90 và không phải NE"],
  "Close_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Close_Note; không viết liền một dòng.",
  "Escalate_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Escalate_Note; không viết liền một dòng."
}
```
