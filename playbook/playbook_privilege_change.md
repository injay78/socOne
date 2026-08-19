# Playbook Phân tích Thay đổi quyền hạn/cấu hình

## Global Evidence Rules
1. Chỉ dùng evidence được cung cấp. Không tự bịa actor, target, group, SID, source IP, remote log, change ticket.
2. Missing/unavailable/truncated data là `unknown`.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. `Close_Note` và `Escalate_Note` bắt buộc cho mọi verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.

7. Privilege/admin/security config change không được FP nếu thiếu actor/source/approval rõ.
8. Tên actor/host có `admin`, `svc`, `security`, `scanner` chỉ là weak context.
9. Historical context chỉ là supporting context.
10. Không public tên công nghệ sinh nội dung, nhà cung cấp, nền tảng hoặc endpoint nội bộ trong kết quả.

---

## Định nghĩa trạng thái

| Trạng thái | Ý nghĩa |
|------------|---------|
| **True Positive** | Unauthorized privilege/config change, account compromise, persistence, security weakening |
| **False Positive** | Approved admin/change activity có evidence rõ |
| **Need Enrichment** | Thiếu actor/source/target/approval/pre-change evidence |

---

## Dữ liệu enrichment

| Trường JSON | Nội dung |
|-------------|----------|
| `alert_info` | rule_name, category, siem_type, alert_time |
| `alert_details` | actor_user, target_user, action, group_name, source_ip, hostname, event_id, security_id, member, group, resource, old/new value |
| `_historical_context` | Ticket cũ tham khảo |

---

## Hướng dẫn phân tích

### Bước 1: Xác định change event
Trích xuất:
- Thời điểm, rule, event_id/action.
- Với EventID `4732` hoặc event tương đương: member được thêm vào security-enabled local group.
- Subject/actor: User thực hiện hành động, `Security ID`, `Account Name`, `Account Domain`.
- Member/target: `Security ID`, `Account Name`, distinguished name hoặc user/resource bị tác động.
- Group: `Security ID`, `Group Name`, `Group Domain`.
- Hành động: create user, add to admin group, reset password, change GPO, create rule, disable security, grant permission, config change.
- Rule intent và mức độ nhạy cảm.

**Đánh giá Rule Intent Match:**
- **Rule bắt khi nào?** Phát hiện thay đổi quyền/cấu hình nhạy cảm: tạo user, add admin group, reset password, đổi GPO/policy, disable security, cấp quyền.
- **Tại sao alert này phát sinh?** Actor / target / group / action nào khớp điều kiện rule.
- **Rule Intent Match:** actor đăng nhập từ nguồn lạ/compromise rồi nâng quyền → MATCH; thay đổi có change-request / maintenance / owner rõ → MISMATCH → nghiêng FP.
- **FP/TP scenario:** TP khi change + evidence compromise (pre/follow-on); FP khi đúng quy trình/approval.
- **Dữ liệu đủ chưa?** Thiếu actor/target/group/action detail hoặc approval/pre-post log → Need Enrichment.

**Result:** `informational`

### Bước 2: Kiểm tra actor và source đăng nhập
- Xác định actor login vào host/resource bằng cách nào: interactive, RDP, remote admin, service, PAM, automation.
- Kiểm tra remote thành công quanh thời điểm tác động: Windows EventID `4624`, Linux `Accepted`, PAM/remote logs nếu có.
- Source IP public/unknown/lạ -> `suspicious`; nếu IP malicious hoặc login suspicious -> `malicious`.
- Source private: xác minh đây là máy user/admin/PAM/app nào.
- Server-to-server remote admin, actor ít khi tác động trên host này -> `suspicious`.
- Actor privileged/admin tác động trong scope công việc + change ticket/maintenance rõ -> có thể `clean`.
- Actor là account máy `$`, service account, account lạ hoặc cloned SID -> `suspicious`.
- Actor first-login-to-target (chỉ khi có `siem_dispatcher` và `actor_user`+`hostname` trong alert_details; thiếu -> unavailable): emit query 4624 (target_field=user, correlate hostname) tìm login trước đó của actor tới host đích trong 90d — 0 login trước = strong TP; history khớp role baseline = nghiêng FP. Không có log trả về -> `unknown`, không suy diễn first-seen.

**⛔ Actor process (chỉ khi alert_details có `process_name`/`command_line`/`parent_process`):** một số nguồn (EDR/Sysmon) gắn tiến trình thực hiện thay đổi quyền/cấu hình. Khi có, đánh giá actor process để phân biệt FP vs escalate:
- Process là **công cụ quản trị hợp lệ đúng path/publisher** (vd `net.exe`/`net1.exe`, `dsa.msc`/MMC, `powershell` gọi cmdlet AD, `gpupdate`, `secedit` từ `C:\Windows\System32`; signer Microsoft) do actor admin chạy trong scope → weak-context nghiêng FP (KHÔNG tự kết FP nếu thiếu approval — vẫn theo rule 7/11).
- Process **lạ / sai path / script/interpreter** (`*.ps1` không ký, `cmd /c` chuỗi bất thường, binary trong `\Temp\`/`\Users\Public\`, LOLBin nạp từ URL ngoài) thực hiện thay đổi quyền → nghiêng escalate/`suspicious`.
- Có `hashes` mà **chưa có VT trong evidence** → KHÔNG suy diễn sạch/độc; nêu vào `Enrichment_Requests` (VT hash) — thiếu VT là missing evidence, không phải bằng chứng FP.
- Thiếu hoàn toàn field process → bỏ qua nhánh này (không suy diễn), đánh giá theo actor/source như trên.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 3: Kiểm tra target, group và action risk
- Thêm member vào Administrators/Domain Admins/privileged group -> high risk.
- Sensitive-group tier (chỉ khi `group_name`/`object_keys` có trong alert_details; thiếu -> ghi unavailable): target group khớp `knowledge/sensitive_groups.yaml`/`privilege_taxonomy.yaml` (Domain/Enterprise/Schema Admins, Backup Operators trên DC, DnsAdmins) = high TP risk; group ứng dụng/mail-only tự định nghĩa có owner rõ = nghiêng FP. Đây là tier của group ĐÍCH bị sửa, khác với privilege tier của actor.
- Disabled-account re-enable (chỉ khi `old_value`/`new_value` UserAccountControl có trong alert_details; thiếu -> unavailable): bitwise check ACCOUNTDISABLE (0x2) — set trong old và clear trong new = account bị bật lại; không có approval/ticket -> `suspicious`/TP-supporting. Parse deterministic, không suy diễn khi thiếu cờ.
- Tạo user mới, enable disabled account, reset admin password, add SSH key, create access token/key, change security policy -> `suspicious`/`malicious` nếu unauthorized.
- Disable logging/security control, open firewall, weaken password/MFA, create mail forwarding/transport rule -> `suspicious`/`malicious`.
- Target/user/group nằm trong change request và owner rõ -> có thể `clean`.
- Tên target lạ/nhạy cảm/gần giống machine account/user admin -> `suspicious`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 4: Kiểm tra SID, clone và pre-change/follow-on activity
- Search `Security ID` của Subject trên SIEM và group by agent/host để xác định có phải thiết bị/account bị clone hay dùng ở nhiều nơi bất thường.
- Trước change có brute force, public auth suspicious, process bất thường, network attack, malware, remote login lạ -> `malicious`.
- Sau change có login bằng account mới, privilege use, data access, policy/security tamper -> `malicious`.
- Không có pre/follow-on log -> `unknown`, không FP high confidence nếu action nhạy cảm.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 5: Kiểm tra approval và business context
- Change ticket, maintenance window, owner confirmation, deployment/automation record exact -> supporting `clean`.
- Approval chung chung không có ID/time/scope -> weak evidence.
- Không có approval cho admin/security change -> `Need Enrichment` hoặc `True Positive` nếu có evidence attack.

**Result:** `clean | suspicious | unknown`

### Bước 6: Tổng hợp và kết luận
Kết luận `True Positive` khi:
- Có evidence actor/source bị compromise hoặc unauthorized.
- Privilege/admin/security config change + pre/follow-on attack evidence.
- Source public/malicious đăng nhập thành công rồi thực hiện change.
- Thêm user/group/admin hoặc security weakening không có approval và có dấu hiệu bất thường.
- Post-change lateral/malware correlation (chỉ khi có post-change EDR/4688 evidence trong `_source_evidence`/`_sub_audit_reports`; thiếu -> unavailable): trong ~30 phút sau change, có lateral/malware tool khớp `knowledge/command_patterns.yaml` (wmic/psexec/mimikatz/reverse_shell) hoặc EDR credential-access/injection alert = active-compromise TP; chỉ có baseline benign (backup/sync) = ủng hộ FP. Không có log post-change -> `unknown`, không bịa follow-on.

Kết luận `False Positive` chỉ khi:
- Actor/source/target/action khớp change request/owner/maintenance.
- Không có pre/follow-on suspicious.
- Rule intent mismatch hoặc change đúng quy trình.

Kết luận `Need Enrichment` khi:
- Thiếu actor/source/target/group/action detail.
- Thiếu approval cho change nhạy cảm.
- Thiếu login/pre/follow-on logs.
- Có suspicious source/action nhưng chưa đủ TP.

`Enrichment_Requests` phải gồm: event detail full, 4624/remote login +/-24h, source owner, SID lookup, group membership before/after, change ticket/owner confirmation, pre/follow-on activity.

---

## Confidence guideline

| Confidence | Điều kiện |
|------------|-----------|
| 90-100 | Actor/source/action/target/approval/pre-follow-on rõ |
| 80-89 | Change context rõ, thiếu một context phụ |
| 70-79 | < 80 → Need Enrichment (chưa đủ tin cho TP/FP) |
| 40-60 | Need Enrichment |

FP cho admin/security change thiếu approval exact → Need Enrichment (không đạt sàn 80). TP/FP chỉ hợp lệ khi Confidence >= 80; < 80 → Need Enrichment.
`Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

---

### YÊU CẦU ĐẦU RA

BẮT BUỘC trả về JSON thuần:

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Xác định change event", "Detailed_Analysis": "- Evidence: actor, target, group/resource, action, event_id.\n- Rule intent: rule bắt privilege/config change nào và có khớp event không.\n- Kết luận step: change event chính và dữ liệu còn thiếu.", "Result": "informational"},
    "Step_2": {"Step_Title": "Kiểm tra actor và source đăng nhập", "Detailed_Analysis": "- Evidence: source IP/host, login method, actor baseline, remote/PAM/app context.\n- Missing/Conflict: ghi rõ khi thiếu login/source/baseline context.\n- Kết luận step: actor/source hợp lệ, suspicious hay unknown.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_3": {"Step_Title": "Kiểm tra target, group và action risk", "Detailed_Analysis": "- Evidence: admin group, user creation, reset, security weakening, target sensitivity.\n- Missing/Conflict: ghi rõ khi thiếu target sensitivity hoặc action detail.\n- Kết luận step: action có rủi ro privilege/security thế nào.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_4": {"Step_Title": "Kiểm tra SID, pre-change và follow-on activity", "Detailed_Analysis": "- Evidence: SID search, brute force, public auth, process, network, later privilege use.\n- Missing/Conflict: ghi rõ khi thiếu pre-change/follow-on telemetry.\n- Kết luận step: có chuỗi compromise liên quan hay không.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_5": {"Step_Title": "Kiểm tra approval và business context", "Detailed_Analysis": "- Evidence: change ticket, owner confirmation, maintenance, automation.\n- Missing/Conflict: ghi rõ khi không có approval/business proof.\n- Kết luận step: approval đủ hỗ trợ FP hay cần enrichment.", "Result": "clean|suspicious|unknown"},
    "Step_6": {"Step_Title": "Tổng hợp và kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các step quyết định TP/FP/NE.\n- Missing/Conflict: dữ liệu thiếu hoặc conflict còn ảnh hưởng confidence.\n- Kết luận step: lý do cuối cùng; historical context chỉ để tham khảo.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Tóm tắt lý do kết luận"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["TP/NE: revert/disable change, reset actor, collect logs, verify approval"],
  "Investigation_Requests": [{"intent": "Mục đích query", "why_raises_confidence": "đang X → lên Y nếu log cho thấy ...", "action": "search_auth|search_process", "target_field": "user|hostname|event_id|group_name|account_state|command_line", "target_value": "value từ alert", "time_range_hours": 24}],
  "Enrichment_Requests": ["NE HOẶC Confidence < 90: thứ KHÔNG query SIEM được (approval ticket, owner, dữ liệu ngoài); log SIEM đặt ở Investigation_Requests; [] chỉ khi Confidence >= 90 và không phải NE"],
  "Close_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Close_Note; không viết liền một dòng.",
  "Escalate_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Escalate_Note; không viết liền một dòng."
}
```
