# Playbook Phân tích Cảnh báo MultiCloud

## Global Evidence Rules
1. Chỉ dùng evidence được cung cấp. Không tự bịa cloud provider, API action, source IP, IAM policy, resource, owner, baseline, approval.
2. Missing/unavailable/truncated data là `unknown`.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. `Close_Note` và `Escalate_Note` bắt buộc cho mọi verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.

**⛔⛔ GATE 0 — High-risk single-event deterministic (đánh giá TRƯỚC mọi bước, KHÓA verdict, VÔ HIỆU HÓA lập luận "high-risk / privileged / lịch-sử-TP → TP" phía sau):**

**⛔ GATE 0-EXCEPTION (kiểm TRƯỚC nhánh khoá NE/70 dưới đây — khớp thì GATE 0 KHÔNG áp):** nếu actor/identity là **IaC/service-managed** đã định danh HẸP — `user_agent` là công cụ IaC (`cloudformation.amazonaws.com`, `*Terraform*`, `*Pulumi*`, `packer-plugin-*`) hoặc SSO/service UA chính chủ (`sso.amazonaws.com`), VÀ actor là role tự-quản/CI (`AWSServiceRoleFor*`, `AWSReservedSSO_*`, OIDC/CI `gh-oidc-*`/`*-provision`), VÀ resource nằm trong naming scope của role — thì pipeline IaC/service CHÍNH LÀ cơ chế approval (code-review/merge; provider tự vận hành): GATE 0 **KHÔNG khoá NE/70**, đi thẳng Bước 2/Bước 5 để kết luận `False Positive` 85-90 (chi tiết ở Bước 2 §Service-managed/IaC identity + Bước 5 §NGOẠI LỆ approval). Chuỗi cấu trúc (user_agent IaC + role tự-quản/CI + resource đúng scope) CHÍNH LÀ bằng chứng quyết định; thiếu approval-ticket/baseline là XÁC NHẬN THIẾU (loại identity này không có ticket), KHÔNG phải bước then chốt. ⛔ Chỉ HUỶ ngoại lệ (quay về đánh giá bình thường) khi có tín hiệu mâu thuẫn: `ip:{source_ip}` malicious/suspicious, resource NGOÀI naming scope của role, hoặc chuỗi `api_calls[]` leo thang / actor sign-in nghi / follow-on lạ. Thiếu chứng cứ IaC khớp HẸP → KHÔNG áp ngoại lệ, theo nhánh GATE 0 bình thường.

Áp khi high-risk action (IAM `CreateRole`/`CreateAccessKey`/…; bulk `GetObject`) là **event đơn lẻ** (KHÔNG có chuỗi `api_calls[]` leo thang) VÀ `ip:{source_ip}` clean/unknown VÀ KHÔNG có approval/baseline provenance VÀ KHÔNG có compromise-signal (actor sign-in nghi ở Bước 2, follow-on lạ ở Bước 4) → **Need Enrichment, Confidence 70** cố định.
⛔ TUYỆT ĐỐI KHÔNG lấy các thứ sau làm lý do `True Positive` cho cấu hình này:
- (a) "action high-risk + thiếu approval" — chỉ đạt NE, KHÔNG phải TP (cần thêm compromise/escalation/bad-IP);
- (b) `context_tags.principal`=privileged / actor gắn tag privileged — chỉ risk-multiplier, KHÔNG thay bằng chứng compromise;
- (c) `historical_context` "cùng actor/IP trước đó đã TP" — verdict cũ là kết luận cũ trên cùng hành vi, KHÔNG phải bằng chứng độc lập (cấm câu "lịch sử đã TP nên TP");
- (d) `event_count`/`object_keys` thô (103 vs 348) khi KHÔNG có baseline median có provenance.
Cùng cloud event (trùng `actor`+`event.action`+`resource_id`+timestamp) qua nhiều rule PHẢI cùng verdict. Chỉ TP khi: source IP xấu, chuỗi `api_calls[]` escalation, actor-compromise, count vượt baseline có provenance, hoặc `object_keys` chạm dữ liệu nhạy cảm định danh được.

7. Cloud IAM/security/network/storage change không được FP nếu thiếu actor/source/approval/baseline rõ.
8. IP sạch/corporate chỉ là supporting context, không tự động FP nếu action high risk.
9. Historical context chỉ là supporting context; không claim baseline/ticket cleanup/CI-CD history nếu không có `_historical_context` hoặc SIEM evidence cụ thể.
10. Không claim VT/Google/Cisco/ASN/source ownership cho source IP nếu không có factual field trực tiếp như `malicious_count`, `as_owner`, `source_asn`, `source_country`, hoặc search text cụ thể.
10a. Source IP thuộc cloud/vendor lớn (Microsoft/Azure/GitHub/AWS/Google) chỉ được nói khi exact owner/ASN field có trong evidence. Nếu chỉ suy ra từ IP range hoặc kiến thức ngoài context, ghi `source owner unknown`.
10b. Không ghi "VT ghi nhận N malicious", "IP sạch", "Microsoft Corp", "GitHub Actions runner", hoặc thông tin reputation trong `Close_Note`/`Escalate_Note` nếu factual IP reputation/source-owner evidence không có trong payload.
10c. Với S3/API aggregate alert, nếu `alert_details.event_count`, `alert_details.object_keys`, `alert_details.object_key_sample`, raw `count`, hoặc raw `key` có trong payload thì PHẢI dùng các field này trong Step 1/3/6. Không được viết "single event", "thiếu số lượng object", hoặc request enrichment để lấy lại danh sách object khi các field này đã có. Baseline 7-30 ngày, approval/ticket, owner và action timeline vẫn là enrichment hợp lệ.
11. Không public tên công nghệ sinh nội dung, nhà cung cấp, nền tảng hoặc endpoint nội bộ trong kết quả.

---

## Định nghĩa trạng thái

| Trạng thái | Ý nghĩa |
|------------|---------|
| **True Positive** | Có evidence compromised identity, malicious source IP, unauthorized IAM/security/resource change |
| **False Positive** | Approved cloud operation có actor/source/resource/change evidence rõ |
| **Need Enrichment** | Thiếu actor/source/action/resource/baseline/approval |

---

## Dữ liệu enrichment

| Trường JSON | Nội dung |
|-------------|----------|
| `alert_info` | rule_name, category, siem_type, alert_time |
| `alert_details` | cloud_provider, account/subscription/project, actor, source_ip, ip_observations, api_call/event.action, resource_id, region, result, old/new values, event_count/object_keys/object_key_sample nếu raw alert có aggregate S3 objects |
| `ip:{ip}` | Phân tích ĐẦY ĐỦ mỗi IP (verdict riêng `Status`/`Confidence`/`Audit_Report`) + `_source_evidence`: `virustotal` (malicious, country, as_owner), `abuseipdb` (abuse_confidence_score, total_reports), `ip2location` (country_code, isp, asn, is_proxy, proxy_type), `rdap` nếu có |
| `_historical_context` | Ticket cũ tham khảo |

---

## Hướng dẫn phân tích

### Bước 1: Xác định cloud event
Trích xuất:
- Thời điểm, provider/account/project/subscription.
- Actor/principal/user/email/role/service account.
- Nếu có `ip_observations`, dùng `role`/`source_field` để phân biệt source_ip, actor_ip, NAT IP hoặc IP quan sát được từ cloud log; không tự suy diễn IP actor nếu input chỉ có IP public.
- Source IP/country/ASN, user agent nếu có.
- API action/event.action, result success/failure.
- Resource bị tác động: IAM, EC2/compute, VPC/network, Bucket/storage, RDS/database, security, logging.
- Với S3 `GetObject`/storage download: nêu rõ `event_count` và tối đa 10 `object_key_sample` nếu có (evidence đã có — Rule 10c).
- Rule intent và mức độ risk.

**Đánh giá Rule Intent Match:**
- **Rule bắt khi nào?** Phát hiện compromise/lateral cloud: IAM escalation, tạo key/resource persistence, storage exposure/exfil, disable logging.
- **Tại sao alert này phát sinh?** API action / actor / source IP / result / resource nào khớp điều kiện rule.
- **Rule Intent Match:** actor sign-in suspicious + chuỗi IAM/exfil → MATCH; deployment/CI-CD có approval, hoặc API fail (AccessDenied) → MISMATCH → nghiêng FP/test.
- **FP/TP scenario:** TP khi high-risk action success + actor/source nghi + follow-on; FP khi khớp approved change/baseline.
- **Dữ liệu đủ chưa?** Thiếu actor/source/result/approval/baseline → Need Enrichment.

**Result:** `informational`

### Bước 2: Kiểm tra actor và source IP
- Source IP malicious/VPN/proxy/country lạ/first seen -> `suspicious` hoặc `malicious` nếu action high risk success.
- Mỗi IP có verdict riêng ở `ip:{ip}` (`Status`/`Confidence`) — dùng làm điểm tựa; số liệu thô ở `ip:{ip}._source_evidence`.
- IP reputation (`ip:{ip}._source_evidence` abuseipdb/ip2location): đọc theo Shared Rule §"IP reputation reading (1b)". Với cloud: `source_ip` sạch chỉ là supporting, không tự FP nếu action high-risk (GATE 0).
- Actor bị sign-in suspicious, brute force, impossible travel, token/key first use -> `suspicious`.
- Actor/service account automation expected + source corporate/known CI/CD + approval rõ -> có thể `clean`.
- **⭐ Service-managed role tự quản (HẸP):** actor là service-linked role của chính cloud provider (vd `AWSServiceRoleFor*`) + `user_agent` là service UA chính chủ (vd `sso.amazonaws.com`) + action nằm trong phạm vi tự quản của service đó (vd `PutRolePolicy` lên `AWSReservedSSO_*`) -> `clean` — đây là cloud provider tự vận hành, không phải actor người.
- **⭐ IaC/CI identity (HẸP):** `user_agent` là công cụ IaC (Terraform/CloudFormation/Pulumi) + actor là role OIDC/CI pipeline (vd `gh-oidc-*`, `*-provision`) + resource khớp naming scope của role -> actor/source `clean`; egress IP của CI runner vốn là datacenter/proxy-like — **KHÔNG tự nó là tín hiệu độc** khi identity IaC khớp. **Kể cả khi IP đó có abuse-report/reputation xấu:** CI runner (GitHub-hosted/Azure/AWS/GCP) dùng dải IP SHARED của cloud provider — hàng nghìn tenant khác lạm dụng cùng IP tạo report, đó là nhiễu KỲ VỌNG, KHÔNG phải bằng chứng actor này bị chiếm. Reputation IP shared chỉ thành tín hiệu khi identity KHÔNG khớp (actor/user_agent/resource lệch scope) hoặc có follow-on lạ. Baseline của IaC role = chính pipeline (code-review/merge) — "thiếu actor baseline" KHÔNG phải blocker khi identity khớp.
- Root/admin/global admin action ngoài baseline -> `suspicious` cao.
- Thiếu source/actor baseline -> `unknown`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 3: Đánh giá API action và resource risk
High risk actions theo DOCX:
- IAM/permission: `CreateRole`, `DeleteRole`, `AttachRolePolicy`, `PutRolePolicy`, `CreateAccessKey`, `CreateUser`, grant admin, assume role unusual, disable MFA, password/key reset.
- Stack/compute/database: `CreateStack`, `RunInstances`, `CreateDBInstance`, terminate/delete resources, create public workload.
- Storage/network/security: `PutBucketPolicy`, open security group/firewall to internet, change route, expose service, disable protection/logging.
- Organization/account discovery hoặc privilege mapping: `GetAccountSummary`, `DescribeOrganization`, `ListAWSServiceAccessForOrganization`, `ListDelegatedAdministrators`.

Đánh giá:
- High risk success + actor/source unknown/lạ -> `suspicious`/`malicious`.
- Failed/no-op action có thể suspicious nếu repeated.
- Low risk/read-only action từ known actor/source -> `clean`/`informational`.
- S3 `GetObject` read-only nhưng `event_count` cao hoặc nhiều `object_keys` là data-access/exfiltration signal. Đánh giá quy mô theo count/key hiện có (Rule 10c — không gọi "single event").
- **S3/storage exfil volume vs baseline:** chỉ kết luận `event_count` bất thường (vd GetObject x50 = export thường vs x10k trong 5 phút từ actor mới = exfil) khi `event_count` vượt HẲN baseline median của chính actor/bucket đó trong `_historical_context`/SIEM 7-30d; chỉ khi `event_count`/`object_keys` + baseline median có provenance trong payload, thiếu baseline -> ghi "baseline unavailable" và giữ `unknown`/Need Enrichment, không suy diễn exfil chỉ từ count thô. **⛔ Deterministic:** không có baseline median provenance thì `event_count`=103 và =348 phải cho CÙNG kết quả (`unknown`→NE ở Bước 6), KHÔNG được coi 348 là "exfil hơn" 103.
- **Multi-resource scope explosion:** high-risk action tác động >=10 distinct resource (đếm distinct từ `resource_id` list / `api_calls[].resource`) = scope explosion / escalation nghiêng `suspicious`/`malicious`, mạnh hơn khi vượt scope approved; chỉ khi `resource_id`/`api_calls[].resource` có trong alert_details, thiếu danh sách resource -> ghi unavailable, không bịa số resource.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 4: Kiểm tra baseline và chuỗi hành động

**⛔ Historical-TP KHÔNG phải verdict driver** (đã khoá tại GATE 0(c) + Rule 9 + Bước 6; không dùng bù thiếu approval). Khi hai sub-alert cùng action khác nhau ở IP reputation → **IP xấu hơn PHẢI có verdict ≥ IP sạch hơn** (monotonic), KHÔNG được đảo (IP sạch→TP còn IP nghi hơn→NE là SAI). Prior history không override IP-reputation ordering. (Khớp Shared Rule §Historical, `common_rule_intent.md`.)

- **⭐ Nếu có `api_calls` (chuỗi per-event):** TỰ dựng chuỗi tấn công từ thứ tự call — vd `CreateAccessKey` → `AttachUserPolicy`(Admin) → `AssumeRole`/`GetObject` = privilege-escalation → exfil; đọc `result`/`resource`/`actor` từng call. Nếu CHỈ có 1 API event đơn (không có chuỗi) → đánh giá theo action risk + `Need Enrichment` cho các call kế cận.
- Search 4 giờ trước/sau và 7-30 ngày baseline nếu có trong input.
- Actor có nhiều change liên tiếp, ngoài giờ, trên resource không thường dùng -> `suspicious`.
- Cùng source IP tác động nhiều user/resource/account -> `suspicious`/`malicious`.
- Sau IAM change có resource creation/exfil/network exposure -> `malicious`.
- Không có baseline/timeline -> `unknown`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 5: Kiểm tra approval và ownership
- Change ticket, deployment pipeline, IaC job, maintenance window, owner confirmation exact -> supporting `clean`.
- Approval chung chung không có scope/time/resource -> weak.
- High risk action thiếu approval -> `Need Enrichment` hoặc `True Positive` nếu có suspicious actor/source/follow-on.
- **⭐ NGOẠI LỆ approval (HẸP):** (1) **service-managed role tự quản** (điều kiện ở Bước 2) — hành động do chính cloud provider thực hiện tự động, KHÔNG tồn tại change ticket cho loại này -> thiếu approval KHÔNG phải blocker, supporting `clean`; (2) **IaC/CI identity khớp** (user_agent IaC + role OIDC/CI + resource đúng naming scope) — pipeline chính LÀ cơ chế approval (code-review/merge) -> supporting `clean` khi KHÔNG có tín hiệu mâu thuẫn (actor sign-in nghi, follow-on lạ, resource ngoài scope role).

**Result:** `clean | suspicious | unknown`

### Bước 6: Tổng hợp và kết luận

**⛔ High-risk single-event, IP sạch, không approval/baseline, không compromise-signal: verdict ĐÃ KHÓA ở GATE 0 = `Need Enrichment`/70** — KHÔNG lật lên TP bằng high-risk-đơn-thuần / privileged tag / historical-TP / count thô (Bước 3 L100). Chỉ TP khi có: IP xấu, chuỗi `api_calls[]` escalation, actor-compromise, count vượt baseline có provenance, hoặc object nhạy cảm định danh được. Chỉ FP khi khớp NGOẠI LỆ service-managed/IaC (Bước 5).

Kết luận `True Positive` khi:
- IP malicious/lạ + high risk action success.
- Actor có sign-in/token/key compromise evidence.
- Unauthorized IAM/admin/security/network/storage exposure.
- Chuỗi hành động sau event cho thấy persistence, privilege escalation, data access/exfil, defense evasion.

Kết luận `False Positive` chỉ khi:
- Actor/source/resource/action khớp approved change/deployment.
- Baseline cho thấy đây là hoạt động thường lệ.
- Không có suspicious sign-in/source/follow-on và rule intent mismatch/noise rõ.

Kết luận `Need Enrichment` khi:
- Thiếu actor/source/resource/action/result.
- Thiếu approval/baseline cho high risk action.
- Source/action suspicious nhưng chưa đủ evidence compromise.

`Enrichment_Requests` phải gồm: full cloud audit event, actor sign-in logs, source IP baseline, actions +/-4h, 7-30d actor baseline, resource owner, change ticket/deployment ID, effective permission/policy diff.

---

## Confidence guideline

| Confidence | Điều kiện |
|------------|-----------|
| 90-100 | Actor/source/action/resource/approval/baseline rõ |
| 80-89 | Event và actor rõ, thiếu một context phụ |
| 70-79 | < 80 → Need Enrichment (chưa đủ tin cho TP/FP) |
| 40-60 | Need Enrichment |

FP cho high risk cloud action thiếu approval/baseline → Need Enrichment (không đạt sàn 80).
**⭐ NGOẠI LỆ sàn approval (HẸP):** khi **service-managed role tự quản** HOẶC **IaC/CI identity khớp** (điều kiện đầy đủ ở Bước 2 + Bước 5) + result đúng chức năng + KHÔNG có tín hiệu mâu thuẫn nào → thiếu approval ticket/baseline KHÔNG cap về NE: cho phép **FP 85–90** (service-managed) / **FP 85** (IaC/CI). `Confidence_Reason` PHẢI nêu identity nào (service-managed/IaC), các trường khớp (actor + user_agent + resource scope), và vì sao approval ticket không tồn tại cho loại hành động này.
`Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

---

### YÊU CẦU ĐẦU RA

BẮT BUỘC trả về JSON thuần:

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Xác định cloud event", "Detailed_Analysis": "- Evidence: provider/account, actor, source IP, action, resource, result.\n- Rule intent: rule bắt cloud action/risk nào và có khớp event không.\n- Kết luận step: cloud event chính và dữ liệu còn thiếu.", "Result": "informational"},
    "Step_2": {"Step_Title": "Kiểm tra actor và source IP", "Detailed_Analysis": "- Evidence: source reputation, actor baseline, admin/root/service account, sign-in context.\n- Missing/Conflict: ghi rõ khi thiếu actor baseline hoặc IP provenance.\n- Kết luận step: actor/source hợp lệ, suspicious hay unknown.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_3": {"Step_Title": "Đánh giá API action và resource risk", "Detailed_Analysis": "- Evidence: IAM, network, compute, storage, database, logging/security risk.\n- Missing/Conflict: ghi rõ khi thiếu old/new value hoặc resource sensitivity.\n- Kết luận step: action/resource có rủi ro bảo mật thế nào.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_4": {"Step_Title": "Kiểm tra baseline và chuỗi hành động", "Detailed_Analysis": "- Evidence: actions +/-4h, 7-30d baseline, related users/resources.\n- Missing/Conflict: ghi rõ khi timeline/baseline không khả dụng.\n- Kết luận step: hành vi là baseline hay chuỗi đáng ngờ.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_5": {"Step_Title": "Kiểm tra approval và ownership", "Detailed_Analysis": "- Evidence: change ticket, IaC/deployment, owner confirmation, maintenance.\n- Missing/Conflict: ghi rõ khi không có approval hoặc ownership proof.\n- Kết luận step: approval đủ hỗ trợ FP hay cần enrichment.", "Result": "clean|suspicious|unknown"},
    "Step_6": {"Step_Title": "Tổng hợp và kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các step quyết định TP/FP/NE.\n- Missing/Conflict: dữ liệu thiếu hoặc conflict còn ảnh hưởng confidence.\n- Kết luận step: lý do cuối cùng; historical context chỉ để tham khảo.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Tóm tắt lý do kết luận"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["TP/NE: revoke key/session, rollback change, check policy/resource exposure"],
  "Investigation_Requests": [{"intent": "Mục đích query", "why_raises_confidence": "đang X → lên Y nếu log cho thấy ...", "action": "search_cloud", "target_field": "actor_user|event_name|api_call|source_ip|resource_id", "target_value": "value từ alert", "time_range_hours": 4}],
  "Enrichment_Requests": ["NE HOẶC Confidence < 90: thứ KHÔNG query SIEM được (approval/deployment ID, owner, dữ liệu ngoài); log cloud audit đặt ở Investigation_Requests; [] chỉ khi Confidence >= 90 và không phải NE"],
  "Close_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Close_Note; không viết liền một dòng.",
  "Escalate_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Escalate_Note; không viết liền một dòng."
}
```
