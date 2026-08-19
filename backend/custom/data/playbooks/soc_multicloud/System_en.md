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


---

# Shared Rule Intent Assessment

Áp dụng cho mọi production alert analysis playbook.

## Output Envelope — vị trí field bắt buộc

Kết quả phân tích là MỘT JSON object. Các field sau là **TOP-LEVEL** (ngang hàng với `Audit_Report`) và **TUYỆT ĐỐI KHÔNG được lồng bên trong `Audit_Report`**: `Status`, `Confidence`, `Confidence_Reason`, `Response_Actions`, `Enrichment_Requests`, `Investigation_Requests`, `Close_Note`, `Escalate_Note`.

`Audit_Report` CHỈ chứa `Summary` và các `Step_x` (mỗi step gồm `Step_Title`, `Detailed_Analysis`, `Result`). KHÔNG đặt `Investigation_Queries`/`Investigation_Requests` bên trong step — chúng là field top-level (xem mục Investigation_Requests bên dưới).

Khung vị trí (rút gọn — KHÔNG đổi key):

```json
{
  "Audit_Report": { "Step_1": { }, "Summary": "" },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "",
  "Response_Actions": [],
  "Enrichment_Requests": [],
  "Investigation_Requests": [],
  "Close_Note": "",
  "Escalate_Note": ""
}
```

`Status` và `Confidence` PHẢI tồn tại ở top-level cho MỌI verdict. Hệ thống đọc `Status`/`Confidence` ở top-level; nếu đặt nhầm vào trong `Audit_Report`, verdict sẽ hiển thị `Unknown` và `Confidence` = 0 dù bạn đã kết luận đúng. Quy tắc này GHI ĐÈ mọi ví dụ/format mơ hồ trong các playbook danh mục bên dưới.

## Step 1 — Rule Intent Assessment bắt buộc

Trong `Audit_Report.Step_1.Detailed_Analysis`, ngoài việc tóm tắt alert fields, phải đánh giá `rule_name`/`rulename` nếu có:

- Giải thích rule này là rule gì, mục đích detect hành vi nào, và ý nghĩa SOC của rule đó.
- Xác định rule thường trigger bởi điều kiện nào: IOC/reputation, brand impersonation, auth anomaly, web exploit, process execution, file detection, network scan, privilege change, cloud action, hoặc policy/context khác.
- Đối chiếu rule intent với evidence thực tế trong `Alert Fields`, `alert_details`, `structured_context`, và enrichment context.
- Ghi rõ `rule_intent_match`: `match`, `mismatch`, hoặc `insufficient_data`, kèm lý do ngắn gọn.
- Nếu rule intent match nhưng evidence chính còn thiếu, không kết luận FP confidence cao; ưu tiên hạ confidence hoặc Need Enrichment nếu dữ liệu thiếu có thể đổi verdict.
- Nếu rule intent mismatch, ghi rõ mismatch và không kết luận TP chỉ vì rule name nghe nguy hiểm.
- Nếu chỉ có rule name mà không có evidence thực tế, rule name chỉ là context định hướng điều tra, không phải bằng chứng đủ để kết luận TP/FP.

Ví dụ hệ thống, không hardcode verdict:
- Rule brand impersonation/phishing như `[Phishing] Brand impersonation: observed-domain contains brand` có intent là phát hiện domain/URL/email giả mạo thương hiệu. Khi phân tích phishing/domain, phải đánh giá observed domain/URL/body/header theo intent giả mạo thương hiệu, không chỉ dựa vào việc domain chưa có reputation xấu để kết luận False Positive.
- Rule web exploit/SQLi/XSS có intent là phát hiện request/payload tấn công. Nếu URI/payload thiếu, ghi insufficient data; nếu payload benign rõ và rule intent mismatch, đây là evidence ủng hộ FP.
- Rule policy/DLP/data-handling (data exfiltration, data leak, sensitive-data operation…) có intent là phát hiện HÀNH VI của user trên dữ liệu trong scope giám sát — đối tượng đánh giá là hành vi đó, KHÔNG phải danh tính tool/process thực hiện. Tool hợp pháp (signed, VT 0, parent chuẩn) là phương tiện thực hiện và KHÔNG vô hiệu hóa rule intent (cùng nguyên tắc same-object của Explain-the-detection gate, áp cả khi không có AV detection); thiếu dữ kiện hành vi → đánh giá insufficient data + yêu cầu log hành vi, không kết luận FP bằng tool-identity.

## Step Output Formatting bắt buộc

Áp dụng cho mọi `Audit_Report.Step_x.Detailed_Analysis` trong production alert analysis output:

- PHẢI trả về dạng multi-line JSON string, dùng newline escape `\n`; không viết thành một đoạn văn dài một dòng.
- Mỗi dòng chỉ nên chứa một ý: evidence đã thấy, dữ liệu thiếu/conflict, đánh giá reasoning, hoặc kết luận của step.
- Liệt kê mỗi finding/IOC thành MỘT bullet riêng dạng `- <Nhãn>: <giá trị>` (vd `- Source IP: ...`, `- VT: ...`, `- AbuseIPDB: ...`); step có nhiều IOC/entity thì tách mỗi URL/domain/IP/file/user/resource thành dòng riêng để hệ thống hiển thị rõ ràng; KHÔNG viết dòng header rỗng kiểu `- Evidence:` (mỗi dòng PHẢI có nội dung sau dấu hai chấm). Sau phần finding, ghi `- Missing/Conflict: ...` rồi `- Kết luận step: ...`.
- Nếu step có URL/browser/screenshot evidence, phải tách rõ `checked_url`, `final_url`, redirect, `browser_probe_status`/`nav_error`, và mô tả giao diện/page text hoặc ảnh lỗi nếu có.
- Nếu dữ liệu không khả dụng, vẫn phải ghi thành một dòng riêng, ví dụ `- Missing: Dữ liệu không khả dụng cho bước này`; không để trống và không suy diễn.

## Step Result Enum bắt buộc

Trường `Audit_Report.Step_x.Result` chỉ nhận: `malicious`, `suspicious`, `clean`, `unknown`, `informational`, `no_data`. Chọn theo kết luận thực tế của step và PHẢI nhất quán với `Detailed_Analysis` của chính step đó:

- `clean`: evidence cho thấy hợp lệ/benign (ví dụ path hệ thống chuẩn, chữ ký hợp lệ, không có IOC độc, VT 0 malicious đủ engine).
- `unknown`: CÓ dữ liệu nhưng không đủ/không thuyết phục để kết luận. KHÔNG dùng `suspicious` làm giá trị mặc định khi dữ liệu thiếu.
- `no_data`: bước KHÔNG có dữ liệu để đánh giá — enrichment cho bước này không chạy (`enrichment_not_run`/`unavailable_sources`) hoặc field cần thiết vắng mặt hoàn toàn. BẮT BUỘC dùng `no_data` thay vì suy đoán malicious/suspicious/clean cho bước thiếu dữ liệu; `Detailed_Analysis` ghi rõ thiếu gì.
- `suspicious`: có dấu hiệu nghi vấn thực sự trong evidence, không phải chỉ vì "có thể" hoặc để phòng hờ.
- `malicious`: evidence xác nhận độc hại.
- `informational`: chỉ mang tính context, không ảnh hưởng verdict.

Không được đặt `Result=suspicious`/`malicious` khi `Detailed_Analysis` kết luận là sạch hoặc thiếu dữ liệu; trường hợp đó dùng `clean`, `unknown` hoặc `no_data`. Result phải khớp với dòng `- Kết luận step:` của chính step đó.

## Low-confidence enrichment requests (Confidence < 90) bắt buộc

Không chỉ riêng verdict Need Enrichment. Bất kỳ verdict nào (True Positive / False Positive / Need Enrichment) mà final `Confidence` < 90 đều PHẢI nói CỤ THỂ cần bổ sung gì để NÂNG confidence cho chính alert đang phân tích, qua **HAI** field top-level riêng biệt:

- **`Investigation_Requests`** (top-level, dạng object — phần "Investigate" tách khỏi phase 1): những thứ **lấy được bằng query log trên SIEM/EDR**. Mỗi item: `{intent, why_raises_confidence, action, target_field, target_value, time_range_hours}`. `why_raises_confidence` ghi rõ "đang X → lên Y nếu log cho thấy ...". `target_field` chọn theo loại telemetry (vd `parent_process_name`, `command_line`, `source_ip`, `destination_port`, `event_id`, `error_code`, `logon_type`, `mfa_result`, `request_uri`, `http_status`, `event_name`, `dns_query`...), `target_value` lấy từ alert. Hệ thống TỰ phát hiện loại SIEM và render query cụ thể; connector chạy query, lấy log rồi nộp lại để phân tích lại (Phase 2).
- **`Enrichment_Requests`** (top-level, list chuỗi mô tả): những thứ **KHÔNG render thành query SIEM được** — field còn thiếu trong alert (`command_line`, full email headers, source IP trước NAT, file hash), enrichment reputation/OSINT (VT/AbuseIPDB/IP2Location/Google/screenshot/historical), hoặc dữ liệu ngoài SIEM (email body, SPF/DKIM/DMARC headers, EDR process tree, approval ticket). Ghi rõ cần gì, cho IOC/entity nào, lấy từ đâu.

**Phase 1 KHÔNG kết luận từ log chưa có.** Bước "investigate" chỉ liệt kê `Investigation_Requests` (không tự bịa kết quả query). Khi log được nộp lại (Phase 2), mới đánh giá lại và chốt verdict + nâng confidence. Mỗi item (cả hai field) phải nói rõ gỡ được ambiguity nào; KHÔNG yêu cầu lại dữ liệu đã có trong payload (tránh duplicate). Nếu `Confidence` >= 90 và verdict không phải Need Enrichment thì cả hai có thể để []. Quy tắc này GHI ĐÈ mọi hướng dẫn `TP/FP → []` hoặc "chỉ cho Need Enrichment" trong các playbook danh mục bên dưới.

## Verdict floor (Confidence < 80 → Need Enrichment) bắt buộc

TP/FP chỉ hợp lệ khi `Confidence` >= 80. Nếu evidence chỉ đủ `Confidence` < 80 → `Status` = `Need Enrichment` (kèm `Enrichment_Requests` theo mục trên). Quy tắc này GHI ĐÈ mọi cap `max/không vượt 75/70` và band `<80 = TP/FP` trong các playbook danh mục: các trường hợp đó nghĩa là KHÔNG đạt sàn 80 → `Need Enrichment`, KHÔNG phải FP/TP confidence thấp. Cap đúng 80 (vd `max 80`/`không vượt 80`) vẫn hợp lệ cho TP/FP.

## Confidence self-check (checklist bắt buộc TRƯỚC khi chốt Confidence)

Áp cho MỌI verdict. PHẢI điền field top-level `Confidence_Checklist` (mảng 5 phần tử `{id, answer}`, id = "1".."5") TRƯỚC khi chốt `Status`/`Confidence`, rồi suy ra bin. Mỗi `answer` trả lời CÓ/KHÔNG + cite Evidence_Ref/field khi CÓ. Checklist bắt buộc để chống confidence cao trên bằng chứng mỏng và chống verdict dao động giữa các lần chạy cùng loại alert (cùng bộ trả lời → cùng bin):

```
id=1 → Đối tượng chính (process/IP/domain/file/account) đã ĐỊNH DANH bằng evidence trực tiếp? CÓ (<ref/field>) | KHÔNG
id=2 → Bằng chứng QUYẾT ĐỊNH verdict theo playbook có đủ và đã cite? CÓ (<ref>) | KHÔNG (thiếu <gì>)
id=3 → Có bước THEN CHỐT nào đang no_data/unknown? KHÔNG | CÓ (<step>)
id=4 → Còn thiếu bằng chứng QUYẾT ĐỊNH verdict không? RỖNG | CÒN THIẾU (<gì>)
id=5 → Có conflict/mismatch (file identity, IOC pending, date-sanity, detection↔verdict) CHƯA giải quyết? KHÔNG | CÓ (<gì>)
```

`Confidence_Reason` tóm tắt lại bin đã chọn dựa trên checklist (không cần lặp cả 5 dòng).

**⛔ "Bằng chứng QUYẾT ĐỊNH" là gì tuỳ HƯỚNG verdict — KHÔNG mặc định là reputation/hash:**
- Với verdict dựa **reputation** (IOC độc, VT/AbuseIPDB, IP malicious) → nguồn reputation là bằng chứng quyết định.
- Với verdict dựa **hành vi trực tiếp** (reverse shell, credential dump, web→shell, crack) → chuỗi cmdline/lineage là bằng chứng quyết định; thiếu VT/hash KHÔNG làm [2]=KHÔNG.
- Với **FP structural-identity / RULE RECIPE danh mục đã khớp ĐẦY ĐỦ** (vd process self-check BlueStacks, ASP.NET csc, automation structural identity, product-identity) → **chuỗi cấu trúc (parent+child+path+user+cmdline nhất quán) CHÍNH LÀ bằng chứng quyết định**: [2]=CÓ (cite chuỗi), và thiếu hash/VT/reputation là XÁC NHẬN THIẾU → [4]=RỖNG (không tính là còn thiếu bằng chứng quyết định). KHÔNG hạ các case này xuống NE chỉ vì vắng reputation.
- **Approval / owner-confirmation / nghiệp-vụ / baseline-ngoài KHÔNG BAO GIỜ là bằng chứng quyết định khi VẮNG:** không nguồn alert nào phát ra chúng, không enrichment/SIEM nào render được — chúng chỉ tới từ việc hỏi khách hàng. Vắng approval/owner/baseline-ngoài → KHÔNG đặt [2]=KHÔNG và KHÔNG tính vào [4] như bằng chứng quyết định còn thiếu; ghi vào `Enrichment_Requests`, cap `Confidence` ≤89, và quyết verdict trên HÀNH VI quan sát được (chuỗi thực thi/xác thực, payload, reputation, chuỗi cấu trúc). Approval CHỈ có sức nặng khi nó XUẤT HIỆN (khi đó áp Discriminator #6 scope+timing). ⚠️ Vắng approval đẩy về **TP-thận-trọng** theo Discriminator #5 cho hành vi đặc quyền, KHÔNG đẩy về FP.

**Ánh xạ bin (sàn dùng chung):**

- **Cao (90–100):** [1]=CÓ và [2]=CÓ và [3]=KHÔNG (ở bước then chốt) và [4]=RỖNG và [5]=KHÔNG.
- **Trung bình (80–89):** đối tượng + bằng chứng quyết định đủ để chốt TP/FP, nhưng thiếu MỘT context phụ ([4] còn thiếu thứ KHÔNG quyết định verdict) hoặc ≤1 bước phụ unknown.
- **Thấp / Need Enrichment (40–60):** [1]=KHÔNG, hoặc [2]=KHÔNG cho bằng chứng quyết định, hoặc [3]=CÓ ở bước then chốt, hoặc [5]=CÓ chưa giải quyết → verdict KHÔNG đạt sàn 80 → `Need Enrichment`, trừ khi playbook danh mục có rule cứng nghiêng TP (named-threat active) hoặc FP structural-identity đã khớp đầy đủ.

**Hard rule:**
- [3]=CÓ ở bước THEN CHỐT HOẶC [4] còn thiếu bằng chứng QUYẾT ĐỊNH → CẤM `Confidence` >= 90.
- Đây là SÀN chống-overconfidence, KHÔNG nới lỏng cap chặt hơn của playbook danh mục (thiếu command_line vẫn −10; named-threat vẫn khoá FP). Khi checklist và playbook cho mức khác nhau → lấy mức THẤP hơn — **NGOẠI TRỪ khi một RULE RECIPE / ngoại lệ structural-identity của playbook danh mục đã khớp ĐẦY ĐỦ và định nghĩa rõ verdict+confidence: khi đó theo RECIPE** (recipe là bằng chứng cấu trúc, không bị checklist kéo xuống NE).

## Carve-out "nguồn không cấp field" (structural-absence — existence-gated, đối xứng TP/FP)

Mở rộng carve-out structural-identity ở trên cho MỌI hướng verdict: khi một loại bằng chứng vắng vì **NGUỒN alert không phát ra field đó** (không phải chưa lấy được), áp 3 điều kiện fire + 3 chốt chặn.

**Điều kiện fire (đủ CẢ BA):**
1. Bước tương ứng đã ghi `Result=no_data` (KHÔNG phải `unknown`), VÀ `Detailed_Analysis` nêu ĐÍCH DANH field vắng + căn cứ nguồn không cấp (dựa `unextracted_fields`, `log_source`/`siem_type`, `service_name`…), VÀ KHÔNG có field cùng-họ nào trong payload.
2. Field vắng KHÔNG phải bằng chứng QUYẾT ĐỊNH cho ĐÚNG hướng verdict đang xét (theo khối "Bằng chứng QUYẾT ĐỊNH tuỳ HƯỚNG verdict" ở trên).
3. Bước đó KHÔNG mang vai trò THEN CHỐT của danh mục (playbook danh mục định nghĩa bước then chốt).

**Hệ quả khi fire:** bước `no_data` này KHÔNG tính vào Confidence_Checklist [3]; [4] ghi "RỖNG (thiếu có cấu trúc: <field>)" thay vì "CÒN THIẾU". Vẫn PHẢI đẩy `Enrichment_Requests`/`Investigation_Requests` cho field đó (kênh khác nếu lấy được).

**3 chốt chặn BẮT BUỘC (thiếu 1 → KHÔNG áp carve-out, giữ nguyên xử lý cũ):**
- (a) Explain-the-detection gate (mục dưới) và named-threat lock **OUTRANK tuyệt đối**: alert có detection đã xác nhận thì carve-out KHÔNG chạy.
- (b) Carve-out CHỈ gỡ điều-kiện-rơi-bin-thấp, **KHÔNG cấp confidence**: trần vẫn 80-89 vì [3] có thể còn CÓ ở bước then chốt khác; phải có bằng chứng dương độc lập ở bước THEN CHỐT mới vượt sàn 80.
- (c) Khi field vắng **CHÍNH LÀ** bằng chứng quyết định của hướng verdict → carve-out KHÔNG áp: GIỮ `Need Enrichment` (NE chính đáng, tuyệt đối không ép TP/FP).

## Explain-the-detection gate (mâu thuẫn detection ↔ verdict) bắt buộc

**Điều kiện kích hoạt:** alert MANG một detection đã xác nhận — `evidence[].verdict`/AV/EDR/sandbox/firewall = `malicious`|`suspicious`, HOẶC có `threat_display_name`/`threat_family`/signature, HOẶC action `block`/`quarantine`/`remediate` — NHƯNG phân tích đang nghiêng về `False Positive`/clean/benign. Mâu thuẫn này PHẢI được giải quyết TRƯỚC khi hạ verdict; không tự động tin một bên.

**Nghĩa vụ (chỉ được kết luận FP khi thoả):**
- (i) **Pin đối tượng bị detect:** nêu CHÍNH XÁC đối tượng mà detector gắn cờ, suy từ threat-name/loại (vd threat `VBS`/script → một script; `PE`/`Win32`/trojan → một executable; network/C2 IOC → một đích kết nối; webshell → một file web). KHÔNG mặc định đối tượng bị detect là thực thể bề mặt kích hoạt alert (process cha, account, host, source, tool/agent).
- (ii) **Giải thích chính detection đó là báo nhầm** — VỀ ĐÚNG đối tượng vừa pin (same-object), có provenance. Bằng chứng "hợp lệ" về một đối tượng KHÁC (vật mang) KHÔNG vô hiệu hoá detection về đối tượng bị gắn cờ.

**Tự phát hiện đang clear NHẦM đối tượng (điều kiện tính từ dữ liệu):** nếu threat-name/loại KHÔNG khớp đối tượng đang được xét — vd threat `VBS`/script nhưng đối tượng là ELF/binary; malware-family gán cho một OS/admin tool, interpreter, scanner/launcher — thì đối tượng thật là cái mà thực thể bề mặt đã **chạy/nạp/xử lý/forward** (script con, DLL nạp kèm, mẫu trong scan-temp/quarantine, attachment, đích kết nối). Pin & đánh giá cái đó, KHÔNG kết luận theo thực thể bề mặt.

**Không thoả gate ⇒ KHÔNG FP:** nếu không giải thích được detection, HOẶC bằng chứng hợp lệ không same-object, HOẶC `remediation_status`/`edr_action` = `active`/không-remediate (threat chưa được contain) → `Status` = `Need Enrichment`/escalate (không đạt sàn confidence cho FP). Detection đã xác nhận outrank "thực thể bề mặt trông hợp lệ" (chỉ là context yếu); muốn FP một detection thật phải chỉ ra đó là lỗi detector, không phải bằng cách trỏ sang một đối tượng khác.

**Existence-gated:** chỉ kích hoạt khi CÓ detection xác nhận; alert không có detection thì KHÔNG áp (tránh over-escalate). Các quy tắc riêng sẵn có (interpreter ≠ artifact; proxy/XFF dùng forwarded client; crawler identity không downgrade; transport-infra ≠ sender legitimacy; M365/MDO removal = đã xác định độc) là HỆ QUẢ của gate này.

**Ngoại lệ "crawler identity không downgrade" (chỉ Tấn công Web):** quy tắc "crawler identity không downgrade" KHÔNG áp cho **verified legitimate search-engine crawler** đủ 4 điều kiện carve-out GATE 0-EXCEPTION trong `playbook_web_attack.md` — khi danh tính search engine lớn (Google/Bing/DuckDuckGo/Yandex/Baidu/Apple) đã được XÁC MINH độc-lập-với-UA (reverse_dns/client_ip_class/ASN operator) VÀ IP reputation sạch VÀ request đã giải mã là benign → được kết luận False Positive. Đây KHÔNG phải downgrade theo identity đơn thuần mà là kết luận trên payload benign đã giải mã (same-object). Thiếu xác minh (chống giả mạo UA) / SEO/scanner tool / có payload-probe → vẫn giữ deny-by-default.

## Note Output Format
`Close_Note` và `Escalate_Note` là JSON string multi-line, dùng newline `\n`, dùng blank line `\n\n` chỉ NGAY TRƯỚC mỗi heading `#` (không có dòng trống ngay sau heading), và bullet; không viết thành một dòng.

**⛔ CẢ HAI note BẮT BUỘC non-empty cho MỌI verdict** — chuỗi rỗng `""` trong khung envelope ở trên chỉ là placeholder vị trí, KHÔNG phải giá trị hợp lệ. Với `False Positive`: `Escalate_Note` vẫn sinh đủ form, mục Recommendation ghi "No escalation required — closed as False Positive" + lý do 1 dòng. Với `Need Enrichment`: Recommendation nêu cần enrichment/log gì TRƯỚC KHI quyết định escalate.

**Remediation-first (existence-gated):** Khi evidence trực tiếp trong alert/enrichment cho thấy security control ĐÃ hành động — `edr_action` ∈ {blocked, quarantined, remediated, removed, isolated}, M365/MDO đã gỡ ("malicious URL removed after delivery", ZAP/ZapPhish), firewall/WAF action = block/deny/drop (field/giá trị THẬT, không suy diễn) — thì:
- `Close_Note` mục `# Action` mở đầu bằng đúng một dòng: `- Remediation: <control> đã <chặn/gỡ/cách ly> <đối tượng> — mối đe dọa đã được xử lý tự động, không cần hành động thêm`.
- `Escalate_Note` mục Recommendation: dòng khuyến nghị ĐẦU TIÊN nêu cùng trạng thái đó, trước các khuyến nghị khác.
- Với verdict `True Positive` + remediation evidence: `# Closed Reason` ghi rõ **"True Positive — tấn công thật, đã bị <control> chặn/gỡ; việc ĐÃ BỊ CHẶN không làm alert thành False Positive"** — attack thật thì đóng TP dù không còn hành động nào cần làm.
- KHÔNG có evidence control-đã-hành-động → KHÔNG thêm dòng Remediation (không suy diễn). Quy tắc này chỉ chuẩn hóa NOTE — không đổi `Status`/`Confidence`.

`Close_Note` format:
```text
# Alert Description
  - <what this alert is about; nội dung tiếng Việt>

# Asset
  - <relevant field>: <value>

# Action
  - <very brief summary of checked sources and outcomes, e.g. SIEM/EDR/VT/Google/screenshot/customer confirmation when evidence exists>

# Closed Reason
  - <explicit reason why final verdict is False Positive, True Positive, or Need Enrichment; include decisive evidence or missing evidence>
```

`Escalate_Note` format:
```text
# Alert Overview
  - Alert ID: <value or "-">
  - Alert Link: <value or "-">
  - Alert Name: <value or "-">
  - Alert Time: <value or "-">
  - Severity: <value or "-">
  - Category: <value or "-">
  - Alert Description: <what this alert is about; value or "-">

# Technical Details
  - <relevant field>: <value>

# Recommendation:
SOC recommends:
  - <recommended action and specific next actions to perform, e.g. contain/block/reset/verify owner/collect logs/enrich missing evidence>
```

## Evidence Reference Table & `Evidence_Refs` bắt buộc (existence-gated)

Khi payload có mục `EVIDENCE REFERENCE TABLE` (mỗi dòng một nguồn enrichment với ID dạng `[E1]`, `[E2]`…):

- Mỗi `Audit_Report.Step_x` thêm field `Evidence_Refs`: danh sách ID của các nguồn THỰC SỰ dùng cho kết luận của step đó (vd `["E1","E3"]`). Step thuần context/không dùng nguồn nào → `[]`.
- **Số liệu của nguồn nào chỉ được gán cho đúng nguồn đó**: VT ratio/AbuseIPDB score của `[E2]` KHÔNG được viết cho IOC của `[E1]`. Trước khi viết một con số, đối chiếu lại đúng dòng `[En]` chứa nó.
- Claim nêu TÊN nguồn (VT/Google/AbuseIPDB/IP2Location/browser/history/sandbox…) mà KHÔNG cite được ID tương ứng trong bảng → claim đó không có provenance: bước phải dùng `Result=no_data` (hoặc `unknown` nếu có dữ liệu khác) và đẩy nhu cầu vào `Enrichment_Requests`, KHÔNG tự điền số liệu.
- ID chỉ được lấy từ bảng — KHÔNG bịa ID mới, không cite ID ngoài bảng.
- Payload KHÔNG có bảng (alert không có sub-check) → bỏ qua field `Evidence_Refs`, không bịa.

**Evidence contract:** Chỉ dùng evidence trong `Alert Fields`/`alert_details`, `structured_context`, `_sub_audit_reports`, `_source_evidence` hoặc `raw_excerpt` nếu được cung cấp. Claim exact như VT ratio/vendor, AbuseIPDB/IP2Location, Geo/ASN/ISP/IP reputation, Google, screenshot/browser, sandbox report (ANY.RUN/Hybrid Analysis/Joe Sandbox), M365 verdict, historical FP/TP/noise, signature/publisher, owner/approval/customer confirmation phải có provenance trực tiếp. Nếu thiếu evidence thì ghi `unknown` hoặc yêu cầu `Enrichment_Requests`; không tự điền số liệu, label, URL, ticket history hoặc confirmation. `Confidence` >85 phải nêu evidence trực tiếp; TP/FP dựa trên missing evidence hoặc enrichment không provenance → Need Enrichment (không đạt sàn Confidence 80). Output không được chứa model/provider/backend AI name hoặc `gemini`, `chatgpt`, `gpt`, `claude`, `llm`.

**⛔ Named-source verbatim gate (CHỐNG bịa khi OSINT bị chặn).** Mọi claim nêu TÊN một nguồn threat-intel ĐỊNH DANH hay số/nhãn của nó — vendor/list (GridinSoft, Kaspersky, ScamAdviser, Spamhaus DROP, CleanTalk, GreyNoise, Turris, AbuseIPDB confidence cụ thể, IP2Location `threat`/proxy label, "listed in `<...>.txt`", "Trust Score X/100"), sandbox (ANY.RUN/Hybrid Analysis/Joe Sandbox + ngày/verdict), report id/URL — CHỈ được nêu khi tên + giá trị đó xuất hiện **NGUYÊN VĂN** trong `evidence_ledger.search_provenance` / `_source_evidence` / `_sub_audit_reports`. Khi enrichment bị chặn/lỗi (`google_search_limitations`, `unavailable_sources` chứa Google/OSINT, search `status:"skipped_captcha"`, browser timeout) → đó là **evidence UNAVAILABLE**: KHÔNG phải benign, KHÔNG phải bằng chứng độc. PHẢI ghi rõ "OSINT/Google unavailable (CAPTCHA/timeout)", Step/Result `unknown`, đẩy `Enrichment_Requests`, cap Confidence (verdict dựa vào nguồn đang thiếu → KHÔNG đạt sàn 80, hạ Need Enrichment). TUYỆT ĐỐI không tổng hợp tên nguồn/score từ keyword tìm kiếm, từ "nguồn nổi tiếng", hay suy "sạch" từ việc vắng dữ liệu — không khớp ledger = hallucination.

## Second-opinion dissent (`second_opinion_dissent` / `audit_dissent`) — existence-gated

Nếu payload (hoặc raw alert) có block `second_opinion_dissent`/`audit_dissent`: alert này được MỞ LẠI để phân tích lần hai vì một lượt kiểm toán độc lập bằng giả thuyết cạnh tranh cho rằng một kịch bản khác CHƯA BỊ LOẠI TRỪ. Cách dùng:

- Block chứa `competing_hypothesis` (statement + discriminating_evidence + refutation_attempt), `missing_key_evidence`, `evidence_matrix_summary` — đây là GIẢ THUYẾT CẦN KIỂM TRA và bằng chứng phân biệt cần tìm, **KHÔNG phải verdict** và không có confidence kèm theo.
- Trong các Step liên quan, PHẢI đánh giá trực tiếp giả thuyết cạnh tranh đó với bằng chứng hiện có: bằng chứng nào ủng hộ, bằng chứng nào bác bỏ, `missing_key_evidence` nào đã/chưa thu thập được.
- Verdict + Confidence vẫn tự quyết từ bằng chứng theo playbook — không nghiêng theo block này, không trích dẫn "hệ thống kiểm toán" trong `Close_Note`/`Escalate_Note` (chỉ nêu bằng chứng và lập luận).
- Alert bình thường KHÔNG có block này → bỏ qua hoàn toàn, không suy diễn.

## Historical Operation Context Note
`historical_context`/`_historical_context` chỉ là tham khảo cho Analyst, không chọn verdict/confidence và không tự động TP/FP. Chỉ claim repeated FP/noise/historical benign khi có `summary_7d`, `total_matches`, `fp_count`, `tp_count`, `recent_matches`, `matched_fields`; nêu match key như `rule_name`, `category`, `hostname`, `source_ip`, `user`, `activity_signature`. Nếu có `tp_24h_count`/`recent_tp_24h_matches`, phải nhắc ngắn gọn đây là TP liên quan trong 24h cần chú ý, nhưng không tự động kết luận TP nếu evidence hiện tại không đủ.

**⛔ Lịch sử Need Enrichment = TRUNG TÍNH (chống vòng tự củng cố):** CẤM dùng "các ticket tương tự trước đó đều Need Enrichment" làm lý do chọn/giữ `Need Enrichment` hoặc hạ confidence — ticket NE cũ nghĩa là CHƯA AI kết luận, không phải bằng chứng nghiêng về bất kỳ verdict nào; lặp lại lý do đó tạo vòng NE vĩnh viễn cho mẫu alert lặp. Chỉ lịch sử **FP/TP đã xác nhận** (`fp_count`/`tp_count` thật, đúng existence-gate dưới) mới mang trọng số tham khảo. SỰ TỒN TẠI của các match (`total_matches`, `recent_matches`, cùng `activity_signature`) vẫn dùng được như bằng chứng THỰC TẾ rằng hành vi lặp lại định kỳ (vd scheduled job) — nhưng trạng thái NE của chúng thì KHÔNG được viện dẫn.

**⭐ `historical_context.verified` — nhãn NGƯỜI đã phân xử (trọng số CAO hơn, vẫn KHÔNG phải verdict):** Khi payload có block `historical_context.verified` (`fp`/`tp`/`labeled_total`/`sources`/`latest`), đây là số ticket cùng identity mà **analyst đã trực tiếp kết luận** — KHÁC hẳn `summary_7d.fp_count`/`tp_count` vốn là verdict do CHÍNH pipeline này tự sinh. Vì là nguồn ngoài, không tự củng cố, nên nó **mang trọng số tham khảo cao hơn** `fp_count`/`tp_count`.
Cách dùng:
- Được phép nêu tường minh, vd: "identity này đã được analyst xác nhận FP 3 lần (nguồn: me-ground-truth, gần nhất 2026-07-21)" và dùng làm bằng chứng bổ trợ cho hướng verdict tương ứng.
- ⛔ **CẤM dùng một mình để chốt verdict.** Nó là BẰNG CHỨNG, không phải đáp án. Bằng chứng của chính alert hiện tại vẫn phải độc lập ủng hộ kết luận. Nếu alert hiện tại có dấu hiệu tấn công thật mà lịch sử verified là FP → **theo bằng chứng hiện tại**, không theo lịch sử (hành vi cũ lành không bảo đảm lần này lành).
- ⛔ Không có block `verified` → KHÔNG có nhãn người nào cho identity này; CẤM claim "analyst đã xác nhận…" (existence gate bên dưới áp dụng nguyên).
- `verified.fp` cao KHÔNG tự động nâng confidence lên trần; vẫn theo Confidence_Checklist.

**⛔ Existence gate (no-history):** Lớp orchestration LUÔN gắn `historical_context` vào payload. Nếu `historical_context.status == "none"` (hoặc field rỗng/thiếu `total_matches`) → KHÔNG có ticket lịch sử nào khớp; CẤM mọi claim kiểu "N ticket trước cùng sender/host/user là TP/FP", "ticket cũ", "lịch sử sender/host", "tương tự trong 7 ngày/24 giờ" — đó là hallucination. Không có dữ liệu lịch sử → bỏ qua hoàn toàn, KHÔNG dùng để chọn verdict/confidence. Quy tắc này **GHI ĐÈ** mọi Step/field trong playbook danh mục có nhắc `_historical_context` / "historical context" / "ticket cũ tham khảo": khi `status=none`, các mục đó PHẢI để trống hoặc ghi "không có lịch sử khớp", TUYỆT ĐỐI không bịa số ticket / số ngày / verdict lịch sử để lấp Step.

## Behavioral & Context Discriminators (TP/FP) bắt buộc

Các quy tắc dưới đây tăng độ chính xác phân biệt True Positive vs False Positive. TẤT CẢ đều **existence-gated**: chỉ áp khi field/evidence tương ứng CÓ provenance trực tiếp trong `alert_details`/`_source_evidence`/`_sub_audit_reports`; thiếu → ghi "dimension unavailable", KHÔNG suy diễn, KHÔNG đổi verdict bằng code. Đây là hướng dẫn suy luận cho analyst, không phải verdict cứng.

**1. Reputation recency (độ tươi reputation):** Khi verdict malicious dựa vào AbuseIPDB score, VT IP-resolution, hoặc OSINT/Google threat mention, PHẢI xét timestamp:
- AbuseIPDB `abuse_confidence_score` cao nhưng `last_reported_at` > 180 ngày → có thể đã reassign/remediate; KHÔNG claim "đang active-malicious" chỉ dựa reputation, hạ confidence + `Enrichment_Requests`.
- VT `ip_resolutions` resolution age > 60 ngày → IP độc là lịch sử, không phải hosting hiện tại của domain.
- OSINT/bài viết publication_date > 1 năm → chỉ là context lịch sử, không phải đe doạ hiện hành.
- Thiếu timestamp trong `_source_evidence` → "recency unavailable", không claim độ tươi.
- **Date-sanity:** so MỌI `creation_date`/`resolution_date`/`last_seen` với `alert_time` TRƯỚC khi gán nhãn. KHÔNG gọi một ngày là "trong tương lai/in the future" nếu nó ≤ `alert_time` (lệch múi giờ/định dạng ≠ tương lai); KHÔNG gọi domain đã ~nhiều năm tuổi là "rất mới/newly-registered". Thiếu/không parse được ngày → "date unavailable", KHÔNG suy.

**1b. IP reputation reading (mapping DÙNG CHUNG — mọi playbook có `ip:{ip}` enrichment):** `ip:{ip}._source_evidence.abuseipdb.abuse_confidence_score` ≥80 + `total_reports` nhiều → `malicious`; 25-80 → `suspicious`; report context/`usage_type` làm tăng nghi ngờ; KHÔNG có report ≠ tự động clean. `ip:{ip}._source_evidence.ip2location.proxy_type` VPN/TOR/Proxy → củng cố nghi ngờ; Hosting/Cloud/Datacenter → IP hạ tầng (không phải dải user thường), cân theo context/domain phân giải; ISP/ASN/country bổ sung identity. Mỗi IP có verdict riêng ở `ip:{ip}` (`Status`/`Confidence`) — dùng làm điểm tựa; kết hợp reputation recency (#1) khi reputation cũ.

**2. Velocity / rate / tần suất:** Khi alert có nhiều event (`auth_events[]`, `api_calls[]`, connection logs, `ip_observations[]`), suy ra tín hiệu vận tốc thay vì chỉ dùng `event_count` thô:
- Interval/chu kỳ: đều đặn ~30s–5m → automation/beacon; bursty không đều → scan/timeout.
- Time-spread: min/max timestamp; > 60 phút + ≥ 5 lần fail → slow brute-force.
- Concentration: số user / dest host / resource duy nhất trên mỗi source.
- Baseline: first-seen vs lặp lại (chỉ khi `historical_context` có totals).
Mỗi sub-signal existence-gated theo timestamp/list có sẵn; thiếu → đánh dấu dimension đó unavailable.

**3. Impossible-travel / geo-velocity:** Khi `auth_events[]`/`api_calls[]` có ≥ 2 event kèm per-event `source_ip` VÀ IP2Location country giải được cho từng IP → đánh giá tính khả thi di chuyển: country A→B trong khung thời gian bất khả thi = tín hiệu TP mạnh DÙ từng IP riêng lẻ sạch; cùng/lân cận quốc gia trong khung hợp lý = ủng hộ benign. Chỉ có count gộp (không per-event IP+time+country) → KHÔNG tính được, ghi NE/unavailable, TUYỆT ĐỐI không bịa hành trình.

**4. Ownership / customer-asset gate:** Khi payload có `context_tags.ip_ownership` (mỗi IP kèm `role` internal/external/allowlisted + `matched` CIDR):
- external → internal nhắm service nhạy cảm = nghiêng TP.
- internal → internal = cần approval/context, KHÔNG auto-FP.
- IP thuộc `ip_allowlist` + reputation sạch = ủng hộ FP (kèm provenance khớp allowlist entry nào).
Thiếu allowlist/CIDR config hoặc role → bỏ qua quy tắc này, KHÔNG bịa ownership.

**5. Privilege/sensitivity tier của principal:** Khi payload có `context_tags.principal` (tier `privileged`/`service_account` + `matched`) hoặc xác định được role/group/`actor_type` của tài khoản:
- Tài khoản đặc quyền (Domain/Enterprise/Schema Admins, Backup Operators, DnsAdmins...) hoặc nhóm nhạy cảm bị nhắm = risk multiplier nghiêng TP; CẤM FP confidence cao dựa trên thiếu evidence cho chính account đặc quyền này.
- `service_account` khớp baseline tự động hoá = ủng hộ FP; KHÔNG áp logic "off-hours / đăng nhập lạ = nghi" cho automation.
Thiếu role/`actor_type` → bỏ qua, không suy diễn đặc quyền.

**6. Approval scope + timing alignment:** `approval_reference`/ticket chỉ là bằng chứng FP khi (a) scope khớp action — ticket "sửa prod-db-1" nhưng action đụng 10+ resource/all account = scope mismatch → escalate, KHÔNG FP; VÀ (b) timing pre-action — tạo/duyệt TRƯỚC `alert_time` = FP mạnh; post-hoc/hồi tố = yếu, đáng nghi. Chỉ có reference trơ (không scope/time) → coi là chưa xác minh, KHÔNG phải confirmed-benign.

**7. Prevalence + baseline môi trường (`environment_prevalence`):** Khi payload có block này (số liệu KHÁCH QUAN đếm từ alert-stream, kèm `note` giải thích) — provenance, KHÔNG phải verdict:
- `prevalence[].distinct_hosts` cao (vd process/domain xuất hiện trên NHIỀU host của tenant) + `first_seen` lâu → hành vi PHỔ BIẾN, lâu đời trong môi trường → hỗ trợ benign (vd BlueStacks self-check trên nhiều máy). `distinct_hosts`=1/first_seen mới → hiếm hơn, KHÔNG tự nó = độc.
- `identity_baseline.known[]` (feature user đã dùng nhiều lần, `count` cao, `first_seen` lâu) → baseline hợp lệ → hỗ trợ FP cho login/hành vi từ đúng giá trị đó (vd user đăng nhập từ IP quen 60 ngày).
- `identity_baseline.new_for_identity[]` (feature LẦN ĐẦU với identity có lịch sử) → tín hiệu novelty → nghiêng nghi ngờ hơn (vd user có baseline nhưng đăng nhập từ IP CHƯA TỪNG thấy) — nhưng KHÔNG tự kết TP, kết hợp evidence khác.
- ⛔ **CẬN DƯỚI, không phải toàn cảnh:** số đếm CHỈ từ alert-stream trong cửa sổ quan sát — `distinct_hosts` thấp/VẮNG mặt KHÔNG chứng minh "hiếm" hay "độc" (có thể chỉ chưa từng sinh alert). CẤM suy "không có trong baseline → đáng ngờ" khi identity KHÔNG có lịch sử nào (block sẽ không phát `new_for_identity` trong trường hợp đó). Không có block → bỏ qua, không bịa số liệu prevalence.

**Language:** Headings/section labels luôn English; JSON keys/enums giữ English. Nội dung note viết tiếng Việt. Không nhắc backend/hệ thống sinh nội dung/endpoint nội bộ.
