# Playbook Phân tích Kết nối Domain độc

## Global Evidence Rules
1. Chỉ dùng evidence được cung cấp. Không tự bịa VT, Google, browser, SIEM, DNS, EDR, owner, allowlist.
2. Missing/unavailable/truncated data là `unknown`, không phải `clean` hoặc `malicious`.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. `Close_Note` và `Escalate_Note` bắt buộc cho mọi verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.

**Named-source rule:** Chỉ nhắc tên nguồn ngoài context nếu payload có đúng tên đó hoặc snippet/result tương ứng. Không có trong evidence thì không được tự bịa tên nguồn. Nếu search result mâu thuẫn với kết luận, phải nêu rõ mâu thuẫn và hạ confidence hoặc dùng `Need Enrichment`.

**Domain/IP provenance rule:** Khi dùng kết quả domain analysis để claim IP hiện tại/lịch sử hoặc số AV của IP resolution, phải trích đúng fact trong `_source_evidence.ip_resolutions`, `_sub_audit_reports`, hoặc `evidence_index.domain_resolution` gồm `resolved_ip`, `resolution_type`, `malicious_count`, `total_engines`/`vt_detection_ratio`. Nếu không thấy fact structured này thì không được tự nêu IP/số AV cụ thể; ghi thiếu provenance và yêu cầu `Enrichment_Requests` lấy raw VT domain resolution/IP reputation.

**Enrichment request discipline:** theo Shared Rule §"Low-confidence enrichment requests (Confidence < 90)" (common_rule_intent.md). Field domain hay thiếu: DNS/proxy/firewall log, raw VT IP report, endpoint process, owner/allowlist.

7. Domain reputation sạch không đủ để FP nếu endpoint/process/context đang suspicious.
7a. **⛔ Root domain ≠ URL/path bị cờ:** Reputation domain GỐC sạch (VT 0/91, popular rank, homepage hợp lệ) KHÔNG có nghĩa URL/path cụ thể bị cờ là sạch. Nếu alert cờ một URL/script path cụ thể (vd Kaspersky Web Threat Protection / category trên `https://domain/sw.js?v=...`) → PHẢI đánh giá CHÍNH URL/path đó qua enrichment `url:{url}` (browser probe, final_url, page/script behavior). KHÔNG kết luận FP/Clean chỉ vì homepage `https://domain/` sạch. Vendor Web-AV/script detection trên path (vd `not-a-virus:HEUR:AdWare.Script.Pusher` trên `/sw.js`) là evidence cho path đó, KHÔNG phải noise.
7b. **⛔ AdWare/Riskware/PUA = MALICIOUS (không phải phần mềm hợp pháp):** Detection name chứa `AdWare`, `Riskware`, `RiskTool`, `Pusher`, `PUA`, `potentially unwanted`, hoặc prefix Kaspersky `not-a-virus:` (vd `not-a-virus:HEUR:AdWare.Script.Pusher`) trên domain/URL/script bị cờ = **malicious evidence** → Step `malicious` → **True Positive**. Adware/riskware là phần mềm KHÔNG mong muốn/độc hại trên endpoint doanh nghiệp, KHÔNG phải "phần mềm hợp pháp" hay "ad script benign". Prefix `not-a-virus:` chỉ là nhãn phân loại PUA/riskware của Kaspersky, **KHÔNG đồng nghĩa benign**. CẤM kết luận FP/Clean với lý do "chỉ là quảng cáo / not-a-virus / PUA nhẹ". **CONFIRMED detection → TP (không hedge):** vendor AV/Web Threat Protection với detection name có TÊN malware-family (`not-a-virus:AdWare.*`, `Riskware.*`, `Trojan.*`…) + `firewall_action` Detected/Blocked = mối đe dọa ĐÃ XÁC NHẬN bởi AV → **True Positive**. Đây KHÁC firewall block chung chung (rule 10b KHÔNG áp). Thiếu URL browser probe / process tree / referrer → chỉ **giảm confidence**, TUYỆT ĐỐI KHÔNG hạ xuống `Need Enrichment`/`False Positive` — AV đã confirm threat; thiếu enrichment chỉ làm rõ "đã xảy ra thế nào", không đổi việc "có độc".
8. Không claim "domain độc/sạch" nếu không có exact observed domain evidence. Brand/domain tương tự không thay thế observed domain.
9. Google/search/screenshot path không phải evidence nếu không có text/result/page behavior cụ thể.
10. Không claim VT ratio, Cisco/Umbrella rank, Google result, screenshot content, or browser page meaning unless the exact factual field/text is present in context.
10a. Không claim Kaspersky/browser block/screenshot content nếu payload chỉ có screenshot path hoặc không có `_screenshots`/browser text/`final_url`/page behavior factual field. Ghi `browser evidence unavailable` và để Step = `unknown`/`informational`.
10b. Firewall action `blocked` và nhiều event chỉ chứng minh traffic bị chặn/lặp lại; không đủ để claim domain malicious nếu thiếu domain reputation/source evidence. Khi thiếu VT/OSINT/browser/process evidence, dùng `Need Enrichment` hoặc confidence cap 70-75 theo evidence hiện có. **Áp cho firewall/blocklist block CHUNG CHUNG; KHÔNG áp cho vendor AV detection có TÊN malware-family (`not-a-virus:AdWare/Riskware`, `Trojan.*`…) — xem rule 7b: named detection = confirmed → TP, không hedge.**
10c. `Close_Note` Action/Closed Reason chỉ được nêu VT/vendor/Kaspersky/Google khi các field đó có provenance trực tiếp; nếu không có thì tóm tắt missing evidence thay vì bịa nguồn kiểm tra.
11. Historical context chỉ là supporting context — **existence-gated** theo nguyên văn Shared Rule §"⛔ Existence gate (no-history)" (common_rule_intent.md); chỉ dùng khi có `summary_7d`/`total_matches` thật.
12. Không public tên công nghệ sinh nội dung, nhà cung cấp, nền tảng hoặc endpoint nội bộ trong kết quả.

---

## Định nghĩa trạng thái

| Trạng thái | Ý nghĩa |
|------------|---------|
| **True Positive** | Endpoint/user/system kết nối domain có evidence malicious/phishing/C2/riskware hoặc domain sạch nhưng process bị inject/độc hại |
| **False Positive** | Domain đúng là benign và nguyên nhân truy vấn được giải thích bằng nghiệp vụ hợp lệ |
| **Need Enrichment** | Chưa xác định được domain có độc hay tại sao thiết bị truy vấn |

---

## Dữ liệu enrichment

| Trường JSON | Nội dung |
|-------------|----------|
| `alert_info` | rule_name, category, siem_type, alert_time |
| `alert_details` | domain, domain_observations, source_ip, destination_domain, hostname, user, process_name, command_line, DNS/gateway/firewall context |
| `domain:*` | Domain sub-analysis, VT factual fields, screenshot/browser access, Google text |
| `url:*` | URL/path bị cờ: browser probe (final_url, redirect, page/script behavior) của chính URL đó — KHÔNG chỉ root domain |
| `ip:*` | IP relation/reputation nếu có |
| `_historical_context` | Ticket cũ tham khảo — CHỈ khi `status` ≠ `none`; `status=none`/thiếu → bỏ qua, KHÔNG bịa số ticket/ngày |

---

## Hướng dẫn phân tích

### Bước 1: Xác định thông tin cảnh báo và observed domain
Trích xuất:
- Thời điểm, rule_name, log source.
- Observed domain chính xác, source IP/hostname/user, destination IP nếu có.
- Nếu có `domain_observations`, dùng `role`/`source_field` để xác định domain nào là destination_domain, dns_query, url_host, referrer_host, host_header, sender_domain hoặc receiver_domain; không tự suy diễn domain đích nếu chỉ có URL path.
- Tần suất kết nối/truy vấn và hệ thống sinh log: endpoint, DNS, firewall, gateway, proxy, EDR.
- Process/command line nếu có.
- Rule intent: blacklist, TI, DNS query, C2, phishing, malware, **adware/riskware/PUA (Web Threat Protection, `not-a-virus:`)**, DGA, policy, blocklist.

Nếu observed domain không rõ, bị truncate, hoặc chỉ có IP -> `Need Enrichment`.

**Đánh giá Rule Intent Match:**
- **Rule bắt khi nào?** Domain bị gắn cờ do TI/blacklist (C2/phishing/malware/DGA) hay policy/blocklist; dựa reputation hay IoC detection.
- **Tại sao alert này phát sinh?** Domain quan sát + nguồn log (DNS/firewall/proxy/EDR) nào khớp điều kiện rule.
- **Rule Intent Match:** domain confirmed độc + có host nội bộ truy vấn → MATCH (điều tra kỹ); domain bị cờ chỉ vì lookalike/typo chưa có action cụ thể, hoặc blocklist sai → MISMATCH → nghiêng FP.
- **FP/TP scenario:** TP khi domain độc + endpoint/process truy vấn thật; FP khi truy vấn có lý do nghiệp vụ rõ.
- **Dữ liệu đủ chưa?** Thiếu domain chính xác / source host / process → Need Enrichment.

**Result:** `informational`

### Bước 2: Đánh giá domain trên VT/reputation/identity
Sử dụng exact observed domain:
- Kiểm tra **Community Score**: nhiều đánh giá đỏ làm tăng nghi ngờ; nhiều đánh giá xanh chỉ là supporting clean.
- Kiểm tra số lượng Security Vendor đánh dấu Red Flag: `>= 3` vendor -> nghi domain độc; `0 < vendor < 3` -> suspicious; `= 0` -> có thể clean nhưng chưa đủ nếu domain mới hoặc context suspicious.
- Kiểm tra **Creation Date** và **Last Analysis Date**: domain mới tạo hoặc LAD quá cũ làm giảm độ tin cậy của kết quả sạch.
- Kiểm tra **Popular Rank**: có popular rank là supporting clean; không có rank không tự động malicious.
- Tổ chức đăng ký/SSL uy tín là supporting clean; registrar/SSL thiếu tin cậy hoặc thiếu dữ liệu -> kiểm tra tiếp.
- Relations: IP resolved độc, hầu hết subdomain độc, hầu hết related files độc -> `malicious` hoặc `suspicious`.
- VT subdomains malicious-count (chỉ khi `_source_evidence`/relations có danh sách subdomain kèm malicious flag; thiếu -> ghi "subdomain evidence unavailable", không suy diễn): > 10 subdomain có malicious flag + pattern wildcard/random -> nghiêng DGA/C2 infra (`malicious`); nhiều subdomain sạch khớp pattern SaaS/CDN đã biết -> supporting clean.
- IP hosting/CDN shared nhiều domain không liên quan -> không tự động kết luận domain độc nếu chỉ dựa trên IP.
- Lookalike/typosquat brand, domain gần giống dịch vụ nổi tiếng, exact search gợi ý domain chuẩn khác -> `suspicious` hoặc `malicious` nếu có phishing/C2/page evidence.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 3: Đánh giá Google/search và browser behavior
Chỉ dùng text/page behavior có trong input:
- Báo cáo rõ domain là C2, malware, phishing, APT, blacklist campaign -> `malicious`.
- Báo cáo nhắc tới IOC nhưng không rõ chức năng -> `suspicious`.
- URL/domain chứa sẵn địa chỉ email người nhận hoặc đoạn **base64** trong URL -> phishing signal mạnh, ít nhất `suspicious`.
- Browser/Safe Browsing cảnh báo độc -> `malicious`.
- Fake login, credential collection, logo/brand không khớp domain, page generic "Trang đăng nhập", "Đổi mật khẩu", "Gia hạn dung lượng", "Email Zimbra", "Dịch vụ email" -> `malicious`.
- Nếu browser hiển thị `refused to connect`, `taking too long to respond`, không có nội dung hoặc không truy cập được: ghi rõ behavior; đây là suspicious/unknown, không tự động FP.
- URL download file: chưa kết luận benign; cần kiểm tra file được tải.
- **URL/path bị cờ (`url:{url}`):** nếu có enrichment `url:{url}` của URL bị cờ → PHẢI ghi rõ kết quả TRUY CẬP URL đó: `checked_url`, `final_url`, `browser_probe_status`/`nav_error`, và **nội dung/script quan sát được (`page_text`)** — RỒI mới đánh giá. Root domain/homepage sạch KHÔNG override URL/path bị cờ; KHÔNG kết luận về URL khi chưa có `url:{url}` browser_probe của chính URL đó (chỉ kiểm root domain ≠ đã kiểm URL). Nếu URL bị cờ là adware/riskware/script độc (vd AdWare/Pusher trên `/sw.js`) → `malicious` (xem rule 7b).
- Domain gốc/page chức năng hợp lệ, ownership rõ, exact observed domain verified -> có thể `clean`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 4: Kiểm tra endpoint/process truy vấn domain
Cần trả lời: tại sao thiết bị kết nối domain này?
- Browser truy vấn domain độc: có thể do extension, link phishing, web nhúng script; cần URL/referrer/timeline. Nếu domain confirmed malicious -> `suspicious`/`malicious` tùy click/download/login evidence.
- Process độc/riskware hoặc system process kết nối domain độc -> `malicious`.
- Process sạch/system process kết nối domain độc -> nghi inject, `suspicious`/`Need Enrichment` nếu thiếu process tree.
- Domain sạch + process sạch + nghiệp vụ rõ -> `clean`.
- Không có process trên endpoint mà domain confirmed malicious -> `Need Enrichment` nếu cần xác minh, không FP.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 5: Kiểm tra log DNS/gateway/firewall và tần suất
Nếu log source là DNS/firewall/gateway:
- Xác định source thực sự: source_ip, NAT, firewall forwarder, DNS recursive, proxy username.
- Nếu IP truy vấn là firewall/DNS, phải xác minh thiết bị phía sau. Không kết luận endpoint nhiễm nếu chỉ thấy IP firewall/DNS.
- Rất nhiều thiết bị truy vấn domain/top-level-domain uy tín với tần suất lớn từ trước đến nay và có business explanation -> có thể FP.
- Chỉ một host truy vấn đều gần đây hoặc bắt đầu gần thời điểm alert -> `suspicious`.
- Với domain malicious: tần suất lớn/outbound lặp lại -> nghi nhiễm mã độc/C2, `malicious`.
- DNS-fail-then-bad-IP sequence (chỉ khi SIEM output có timestamp có thứ tự cho `dns_query` + `destination_ip` + `firewall_action`; thiếu thứ tự -> ghi "event ordering unavailable", không suy diễn): DNS query fail/NXDOMAIN rồi NGAY (1-2s) kết nối tới IP có reputation độc = dấu hiệu DNS hijack / subdomain-takeover -> `malicious`.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 6: Tổng hợp và kết luận
Kết luận `True Positive` khi:
- Domain confirmed malicious/phishing/C2 và có endpoint/user/system truy vấn, đặc biệt có process/riskware/browser fake login/download.
- Domain malicious + process độc/không phù hợp/system process nghi inject.
- DNS/gateway cho thấy host cụ thể truy vấn domain malicious lặp lại.

Kết luận `False Positive` chỉ khi:
- Exact observed domain có evidence benign rõ.
- Nguyên nhân truy vấn phù hợp nghiệp vụ, process/log source rõ.
- Không có step malicious và rule intent mismatch hoặc blocklist sai.

Kết luận `Need Enrichment` khi:
- Domain reputation suspicious/unknown.
- Không biết source host thật do NAT/DNS/firewall.
- Domain malicious nhưng chưa lấy đủ process/timeline/referrer/deep log để xác định nguyên nhân.
- Browser truy vấn domain malicious nhưng thiếu URL/referrer/download/click evidence.

`Enrichment_Requests` phải yêu cầu: DNS/proxy/firewall log quanh thời điểm, source host behind NAT, EDR process tree, browser history/referrer, downloaded file hash, domain exact VT/detail/search evidence.

---

## Confidence guideline

| Confidence | Điều kiện |
|------------|-----------|
| 90-100 | Domain confirmed malicious/benign và source/process/nguyên nhân rõ |
| 80-89 | Domain/source rõ, thiếu một context phụ |
| 70-79 | < 80 → Need Enrichment (chưa đủ tin cho TP/FP) |
| 40-60 | Need Enrichment |

FP thiếu process/source host exact → Need Enrichment (không đạt sàn 80 — Shared Rule §"Verdict floor").
`Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

---

### YÊU CẦU ĐẦU RA

BẮT BUỘC trả về JSON thuần:

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Xác định thông tin cảnh báo và observed domain", "Detailed_Analysis": "- Evidence: thời điểm, rule, domain, source, tần suất, log source.\n- Rule intent: rule bắt domain reputation/phishing/C2 hay category nào.\n- Kết luận step: observed domain có khớp rule intent không.", "Result": "informational"},
    "Step_2": {"Step_Title": "Đánh giá domain reputation và identity", "Detailed_Analysis": "- Evidence: Community Score, VT, creation date, last analysis, popular rank, relations.\n- Missing/Conflict: ghi rõ nếu reputation/identity thiếu hoặc mâu thuẫn.\n- Kết luận step: exact domain identity/reputation hỗ trợ verdict nào. Bảng per-domain và IP-resolve (từng IOC + tỷ lệ VT) hiển thị tự động ở report — KHÔNG liệt kê từng IOC trong text, chỉ nêu kết luận + số liệu tổng.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_3": {"Step_Title": "Đánh giá search và browser behavior", "Detailed_Analysis": "- Evidence: Google text, page behavior, final_url, screenshot/page text nếu có.\n- Missing/Conflict: ghi rõ nav_error hoặc không có browser/search evidence.\n- Kết luận step: search/browser hỗ trợ malicious, clean hay unknown.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_4": {"Step_Title": "Kiểm tra endpoint/process truy vấn domain", "Detailed_Analysis": "- Evidence: process, command line, user, browser/referrer/download.\n- Missing/Conflict: ghi rõ khi thiếu endpoint/process context.\n- Kết luận step: truy vấn domain có nguyên nhân hợp lý hay đáng ngờ.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_5": {"Step_Title": "Kiểm tra DNS/gateway/firewall và tần suất", "Detailed_Analysis": "- Evidence: source thực, NAT/DNS/firewall caveat, frequency.\n- Missing/Conflict: ghi rõ khi chưa xác định được source thực hoặc scope.\n- Kết luận step: tần suất/phạm vi làm tăng hay giảm rủi ro.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_6": {"Step_Title": "Tổng hợp và kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các step quyết định TP/FP/NE.\n- Missing/Conflict: dữ liệu thiếu hoặc conflict còn ảnh hưởng confidence.\n- Kết luận step: lý do cuối cùng; historical context chỉ tham khảo KHI có thật (status≠none) — CẤM bịa 'N ticket lịch sử'.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Tóm tắt lý do kết luận"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["TP/NE: hành động chặn domain, điều tra host, query log nếu cần"],
  "Investigation_Requests": ["(Tùy chọn — domain chủ yếu quyết bằng reputation VT/Google/browser) chỉ emit khi reputation chưa đủ VÀ log giúp gỡ ambiguity (NAT source, DNS frequency): object {intent, why_raises_confidence, action, target_field=dns_query|source_ip|destination_ip|hostname, target_value, time_range_hours}"],
  "Enrichment_Requests": ["NE HOẶC Confidence < 90: thứ KHÔNG query SIEM được (reputation/OSINT còn thiếu, file hash, dữ liệu ngoài); log SIEM đặt ở Investigation_Requests; [] chỉ khi Confidence >= 90 và không phải NE"],
  "Close_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Close_Note; không viết liền một dòng.",
  "Escalate_Note": "JSON string multi-line, dùng \\n; sinh đúng mục Note Output Format - Escalate_Note; không viết liền một dòng."
}
```
