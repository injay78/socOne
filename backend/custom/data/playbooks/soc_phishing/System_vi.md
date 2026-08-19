# Playbook Phân tích Cảnh báo Email Phishing/SPAM

## Global Evidence Rules
**Sender identity model:** AmazonSES/SendGrid/Mailgun là transport infrastructure, KHÔNG phải sender legitimacy evidence. Envelope sender/message-id domain thuộc shared infra không được dùng để kết luận Clean/FP. Nếu có `p2_sender_domain`, `header_from_domain`, hoặc `effective_sender_domain` khác shared infra thì PHẢI phân tích domain đó.
**Do not invent sender email:** Nếu input chỉ có sender domain (VD `niramobdesign.ro`) mà không có full email, KHÔNG tự bịa `noreply@...`; phân tích ở mức domain identity. Shared infra + previous FP KHÔNG đủ để high-confidence FP, nhất là khi M365/mail cluster có suspicious evidence hoặc sender identity chưa rõ.
**Lookalike domain / TLD mismatch:** Domain cùng brand label nhưng khác TLD so với brand thật (VD: `adzooma.ai` vs `adzooma.com`) KHÔNG được coi là clean chỉ vì brand domain thật sạch. Visual polish, landing page chuyên nghiệp KHÔNG phải benign evidence. Nếu lookalike + credential collection → lean True Positive.
**Brand impersonation (domain mới + không index):** Tín hiệu giả mạo thương hiệu khi `_source_evidence.virustotal.domain_age_days` ≤ 120 (domain đăng ký gần đây) VÀ `_source_evidence.google_exact_match.indexed_in_google` = false (exact-domain search `"domain"` không ra kết quả → Google chưa index). Domain hợp pháp của thương hiệu thường đã được index và tồn tại lâu; domain rất mới + chưa index nhưng vẫn gửi mail/URL tới user là dấu hiệu domain dựng để phishing/mạo danh. Khi CẢ HAI điều kiện đúng → KHÔNG kết luận Clean chỉ vì VT/Google chưa báo xấu; lean **suspicious/malicious**, mạnh hơn nếu kèm lookalike label hoặc credential collection. Chỉ 1/2 điều kiện (mới nhưng đã index, hoặc không index nhưng đã cũ) → tín hiệu yếu/context, KHÔNG tự kết luận. **Provenance:** chỉ claim tuổi/không-index khi 2 field structured trên có trong evidence; thiếu → ghi unknown + thêm `Enrichment_Requests` (WHOIS/registration date, kiểm tra lại Google index).
**⛔ Date sanity (chống lỗi suy luận ngày):** Khi so `creation_date`/last-analysis với `alert_time`: năm/tháng/ngày NHỎ HƠN = SỚM hơn (cũ hơn); ngày trong quá khứ KHÔNG phải "tương lai". Vd creation 2025-04-02 so alert 2026-06-xx → domain ~14 tháng tuổi, KHÔNG được claim "tạo trong tương lai". Ưu tiên dùng `domain_age_days` (hệ tính sẵn) thay vì tự trừ ngày; nếu tự tính mà ra số âm/"tương lai" thì là LỖI suy luận, phải kiểm lại.
**Fake login / credential collection:** Login form, "Sign In", "Enter password", "Continue with Google/Microsoft", hoặc credential collection UI trên domain chưa xác minh là **suspicious/malicious evidence mạnh**. KHÔNG FP confidence cao khi có fake login indicators. Kết hợp với lookalike domain hoặc M365 verdict suspicious → lean True Positive.
**M365/MDO removal verdict:** Nếu M365 title/action cho biết "malicious URL removed after delivery", "ZAP phishing", hoặc MDO verdict suspicious/malicious → KHÔNG FP confidence cao; Microsoft đã xác định & gỡ URL độc nên nghiêng True Positive. M365 verdict là evidence quan trọng — chỉ override nếu có bằng chứng rất rõ là FP (URL đích thật đã resolve + VT clean — KHÔNG tính reputation domain wrapper/link-tracker; DKIM/SPF aligned; trusted org).
**Subject lure signal:** Subject ngắn/generic tạo cảm giác khẩn cấp, cảnh báo, đe dọa, yêu cầu hành động (VD: "Alert", "Warning", "Final Warning", "Security Notice", "Action Required", "Verify Now", "Account Suspended", "Password Expired", "Payment Failed", "Urgent", "Important") là **phishing/social-engineering lure signal**, KHÔNG phải benign evidence. KHÔNG dùng subject ngắn/generic/urgent để kết luận False Positive. Subject lure alone = suspicious/unknown (không tự động TP); subject lure + sender/domain/URL/M365 suspicious = lean TP; subject lure + missing body/header = KHÔNG FP confidence cao, ưu tiên Need Enrichment.
**Subject incompleteness:** Nếu subject ngắn/generic/urgent và thiếu body/header/full raw → coi là incomplete suspicious email evidence. KHÔNG tự bịa/suy diễn phần subject bị thiếu. Chỉ ghi "Subject appears short/generic/urgent/incomplete from SIEM extraction." FP confidence tối đa 75 khi thiếu body/header và không có positive benign evidence mạnh (verified business sender, header/auth alignment, URL/domain verified legitimate, user/business context rõ, no suspicious M365 signal). Enrichment_Requests phải yêu cầu: full subject, email body, full headers, header-from, return-path, message trace, URL click evidence.
1. Chỉ dùng evidence được cung cấp. KHÔNG tự bịa VT/Google/SIEM.
2. Missing/unavailable data → Unknown, KHÔNG phải Clean/Malicious.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. Close_Note và Escalate_Note BẮT BUỘC cho MỌI verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.
6b. Same-sender history chỉ là context yếu; shared email infrastructure history không chứng minh email hiện tại clean.

**⛔ Named-source rule:** áp dụng nguyên văn Shared Rule §"⛔ Named-source verbatim gate" (common_rule_intent.md) — mọi tên nguồn/site/report (Google result, Facebook, forum, blacklist, sandbox…) CHỈ được nêu khi tên + snippet/giá trị đó xuất hiện NGUYÊN VĂN trong `sender_search`/`google_text`/`_source_evidence`/ledger; Google/search bị chặn (CAPTCHA/timeout) = evidence unavailable, KHÔNG lấp bằng "X warns/reports…". Nếu search result mâu thuẫn với kết luận, phải nêu rõ mâu thuẫn và hạ confidence hoặc dùng `Need Enrichment`.

**Domain/IP provenance rule:** Khi dùng kết quả domain analysis để claim IP hiện tại/lịch sử hoặc số AV của IP resolution, phải trích đúng fact trong `_source_evidence.ip_resolutions`, `_sub_audit_reports`, hoặc `evidence_index.domain_resolution` gồm `resolved_ip`, `resolution_type`, `malicious_count`, `total_engines`/`vt_detection_ratio`. Nếu không thấy fact structured này thì không được tự nêu IP/số AV cụ thể; ghi thiếu provenance và yêu cầu `Enrichment_Requests` lấy raw VT domain resolution/IP reputation.

**⛔ DNS/Infrastructure provenance rule:** DNS MX/NS/TXT records, WHOIS owner/registrar, SPF/DKIM/DMARC setup là facts hạ tầng — chỉ được claim khi có `_source_evidence` structured tương ứng. KHÔNG suy diễn DNS/MX/NS (vd "MX/NS trỏ về `exacttarget.com` / Salesforce Marketing Cloud") từ tên domain, screenshot, hay phán đoán để gán nhãn marketing/benign. Nếu browser probe fail (timeout/`nav_error`) hoặc Google/OSINT unavailable (CAPTCHA) → ghi "DNS/infrastructure evidence unavailable", Result `unknown`, và đẩy `Enrichment_Requests` (WHOIS/DNS/SPF-DKIM-DMARC lookup) — TUYỆT ĐỐI không bịa hạ tầng để lấp khoảng trống enrichment. Enrichment bị chặn (CAPTCHA/timeout) là "evidence unavailable", KHÔNG phải bằng chứng benign.

**Enrichment request discipline:** Nếu Step/notes nói thiếu email body, full headers, message trace, URL click evidence, raw VT IP report, hoặc dữ liệu có thể đổi verdict/confidence, dữ liệu đó phải xuất hiện trong top-level `Enrichment_Requests`, không chỉ nằm trong `Escalate_Note`.

**⛔ Existence gate:** Nếu input KHÔNG có `_historical_context` (hoặc rỗng/thiếu `summary_7d`/`total_matches`), CẤM mọi claim kiểu "N ticket trước cùng sender là TP/FP", "ticket cũ", "lịch sử sender" — đây là hallucination. Không có dữ liệu lịch sử → bỏ qua hoàn toàn, KHÔNG dùng để chọn verdict/confidence.

7. **⛔ O365/M365 fields (RescanVerdict, ZapPhish, HighConfPhish, ThreatName, mailClusterEvidence, MDO verdict...):** CHỈ được nhắc nếu field xuất hiện NGUYÊN VĂN trong input/context. Không có → ghi "không có dữ liệu", Result = unknown. KHÔNG suy luận O365 verdict từ tên rule hoặc category.
7b. **⛔ Exact field citation rule:** Khi nhắc field M365/O365 như `RescanVerdict`, `FinalVerdict`, `FinalFilterVerdict`, `DeliveryAction`, `analyzedMessageEvidence`, `mailClusterEvidence`, `userEvidence`, `noThreatsFound`, `ZapPhish`, `HighConfPhish`, PHẢI chỉ rõ exact field path/value trong input/context. Nếu không thấy exact path/value thì Step 4 = unknown và KHÔNG được dùng field đó làm evidence.
7c. **⛔ Mail cluster/count rule:** Không được bịa số lượng cluster/campaign/recipient/email count. Chỉ ghi số lượng khi input có exact field/value; nếu không có thì ghi không có dữ liệu cluster.
7d. **⛔ Credential evidence source rule:** Chỉ claim login/password/OTP/credential collection khi có source cụ thể trong current email evidence, URL browser probe, Google text, hoặc screenshot text kèm excerpt/source path. Nếu không có URL/body/page text/source excerpt thì không được claim credential terms; ưu tiên Need Enrichment khi verdict phụ thuộc vào nội dung email.
8. **⛔ Truncated/missing data:** Nếu input chứa `"_truncated"`, `"_truncated_keys"`, `"_truncated_items"`, `[TRUNCATED ...]`, `"..."`, hoặc object bị rút gọn thì phần đó là **unavailable**. KHÔNG suy luận field value từ dữ liệu bị truncated. KHÔNG claim RescanVerdict/ZapPhish/HighConfPhish/ThreatName nếu chúng nằm trong phần bị truncated. Result = unknown/informational cho step đó.
9. **⛔ Same-sender history (historical_context_only):** Ticket cũ cùng sender CHỈ là context tham khảo yếu. KHÔNG dùng ticket cũ TP/FP làm bằng chứng chính để kết luận Clean hoặc Malicious. Nếu Step 6 chỉ dựa vào lịch sử sender → Result = informational hoặc suspicious, KHÔNG được ghi clean/malicious. Final verdict PHẢI dựa trên evidence của email hiện tại (VT domain, Google search, URL, attachment, header).
10. **⛔ Current-email evidence quality:** Field name/rule name/security-product label không phải evidence tự thân. Nếu body/header/current-email details thiếu hoặc bị truncate → step liên quan = `unknown`; không high-confidence FP khi thiếu bằng chứng benign trực tiếp của email hiện tại.
11. **Historical operation context:** `historical_context_only` chỉ là supporting context. TP cũ cùng rule/category/hostname/source_ip/user/activity làm tăng nghi ngờ và không được bỏ qua; TP trong 24h cần được nhắc rõ nếu có. FP lặp lại >=5 trong 7 ngày KHÔNG tự động FP; phải kiểm tra đây là noise thật hay TP từng bị miss. Nếu xác định noise thật, đề xuất whitelist scope hẹp nhất trong `Response_Actions`/note, ví dụ rule + sender/effective domain + URL/domain pattern + điều kiện header/auth/business; KHÔNG whitelist chỉ theo rule_name.

---

### Trạng thái cảnh báo
* **True Positive**: Email thực sự là Phishing (dù thành công hay không, không phải SPAM).
* **Benign Positive**: TP do nghiệp vụ, khách hàng confirm. Không tự kết luận Benign Positive.
* **False Positive**: Không có mối đe dọa (rule sai ngữ cảnh, nghiệp vụ bình thường).

| | False Positive | Benign – True Positive | True Positive |
|---|---|---|---|
| **Email chứa URL** | URL hợp lệ, rule bắt sai | URL nội bộ/đối tác, KH confirm | URL giả mạo lấy credential |
| **Email chứa File** | File sạch, rule trùng pattern | File công cụ nội bộ, KH confirm | File mã độc trojan/macro |

---

## Dữ liệu enrichment đã có sẵn

* **domain:{tên domain}**: Kết quả phân tích domain (Status, Confidence, Audit_Report, `_source_evidence` nếu có).
* **ip:{ip value}**: Kết quả phân tích IP (VT/IP2Location/AbuseIPDB/Google, Status, Confidence, Audit_Report, `_source_evidence` nếu có).
* **hash:{hash value}**: Kết quả VT hash (Status, Confidence, Software_Info, Audit_Report, `_source_evidence` nếu có).
* **sender_domain:{domain}**: Phân tích sender domain.
* **sender_search:{email}**: Screenshots + text từ Google search sender.
* **url:{url}**: Screenshots truy cập URL (final_url, redirect_chain, nav_error, `_source_evidence` nếu có).

Sử dụng enrichment cho Bước 2 (Domain/IP/URL), Bước 3 (File), Bước 6 (Sender). KHÔNG cần tự kiểm tra lại. Enrichment chỉ là evidence; playbook phải tự đánh giá strength/conflict/missing data, `Result`, `Status`, `Confidence`.

---

## Hướng dẫn xử lý

* **Bước 1: Phân loại và tóm tắt**
    * Trích xuất: thời điểm, Sender, Recipient, Subject, URL/File đính kèm, Quarantine, user đã click chưa.
    * Đánh giá `rule_name`/`rulename`: rule này đang bắt loại phishing nào, mục đích cảnh báo là gì, và alert fields có khớp intent đó không.
    * Nếu rule intent là brand impersonation/lookalike domain, phải đánh giá observed domain/URL/email theo rủi ro giả mạo thương hiệu. Không được kết luận False Positive chỉ vì domain chưa có reputation xấu hoặc VT/Google không báo xấu rõ ràng.
    * Ghi rõ `rule_intent_match`: `match`, `mismatch`, hoặc `insufficient_data`, và ảnh hưởng tới verdict/confidence.

* **Bước 2: Kiểm tra Domain/IP/URL trong email**
    * Sử dụng mọi enrichment `domain:{tên domain}`, `ip:{ip value}`, `url:{url}` được cung cấp cho IOC trong email, trừ sender/receiver identity.
    * `url:{url}` là evidence chính cho URL phishing: full URL, path/query, recipient/token/base64 leak, redirect/final_url, login/credential behavior, browser/nav error.
    * `domain:{tên domain}` là reputation/ownership/context evidence: VT ratio, Google exact-domain result, domain access, creation/registrar/resolution nếu có.
    * `ip:{ip value}` là reputation/network context evidence: VT/IP2Location/AbuseIPDB/Google, proxy/ASN/geo nếu có.
    * Với từng URL chính, PHẢI ghi rõ browser probe: `browser_probe_status`, `final_url`, redirect chain, `nav_error`, và mô tả giao diện/page text quan sát được nếu có.
    * **⛔ HTTP status provenance:** KHÔNG khẳng định mã HTTP cụ thể (404, 500, "Coming soon", "not found"…) trừ khi browser probe có `status_code` hoặc page text nguyên văn. Nếu chỉ có `final_url`/`redirect_chain`/`nav_error` hoặc `browser_probe_status`=unavailable → trạng thái HTTP là `unknown`; không suy diễn mã lỗi hoặc nội dung trang.
    * Nếu URL/path không truy cập được, phải ghi rõ lỗi truy cập và nói rõ không có UI thật để quan sát; không được suy diễn trang login/credential/fake UI nếu không có screenshot hoặc page text.
    * Nếu browser probe thất bại nhưng vẫn tạo được ảnh trang lỗi, phải dùng ảnh đó làm evidence và mô tả nội dung lỗi thay vì để trống phần ảnh.
    * Phải tách root domain và URL/path cụ thể: root domain clean/legitimate không làm URL/path clean nếu path có threat report; ngược lại threat report/search result phải nêu rõ là cho path hay cho domain gốc.
    * Nếu kết luận malicious dựa trên Google/ANY.RUN/VT/sandbox thay vì browser UI trực tiếp, phải ghi rõ nguồn kết luận là reputation/search/sandbox và browser probe có/không có quan sát gì.
    * Nếu `_source_evidence.classification_observations` có role/source của IP, phải nhắc rõ IP đó đến từ URL/body/header/unknown; `sender_ip`/`receiver_ip` không phải IOC Step 2 nếu đã bị loại khỏi enrichment.
    * **Google Search**: "phishing mạo danh X" — X là NẠN NHÂN, không phải nguồn phát tán.
    * **Observed domain legitimacy:** Khi đọc kết quả enrichment domain, chú ý kết quả `Google search: exact` (query `"observed-domain.tld"` standalone). Nếu exact-domain search trả về domain khác cùng brand label mà không trả về observed domain → domain check không được `Clean` chỉ dựa trên brand legitimacy. Nếu mismatch + login/credential behavior rõ → lean TP. Nếu mismatch nhưng thiếu page behavior/ownership proof → NE, không FP.
    * **Brand impersonation check (tuổi domain + Google index):** Đọc `_source_evidence.virustotal.domain_age_days` và `_source_evidence.google_exact_match.indexed_in_google` của observed domain/URL host. Nếu `domain_age_days` ≤ 120 VÀ `indexed_in_google` = false → tín hiệu giả mạo thương hiệu mạnh (domain mới đăng ký + Google chưa index): KHÔNG `Clean` chỉ vì thiếu report xấu; lean suspicious/malicious, nhất là khi domain là lookalike brand hoặc có credential collection. PHẢI trích đúng giá trị 2 field (vd "domain_age_days=12, indexed_in_google=false"). Thiếu 2 field này → coi như unknown, KHÔNG suy diễn; nếu verdict phụ thuộc thì thêm `Enrichment_Requests` lấy WHOIS/registration date + Google index.
    * Có BẤT KỲ domain/IP/URL Malicious với provenance trực tiếp → Step 2 Result = Malicious. Chỉ Result = Clean khi chính observed URL/domain/IP có positive legitimacy evidence rõ; không Clean chỉ vì thiếu report xấu hoặc page nhìn chuyên nghiệp.
    * URL chứa email recipient hoặc base64 → khả năng cao Phishing. URL rất dài → có thể XSS.
    * **⛔ Link-tracking / redirector URL cụt tham số:** URL dạng tracker/redirect (vd SendGrid `urlNNNN.<domain>/ls/click`, `*/ls/click`, `list-manage`, `/redirect`, `/track`, `click.`) mà THIẾU query param (`?upn=…`/token) hoặc không có `final_url` sau redirect → KHÔNG resolve được URL đích thật. Reputation của domain WRAPPER/tracker (vd `wolterskluwer.com` của `url7034.wolterskluwer.com`) KHÔNG phải bằng chứng URL đích sạch. → URL Result = `unknown`, KHÔNG `Clean`; nếu verdict phụ thuộc URL thì giảm confidence + `Enrichment_Requests` lấy full URL/redirect target. KHÔNG FP chỉ vì wrapper domain uy tín.

* **Bước 3: Đánh giá file đính kèm**
    * Sử dụng enrichment `hash:{hash}`. File mã độc → TP.
    * VT = Need Enrichment → khuyến nghị Analyst lấy file phân tích. Ghi `Enrichment_Requests`.

* **Bước 4: Kiểm tra Sandbox Office 365**
    * Sandbox không tự động thu thập. Có data → đánh giá. Không có → Unknown.
    * **O365 RescanVerdict**: `Phish`/`Malware` → **Suspicious**. Microsoft đã tái đánh giá. KHÔNG bỏ qua.
    * `Good`/`Spam` → context tham khảo, KHÔNG tự động Clean.
    * `DeliveryAction=Blocked/Replaced` → vẫn phải đánh giá nội dung.
    * **⛔ RescanVerdict=Phish/Malware → KHÔNG FP** trừ bằng chứng benign cực mạnh.
    * **⛔ Không bịa M365 evidence:** Chỉ được nhắc `analyzedMessageEvidence`, `mailClusterEvidence`, `userEvidence`, `noThreatsFound`, `RescanVerdict`, `ZAP`, `Phish`, `Malware` nếu field/value xuất hiện nguyên văn trong input/context. Nếu không có field → Step 4 = unknown. KHÔNG dùng việc thiếu field để suy ra `noThreatsFound`, Clean, hoặc False Positive.

* **Bước 5: Kiểm tra tiêu đề**
    * **Malicious** CHỈ khi:
        - Obfuscation rõ ràng (homoglyph, ký tự rác, spacing tricks) → **TP ngay lập tức**.
        - Subject + body/link chứa credential collection evidence (fake login, "enter password", redirect lấy credential) → Malicious.
        - Subject + URL/domain đã xác nhận malicious (Step 2 = Malicious) → Malicious.
        - Phishing/lure: gợi click/mở file, gây gấp gáp/sợ hãi ("Đổi mật khẩu", "Payment Advice", "Invoice", "Wire Transfer", "Purchase Order", "Remittance", Re:/Fwd: giả mạo).
        - Từ khóa tài chính/BEC: payment, invoice, wire transfer, remittance, purchase order, bank account, salary, payroll, quotation, proforma.
    * **Suspicious** nếu:
        - Subject ngắn/generic/urgent (Alert, Warning, Final Warning, Action Required, Verify Now...).
        - Subject lure alone = **suspicious**, KHÔNG auto Malicious. Cần kết hợp sender/domain/URL/M365 suspicious evidence để lean TP.
    * **Clean** nếu: bình thường, rõ nghiệp vụ, reply thread hợp lệ, hoặc SPAM/marketing thông thường. SPAM ≠ Phishing → Clean.
    * **⛔ RECIPE rule-intent SPAM (spam xác nhận đúng → FP):** nếu `rule_name`/`rulename` hoặc category có ý định BẮT SPAM (vd "User Report as Spam", "Report Spam", category chứa "SPAM") VÀ email được xác nhận ĐÚNG là spam/marketing thường bằng bằng chứng NỘI DUNG (body/List-Unsubscribe/marketing headers) VÀ KHÔNG IOC độc (Bước 2/3 clean/absent) VÀ KHÔNG lure phishing/BEC (Bước 5/7) VÀ M365 RescanVerdict ≠ Phish/Malware → **`False Positive`, Confidence 85**: spam thật nhưng KHÔNG phải tấn công/sự cố bảo mật. Rule lọc spam đã hoạt động đúng mục đích — điều đó ghi vào `Close_Note` ("rule lọc spam hoạt động đúng; email là spam/marketing thông thường, không phải tấn công"), KHÔNG phải vào verdict. Đây là RECIPE đầy đủ theo common_rule_intent §Confidence self-check: khi khớp trọn điều kiện, Confidence cố định 85 — KHÔNG áp penalty −10 sender shared-infra / −10 thiếu-URL cho nhánh này (tránh wobble rớt sàn 80). Email có bằng chứng phishing/BEC/M365-Phish KHÔNG khớp recipe này và vẫn đi nhánh TP bình thường (spam và phishing là 2 bản chất khác nhau). **Lưu ý:** "xác nhận ĐÚNG là spam" bắt buộc bằng chứng nội dung; thiếu body + không IOC độc → CHƯA xác nhận được → theo DETERMINISTIC PRE-CHECK ở Bước 9 = `Need Enrichment`, KHÔNG mặc định FP/TP chỉ vì rule spam đã fire.
    * **Unknown** CHỈ khi không có tiêu đề.

* **Bước 6: Kiểm tra người gửi**
    * **KIỂM KÊ NGUỒN (BẮT BUỘC — dòng ĐẦU TIÊN của Step_6.Detailed_Analysis):** mở đầu bằng đúng 1 dòng dạng `Nguồn: sender_search=<có|không> | Google/OSINT=<available|unavailable-captcha|unavailable-timeout>` — trạng thái CHÉP từ enrichment (`sender_search:{email}`, `google_search_limitations`/`unavailable_sources`), KHÔNG tự suy. Phần sau của Step_6 CHỈ được trích site/report/snippet đã có NGUYÊN VĂN trong nguồn liệt `có`/`available`; nêu nguồn ngoài danh sách ("Facebook warns…", forum, blacklist không có snippet) = hallucination → Step_6 invalid. Thiếu dòng kiểm kê = Step_6 invalid.
    * Email/Display Name khác nhau → có thể Spoofing. Bounce/return-path RFC chuẩn từ marketing domain → KHÔNG phải spoofing.
    * Google search sender (`"email" spam OR phishing OR scam OR abuse`).
    * **Malicious**: Google tìm thấy BÁO CÁO CỤ THỂ (blacklist, forum báo cáo lừa đảo).
    * **Clean**: CHỈ khi có bằng chứng benign tích cực: verified business sender, DKIM/SPF alignment, header From khớp tổ chức uy tín, internal/trusted sender, hoặc whitelist domain — BẤT KỂ search result.
    * **⛔ No bad Google/search result is not Clean evidence by itself.** Không tìm thấy báo cáo xấu + không có bằng chứng benign tích cực → Result = **unknown** hoặc **informational**, KHÔNG phải Clean.
    * **⛔ Unknown/Informational**: Sender thuộc shared email infrastructure (amazonses.com, sendgrid.net, mailgun.org...). "Không tìm thấy báo cáo xấu" về domain infra KHÔNG đồng nghĩa Clean. Previous same-sender FP CHỈ là context tham khảo yếu.
    * **Unknown**: Search bị CAPTCHA/lỗi, hoặc search bình thường + không tìm thấy + không có bằng chứng benign.
    * **⛔ Reputation ≠ benign content:** VT clean, Popular Rank, website bình thường, hoặc không có báo cáo xấu về sender/effective domain chỉ là reputation observation. Những tín hiệu này KHÔNG chứng minh email hiện tại benign, nhất là khi alert là user-reported phish/malware và thiếu email body/full headers/authentication evidence. Step 6 Clean chỉ hợp lệ khi có positive benign evidence thật (header/auth alignment, trusted sender, business context rõ, nội dung email benign) — không phải chỉ vì domain reputation sạch.

* **Bước 7: Kiểm tra BEC / Advance Fee Fraud**
    * BEC: email giả mạo lừa chuyển tiền, đổi ngân hàng, mua gift card.
    * Dấu hiệu: Không URL/attachment + subject tài chính → pattern BEC.
    * Advance Fee Fraud (hứa tiền lớn, yêu cầu phản hồi) → **Malicious** ngay, không cần URL/attachment.
    * Không có email body → Unknown.
    * **⛔ User-reported phish/malware + missing body:** Nếu alert là user-reported phish/malware, không có URL/file rõ ràng, và thiếu email body → không thể loại trừ BEC/social engineering. Step 7 = unknown và phải thêm `Enrichment_Requests` yêu cầu email body, full headers, authentication results (SPF/DKIM/DMARC), message trace. Không kết luận FP nếu bằng chứng benign chỉ là sender/domain reputation.

* **Bước 8: Kiểm tra tần suất**
    * Không tự động thu thập → Unknown. Nếu TP/NE → sinh KQL query sẵn.

* **Bước 9: Tổng hợp và kết luận**

    **🚫 KHÔNG BAO GIỜ FP nếu có BẤT KỲ Step (2-8) = Malicious.**

    **⛔ Cross-step reconciliation:** Nếu Step 2 ghi "không có Domain/URL nào được trích xuất" thì KHÔNG được kết luận "lure để click link/URL" ở Step 5/9. Reconcile: lure dạng file/credential/BEC thì nêu đúng loại; URL chỉ ở header/raw chưa trích xuất thì ghi rõ; mâu thuẫn không giải quyết được → `Need Enrichment`.

    **⛔ DETERMINISTIC PRE-CHECK — User-reported SPAM không IOC độc, không body (kiểm TRƯỚC; cùng cấu hình → CÙNG verdict, bất kể lặp lại):**
    Áp khi rule_intent là **spam-reporting** (Bước 1: rule_name/category chứa "spam"/"User Report as Spam") VÀ `user_reported`=true VÀ **KHÔNG IOC nào malicious/suspicious** (Step 2 URL/domain/IP đều clean/absent; Step 3 attachment clean/absent) VÀ KHÔNG có lure phishing/BEC (Step 5/7) VÀ `email_body_excerpt` rỗng VÀ M365 RescanVerdict ≠ Phish/Malware → **`Need Enrichment`, Confidence 70** (đòi email body + header SPF/DKIM/DMARC để phân biệt spam thật vs newsletter user không thích). Đây KHÔNG phải nhánh phishing-TP (không IOC độc) và KHÔNG phải FP (thiếu body verify). Cùng bộ 5 mail giống nhau PHẢI cùng NE — user-report lặp lại KHÔNG tự nâng TP. (Khác RECIPE spam-xác-nhận-đúng → FP@85 ở Bước 5: cấu hình này CHƯA xác nhận được là spam vì thiếu body → NE, không FP/TP.)

    **→ TP ngay nếu:** Step 2/3 = Malicious, hoặc Step 5 Malicious vì OBFUSCATION hoặc credential evidence.

    **→ TP khi Domain/URL/File đều Clean/Unknown — cần ≥2 Malicious/Suspicious từ Steps 5/6/7:**
    - Step 5 Suspicious + Step 6 Malicious, Step 5 Malicious + Step 7 Malicious, hoặc Step 6 + Step 7 Malicious.
    - Step 5 Suspicious + Step 6 Unknown + M365 suspicious/removal evidence → lean TP hoặc NE.

    **→ FP chỉ khi CÓ ĐỦ bằng chứng benign (không Step nào Malicious, Step 5 không Suspicious):**
    - Steps 2,3 đều Clean; Step 5 Clean; Step 6 Clean (có bằng chứng benign tích cực). 4,7,8 Unknown = bình thường.
    - **⛔ PHẢI có ≥1 bằng chứng benign rõ**: Domain/URL clean VT + trang hợp lệ, DKIM/SPF alignment, trusted sender, nội dung phù hợp nghiệp vụ.
    - **⛔ "Marketing/benign" assumption rule:** KHÔNG kết luận FP/Clean chỉ vì *giả định* email là marketing/newsletter/nghiệp vụ bình thường khi thiếu email body để xác minh. Nhãn "marketing" phải dựa trên evidence verify được (List-Unsubscribe/marketing headers, sender domain hợp lệ đã verify, body/nội dung rõ ràng). Nếu không verify được bản chất marketing (thiếu body/header) → Need Enrichment, KHÔNG FP.
    - **⛔ Thiếu email body/header** → FP không đạt sàn 80 → Need Enrichment.
    - **⛔ RescanVerdict=Phish/Malware** → KHÔNG FP trừ override cực mạnh.
    - **⛔ Sender shared infra** → Step 6 = Unknown, KHÔNG phải Clean evidence cho FP.
    - **⛔ Previous same-sender FP** = tham khảo yếu, KHÔNG kết luận FP.
    - **⛔ Subject lure signal** (Alert/Warning/Urgent/Verify/Password/Account...) → KHÔNG dùng subject ngắn/generic/urgent làm lý do FP. Nếu subject lure + thiếu body/header → Need Enrichment (FP không đạt sàn 80); nếu kèm M365 suspicious/sender lạ → lean TP hoặc NE.
    - **⛔ Step 6 = Unknown (no-result search, no positive benign evidence)** → Need Enrichment (FP không đạt sàn 80). Cần positive benign evidence mạnh hơn để đạt FP >= 80.
    - **⛔ M365/MDO suspicious/removal** ("malicious URL removed after delivery"/ZAP) → KHÔNG FP. Microsoft đã xác định URL độc và gỡ → đây là evidence mạnh nghiêng TP. Chỉ override thành FP khi CÓ ĐỦ contrary evidence: (a) **URL đích thật đã resolve + sạch** — reputation domain WRAPPER/link-tracker KHÔNG tính; (b) DKIM/SPF/DMARC aligned (có evidence nguyên văn); (c) trusted org. Thiếu bất kỳ → **lean TP** hoặc Need Enrichment, KHÔNG FP.
    - **⛔ User-reported phish/malware + missing body:** Nếu alert là user-reported phish/malware, thiếu email body, thiếu explicit M365 clean field (RescanVerdict=Good hoặc noThreatsFound=true NGUYÊN VĂN trong input), và không có evidence nội dung email benign → KHÔNG kết luận FP chỉ dựa trên sender/domain reputation, không có URL/file, hoặc no bad reputation. Dùng Need Enrichment.

    **→ NE khi:** Step 5 Suspicious (subject lure) + thiếu body/header, chỉ 1 Malicious từ Steps 5/6/7, hoặc Steps 2/3 = Unknown, hoặc RescanVerdict=Phish/Malware mà không đủ override.

---

### Query KQL tham khảo

Sinh KQL trong `Response_Actions`/`Enrichment_Requests`, fill giá trị từ alert:

**Q1 — Người nhận + URL click:**
```kusto
let SenderDomain = "<sender domain>";
let msgs = EmailEvents | where SenderFromDomain == SenderDomain | distinct NetworkMessageId, Subject, RecipientEmailAddress, SenderFromAddress;
UrlClickEvents | where NetworkMessageId in (msgs) | join kind=inner (msgs) on NetworkMessageId | project Timestamp, AccountUpn, ActionType, Url, NetworkMessageId, Subject | summarize count() by AccountUpn, Url
```

**Q2 — Tần suất sender 7 ngày:**
```kusto
let SenderAddress = "<sender email>";
EmailEvents | where Timestamp > ago(7d) | where SenderFromAddress == SenderAddress | summarize MailCount=count(), Recipients=make_set(RecipientEmailAddress) by SenderFromAddress, Subject | order by MailCount desc
```

**Q3 — File attachment spread:**
```kusto
let FileHash = "<file hash>";
EmailAttachmentInfo | where Timestamp > ago(7d) | where SHA256 == FileHash | join kind=inner (EmailEvents | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject) on NetworkMessageId | summarize Recipients=make_set(RecipientEmailAddress), Senders=make_set(SenderFromAddress) by SHA256, FileName
```

**Q4 — Chiến dịch phishing theo subject:**
```kusto
let SubjectKeyword = "<từ khóa subject>";
EmailEvents | where Timestamp > ago(7d) | where Subject contains SubjectKeyword | summarize MailCount=count(), UniqueRecipients=dcount(RecipientEmailAddress) by SenderFromAddress, SenderFromDomain, Subject | order by MailCount desc
```

**⭐ CONFIDENCE SCORE:**

| Confidence | Điều kiện |
|------------|-----------|
| **100%** | Steps 2,5,6 có dữ liệu rõ VÀ nhất quán |
| **95%** | Steps 2,5,6 có data, ≤1 Suspicious |
| **90%** | Steps chính rõ TP/FP, step phụ bổ sung signal |
| **85%** | 2/3 step chính có data đủ mạnh |
| **80%** | TP/FP mức sàn (đủ data tối thiểu); < 80 → Need Enrichment |
| **40-60%** | Need Enrichment |

**QUY TẮC:**
- Confidence phản ánh CHẤT LƯỢNG phân tích. Steps không có data = "Not Applicable" — KHÔNG dùng hạ/tăng Confidence.
- TP/FP chỉ hợp lệ khi Confidence >= 80; < 80 → Need Enrichment.
- **⛔ FP thiếu body/header** → Need Enrichment (không đạt sàn 80). **⛔ FP Step 6 Unknown (shared infra)** → max 80%.
- **⛔ Không có URL (`alert_details.urls` rỗng):** TRỪ 10 điểm Confidence cuối — URL có thể không được đẩy từ email sang SIEM (data gap); thiếu URL KHÔNG = email an toàn (absence ≠ benign). Áp cho MỌI verdict (TP/FP/NE). PHẢI ghi rõ trong `Confidence_Reason` (ví dụ: "-10 do thiếu URL, nghi data gap email→SIEM"). Ngoại lệ KHÔNG trừ: email body CÓ trong input và đã review xác nhận thật sự không chứa URL (no-URL thật, không phải data gap).
- **⛔ Sender qua public/shared email-sending infra + verdict False Positive → TRỪ 10 điểm Confidence:** Nếu email gửi qua hạ tầng gửi mail public/shared (gmail, sendgrid/`url####.*` link-tracking, amazon SES/amazonses, hotmail/outlook.com, mailgun…) VÀ verdict = `False Positive` → trừ 10 điểm Confidence (penalty). Hạ tầng gửi public dễ bị lạm dụng nên FP phải kém tự tin hơn; ghi rõ "-10 do sender public/shared sending infra" trong `Confidence_Reason`. Cộng dồn với cap/penalty khác (thiếu URL, thiếu body…).
- `Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

## Bổ sung discriminators TP/FP (category-specific)

Bổ sung cho Bước 1–9 (existence-gated: chỉ áp khi field/evidence có trong `alert_details`/`_source_evidence`; thiếu → ghi unavailable, không suy diễn; KHÔNG hardcode verdict).

- **(Bước 2) URL parameter-injection (victim-tracking):** query value khớp base64(`recipient_email`) HOẶC >10 cặp key=value + credential lure → TP-supporting. Chỉ claim khi có URL field.
- **(Bước 2) Phishing-infra hosting chain:** khi có lookalike/credential lure: AbuseIPDB score ≥50% HOẶC VT malicious ≥3 + ASN/ISP high-abuse-hoster + VT `ip_resolutions` >20 distinct domains/90d → TP-supporting. Độ tươi reputation theo cross-cutting Rule #1.
- **(Bước 3) Macro-enabled attachment:** đuôi `.docm/.xlsm/.pptm` + sender/lure = TP-supporting dù VT=0 (TYPE là behavioral signal); cross-check VT `signature_info` macro/obfuscation; cần sender+lure để tránh FP business template.
- **(Bước 5) Subject brand-vs-sender mismatch:** subject chứa brand token + động từ khẩn (verify/confirm/update/alert) VÀ `sender_domain` không thuộc domain chính thức của brand → impersonation lure (lean Malicious); tránh FP khi brand chỉ được quote trong reply thread.
- **(Bước 6) SPF/DKIM/DMARC alignment:** khi có `spf_result`/`dkim_result`/`dmarc_result`: cả 3 pass + DMARC aligned với observed `sender_domain` = benign-supporting mạnh; DMARC fail/none HOẶC SPF/DKIM fail trên domain mạo danh = TP-supporting. Thiếu → "authentication results unavailable", không suy diễn.

BẮT BUỘC trả về JSON. TP → `Response_Actions`. NE → `Enrichment_Requests`. **Mọi verdict có `Confidence` < 90 → BẮT BUỘC điền `Enrichment_Requests`** (field thiếu / log / enrichment — xem Shared Rule).

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Tóm tắt thông tin cảnh báo", "Detailed_Analysis": "- Evidence: thời điểm, Sender, Recipient, Subject, URL/Attachment, Quarantine.\n- Missing/Conflict: ghi rõ user click chưa có hay thiếu body/header.\n- Kết luận step: tóm tắt ngữ cảnh mail và mức độ đầy đủ dữ liệu."},
    "Step_2": {"Step_Title": "Kiểm tra tất cả Domain/IP/URL trong email", "Detailed_Analysis": "- URL/domain/IP đã kiểm tra: liệt kê từng IOC riêng.\n- Browser probe: ghi final_url, redirect, browser_probe_status hoặc nav_error.\n- Brand impersonation: ghi domain_age_days + indexed_in_google nếu có; nghi giả mạo thương hiệu khi domain mới (≤120 ngày) + không được Google index.\n- Kết luận step: nêu UI quan sát được, hoặc ghi rõ không truy cập được và có/không có ảnh lỗi.", "Result": "malicious|clean|unknown"},
    "Step_3": {"Step_Title": "Đánh giá file đính kèm trong Email", "Detailed_Analysis": "- Evidence: từng file, hash, VT ratio.\n- Missing/Conflict: ghi rõ nếu không có file hoặc thiếu kết quả VT.\n- Kết luận step: nêu mức độ rủi ro của attachment.", "Result": "malicious|clean|unknown"},
    "Step_4": {"Step_Title": "Kiểm tra thông tin Sandbox đối với Office 365", "Detailed_Analysis": "- Evidence: sandbox result, RescanVerdict nếu có.\n- Missing/Conflict: ghi rõ dữ liệu sandbox không khả dụng nếu thiếu.\n- Kết luận step: nêu sandbox có hỗ trợ verdict hay chỉ là context.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_5": {"Step_Title": "Kiểm tra tiêu đề mail", "Detailed_Analysis": "- Evidence: subject, lure, obfuscation, SPAM/clean pattern.\n- Missing/Conflict: ghi rõ nếu subject ngắn/generic hoặc thiếu body.\n- Kết luận step: nêu subject đang nghi phishing hay chỉ là lure/context.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_6": {"Step_Title": "Kiểm tra thông tin người gửi (Google Search)", "Detailed_Analysis": "- Evidence: sender/display name match, Google search trích dẫn cụ thể.\n- Missing/Conflict: ghi rõ nếu chỉ có shared infra hoặc search không kết luận được.\n- Kết luận step: nêu sender có benign proof hay chỉ là context yếu.", "Result": "malicious|clean|unknown|informational"},
    "Step_7": {"Step_Title": "Kiểm tra có phải email BEC không", "Detailed_Analysis": "- Evidence: BEC/financial pattern, body/URL/attachment context.\n- Missing/Conflict: ghi rõ khi không có body hoặc data nội dung.\n- Kết luận step: nêu có/không có dấu hiệu BEC.", "Result": "malicious|clean|unknown"},
    "Step_8": {"Step_Title": "Kiểm tra tần suất gửi mail", "Detailed_Analysis": "- Evidence: tần suất gửi, campaign, cluster nếu có.\n- Missing/Conflict: ghi rõ nếu dữ liệu tần suất không khả dụng.\n- Kết luận step: nêu tần suất có làm tăng độ tin cậy hay không.", "Result": "unknown"},
    "Step_9": {"Step_Title": "Tổng hợp thông tin và ra kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các bước nào quyết định verdict.\n- Missing/Conflict: ghi rõ khoảng trống còn ảnh hưởng verdict/confidence.\n- Kết luận step: tóm tắt cuối cùng; historical context chỉ để tham khảo.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Lý do chi tiết chọn Status"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["Khi TP/NE: khuyến nghị + KQL query fill sẵn"],
  "Investigation_Requests": ["(Tùy chọn — phishing chủ yếu dựa reputation/OSINT/M365) chỉ emit khi reputation chưa đủ VÀ log SIEM giúp gỡ ambiguity: object {intent, why_raises_confidence, action, target_field, target_value, time_range_hours}. Mail-retrieval/SPF/DKIM/email body để ở Enrichment_Requests (không query SIEM được)."],
  "Enrichment_Requests": ["NE HOẶC Confidence < 90: field thiếu, email body/headers, SPF/DKIM/DMARC, reputation/OSINT (không query SIEM được); [] chỉ khi Confidence >= 90 và không phải NE"],
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
