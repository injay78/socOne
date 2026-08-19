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
