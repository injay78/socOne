# Playbook Phân tích Xác thực bất thường từ Public

## Global Evidence Rules
1. Chỉ dùng evidence được cung cấp. Không tự bịa IP reputation, geo, MFA status, user confirmation, sign-in history.
2. Missing/unavailable/truncated data là `unknown`, KHÔNG phải `clean` hoặc `malicious`.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. `Close_Note` và `Escalate_Note` BẮT BUỘC cho mọi verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.

## Category discipline


**Named-source evidence rule:** Chỉ claim tên nguồn cụ thể như ThreatFox, SOC Defenders, GreenSnow, ciarmy/GitHub, Zedmos, GreyNoise, LevelBlue, AbuseIPDB, VirusTotal, CleanTalk, Turris Sentinel, vendor blog, sandbox report hoặc security report khi đúng tên nguồn/snippet xuất hiện trong `_source_evidence`, `_sub_audit_reports`, `google_search_results`, `google_text`, `_evidence_context` hoặc `evidence_index`. Nếu chỉ có một nguồn trong evidence thì chỉ nêu nguồn đó; không tự thêm nguồn khác. Nếu search result mâu thuẫn với kết luận, phải nêu mâu thuẫn và hạ confidence hoặc dùng `Need Enrichment`.

**Enrichment request discipline:** Nếu phân tích/Confidence_Reason/notes nói thiếu sign-in logs, MFA details, device/user agent, baseline, approved VPN/travel/corporate context, xác minh hành vi đăng nhập với người dùng/khách hàng, follow-on mail/cloud/account logs hoặc IP enrichment, dữ liệu đó phải xuất hiện trong top-level `Enrichment_Requests`, không chỉ viết trong `Escalate_Note`. ⛔ TRỪ field đã bị **GATE 0 Source-capability** loại (MFA/conditional-access/device cho nguồn `sshd`/PAM) và baseline khi `environment_prevalence.identity_baseline` đã có trong payload — những thứ này KHÔNG được coi là "thiếu" và KHÔNG đưa vào `Enrichment_Requests`.

**Response action discipline:** `Response_Actions` phải bám hai phần chính của playbook là `## Hướng dẫn xử lý` và `### Phản ứng`. Mỗi phần tử trong `Response_Actions` sẽ được render thành một mục trong ordered list HTML, nên KHÔNG bắt đầu item bằng dấu `-`, số thứ tự, hoặc nhúng bullet/newline trong cùng một string. Với `True Positive`, KHÔNG mở đầu bằng action xác minh approval/hành vi hợp lệ với user/admin; phải đi thẳng vào phản ứng nguy cơ và điều tra sau đăng nhập:
1. Chặn IP theo chính sách phản ứng khi IP nước ngoài/IP độc/tần suất cao.
2. Revoke/expire tất cả sessions hiện tại của tài khoản nếu có login success/password success + MFA fail.
3. Yêu cầu user đổi mật khẩu và kiểm tra/bật MFA phù hợp nếu có login success/password success + MFA fail.
4. Kiểm tra follow-on logs, mail forwarding rules, OAuth consent và hoạt động cloud/account sau đăng nhập.
Chỉ dùng action xác minh user/customer/admin cho `Need Enrichment`, IP Việt Nam/ISP lớn/nguồn có thể hợp lệ, hoặc trường hợp thật sự thiếu dữ liệu để phân biệt approved activity với bất thường. Các action kiểm tra kỹ thuật như follow-on logs, MFA details, mail forwarding rules, OAuth consent có thể là item riêng khi đó là bước điều tra độc lập.

Với action xác minh trong các trường hợp KHÔNG thuộc TP trực tiếp, phải nêu cụ thể đối tượng, user, IP, thời điểm, app/service/client ID, thiết bị hoặc hệ thống cần xác minh; không viết chung chung kiểu "xác minh với admin". Ví dụ hợp lệ:
1. `Xác minh: Khách hàng/Admin xác nhận IP <source_ip> có phải là IP hợp lệ của developer hoặc server được phép truy cập vào user '<username>' trên thiết bị/dịch vụ <service/device> hay không.`
2. `Nếu xác nhận hợp lệ và không có follow-on suspicious: Close cảnh báo theo approved activity/baseline.`
3. `Nếu không xác nhận, không có approved context, hoặc có follow-on suspicious: Xử lý như nghi ngờ compromise: revoke SSH keys/token của user <username>, kiểm tra commit/thay đổi repository bất thường, kiểm tra auth logs/follow-on activity, và chặn IP <source_ip> nếu phù hợp.`
4. `Xác minh: Liên hệ user <username> hoặc quản trị viên để xác nhận tại thời điểm <alert_time>, user có sử dụng ứng dụng mới hoặc cấp quyền cho ứng dụng có ClientAppId <client_app_id> truy cập mail hay không.`
5. `Nếu xác nhận hợp lệ và không có follow-on suspicious: Đóng cảnh báo là False Positive theo approved activity.`
6. `Nếu không xác nhận, không có approved context, hoặc có follow-on suspicious: Xử lý như nghi ngờ compromise: revoke tất cả sessions, yêu cầu đổi mật khẩu mạnh tối thiểu 8 ký tự gồm chữ hoa, chữ thường, số và ký tự đặc biệt, kiểm tra/bật MFA phù hợp, rà soát mail forwarding rules và OAuth consent của tài khoản, kiểm tra follow-on mail/cloud logs, chặn IP nếu phát hiện dấu hiệu tấn công diện rộng.`


**Language:** Headings/section labels luôn English; JSON keys/enums giữ English. Nội dung note viết tiếng Việt. Không nhắc backend/hệ thống sinh nội dung/endpoint nội bộ.

7. **Unavailable/truncated data:** Nếu input chứa `"_truncated"`, `status: unavailable`, `no_data`, hoặc object bị rút gọn thì phần đó là **unavailable** — KHÔNG được suy luận dữ liệu từ source đó. **VT/AbuseIPDB/IP2Location:** chỉ ghi score, country, ISP, proxy, abuse_confidence nếu field/source object CÓ THẬT trong input; AbuseIPDB disabled/missing -> KHÔNG suy luận abuse score; IP2Location unavailable -> KHÔNG suy luận country/ISP/proxy; KHÔNG suy luận sign-in/MFA values từ dữ liệu bị truncated. Enrichment unavailable/no_data KHÔNG được tăng confidence.
8. **GeoIP/datacenter/ISP chỉ là context, KHÔNG tự kết luận malicious hoặc False Positive.**
10. `Close_Note` Action/Closed Reason chỉ được nêu "đã kiểm tra VT/AbuseIPDB/IP2Location/Google" hoặc kết quả sạch/xấu khi `_sub_audit_reports`, `_source_evidence`, hoặc evidence index có factual fields tương ứng. Nếu không có, chỉ nói đã kiểm tra sign-in context từ alert và ghi IP reputation unavailable/unknown.
11. **IP reputation rule:** IP malicious với evidence mạnh như AbuseIPDB high score + nhiều reports, VT nhiều vendor malicious, threat intel rõ, hoặc kết quả `playbook_check_ip` kết luận IP malicious có provenance -> Step_2 = `malicious`. Có thể đủ để kết luận `True Positive` khi đi kèm password success, MFA fail, risky sign-in, login success, hoặc dấu hiệu account compromise; nếu chỉ có IP reputation mà thiếu sign-in result/MFA/baseline thì không claim account compromise. Chỉ yêu cầu SOC/customer xác minh IP khi chưa đủ dữ liệu xác định role/outcome; không dùng xác minh approval như action đầu tiên cho TP từ IP malicious/nước ngoài.
12. Login success từ IP/quốc gia lạ hoặc MFA fail sau password success không được FP nếu chưa có evidence known travel/VPN/corporate baseline/approved activity rõ. Với IP nước ngoài/IP lạ/cloud/VPS/datacenter, action phải là phản ứng nguy cơ; chỉ xác minh người dùng/khách hàng khi IP Việt Nam/ISP lớn/nguồn có thể hợp lệ hoặc dữ liệu còn ambiguous.
13. IP sạch/Việt Nam/ISP lớn chỉ là supporting context, không tự động FP; cần baseline/approved evidence rõ hoặc action xác minh có nhánh điều kiện theo `Response action discipline`.
15. **Historical operation context:** `historical_context_only` chỉ là supporting context. TP cũ cùng rule/category/source_ip/user/activity làm tăng nghi ngờ và không được bỏ qua; TP trong 24h cần được nhắc rõ nếu có. FP lặp lại >=5 trong 7 ngày KHÔNG tự động FP; phải kiểm tra đây là noise thật hay TP từng bị miss. Nếu xác định noise thật, đề xuất tuning scope hẹp nhất trong `Response_Actions`/note, ví dụ rule + user group + approved VPN/corporate IP range + app/service; KHÔNG suppress chỉ theo rule_name.
16. **Historical/noise claim:** Chỉ được nói repeated FP/noise/historical benign khi `historical_context` có số liệu cụ thể. Không có `historical_context` thì không claim alert này là noise lặp lại.
17. Không public tên công nghệ sinh nội dung, nhà cung cấp, nền tảng hoặc endpoint nội bộ trong kết quả.

---

### Trạng thái cảnh báo

* **True Positive**: Có evidence trực tiếp về tấn công xác thực public hoặc account compromise: IP malicious + password success/MFA fail/login success, đăng nhập thành công hoặc password success + MFA fail từ IP nước ngoài/lạ không có approved evidence rõ, risky sign-in/impossible travel rõ, MFA abuse, password spray/bruteforce thành công, hoặc follow-on compromise.
* **False Positive**: Có evidence rõ cho thấy đăng nhập thuộc VPN/corporate/travel/automation/baseline hợp lệ, không có follow-on suspicious.
* **Need Enrichment**: Chưa rõ IP/user/device/MFA/sign-in result/baseline/approved activity đến mức không xác định được có đăng nhập thành công/password success + MFA fail hay không, hoặc thiếu dữ liệu để phân biệt hành động hợp lệ với rủi ro; Analyst cần xác minh/bổ sung dữ kiện. ⛔ MFA và baseline ở đây là **existence-gated theo nguồn**: nguồn `sshd`/PAM không có MFA (GATE 0 Source-capability) và baseline đã có trong `environment_prevalence` thì KHÔNG được tính là "chưa rõ" để chọn Need Enrichment.

### Tiêu chí False Positive

FP khi ĐỒNG THỜI:
1. **IP/source context hợp lệ**: IP thuộc corporate VPN, approved VPN, ISP/location quen thuộc của user, jump host, partner hoặc automation đã biết và có evidence rõ.
2. **Hành vi đăng nhập hợp lệ**: sign-in result, MFA result, app/service, device/user agent, thời điểm và location phù hợp baseline hoặc approved activity.
3. **Không có tín hiệu rủi ro sau đăng nhập**: không có MFA abuse, risky sign-in, impossible travel, inbox forwarding, OAuth consent, MFA/password change, token/session bất thường, data download hoặc cloud action đáng ngờ.
4. **Rule intent mismatch/noise rõ**: rule bắt nhầm do travel/VPN/corporate NAT/automation hoặc baseline hợp lệ, có evidence trực tiếp.

**Dấu hiệu mạnh FP:** approved VPN/corporate IP range, known device/app, location quen thuộc, MFA success hợp lệ, user/service owner approval có provenance, không có follow-on suspicious.

**Không được FP nếu:** Bước 2 = `malicious` từ evidence mạnh; login success từ IP lạ/nước ngoài; password success + MFA fail; risky sign-in; hoặc thiếu baseline/approved evidence. Với IP nước ngoài/lạ + login success/password success + MFA fail không có approved evidence rõ, dùng `True Positive - Phản ứng nguy cơ`; chỉ dùng `Need Enrichment` khi chưa xác định được outcome/IP/MFA hoặc chưa đủ dữ liệu để biết có đăng nhập thành công/password success + MFA fail hay không.

---

## Dữ liệu enrichment đã có sẵn

### Structured context
* **alert_info**: rule_name, category, siem_type, alert_time.
* **alert_details**: username, source_ip, ip_observations, source_country, device, app, service, sign-in result, MFA result, logon_type, risk reason nếu có.
* **ip:{ip}**: Kết quả phân tích IP từ `playbook_check_ip` nếu đã được attach trong `_sub_audit_reports`/`_source_evidence`: VT, AbuseIPDB, IP2Location, Google Search/access nếu flow thu thập được. **Chỉ dùng source THỰC SỰ có trong input.** Unavailable/missing -> KHÔNG suy luận; nếu thiếu kết quả full IP check thì yêu cầu enrich/chạy luồng `playbook_check_ip`.
* **_historical_context**: ticket cũ tham khảo, không tự động TP/FP.
* **environment_prevalence** (nếu có trong payload): `identity_baseline.known[]` = các feature (logon_src/device/app) user ĐÃ dùng lặp lại kèm `count`/`first_seen`/`last_seen`; `new_for_identity[]` = feature lần đầu với identity đã có lịch sử; `prevalence[]` = độ phổ biến entity trên tenant. **ĐÂY LÀ NGUỒN BASELINE ĐÃ CÓ SẴN** — đọc trực tiếp, KHÔNG xin lại "baseline 7-30d". Provenance khách quan (cận dưới theo alert-stream), KHÔNG tự set verdict (xem cảnh báo cận-dưới ở common_rule_intent.md Discriminator #7).

---

## Hướng dẫn xử lý

**⛔ GATE 0 — Source-capability (đánh giá TRƯỚC mọi bước, existence-gated theo nguồn):**
Trước khi đánh giá bất kỳ bước nào, xác định NGUỒN log của alert từ `service`/`program_name`/`siem_type`:
- Nếu nguồn là **`sshd` / PAM Linux** (hoặc Windows Security 4625/4776) thì **MFA result, conditional access, device compliance, app/client_app, risk_detail LÀ FIELD KHÔNG TỒN TẠI** trong nguồn này (đặc tính nguồn, không phải thiếu dữ liệu). Với các field đó: ghi "MFA not applicable (sshd)" một dòng, phần MFA `Result = no_data`; **CẤM** ghi chúng vào Missing, **CẤM** đưa vào `Enrichment_Requests`, **CẤM** lấy "thiếu MFA/conditional-access/device" làm lý do hạ Confidence hoặc chọn `Need Enrichment`. Áp carve-out "nguồn không cấp field" (common_rule_intent.md): các field này KHÔNG tính vào Confidence_Checklist [3]/[4].
- Verdict cho nguồn sshd/PAM quyết trên bằng chứng nguồn CÓ THỂ cung cấp: phương thức xác thực (publickey/password), sign-in result (Accepted/Failed), source IP + reputation/geo, chuỗi `auth_events`, và baseline `environment_prevalence.identity_baseline` của user.
- Chỉ nguồn **Azure AD/Entra/M365 sign-in** (có schema MFA/conditional-access) mới được coi "thiếu MFA" là dữ kiện điều tra và đưa vào `Enrichment_Requests`.
- ⛔ Carve-out này CHỈ CẤM dùng "thiếu MFA" làm lý do — KHÔNG cấp bằng chứng FP. Mọi khoá cứng giữ nguyên: login success/password success từ IP nước ngoài/lạ không approved vẫn `True Positive - Phản ứng nguy cơ` (Rule 12, Bước 3); IP malicious + success vẫn TP; `Accepted password` (không phải publickey) từ IP lạ vẫn theo nhánh TP.

**⛔ GATE 0-B — Sign-in result là bằng chứng ĐÃ CÓ trong log (không phải "unavailable"):**
- `raw`/`full_log`/`message`/`rule_name` chứa `Accepted publickey`/`Accepted password`/`session opened`/"authentication **success**" → `sign_in_result = SUCCESS` (đăng nhập THÀNH CÔNG). ⛔ CẤM ghi "Sign-in Result: unavailable/không khả dụng" khi log ĐÃ có `Accepted`/"success" — đó là tự mâu thuẫn với evidence; sign-in result CHÍNH LÀ bằng chứng quyết định ĐÃ CÓ, KHÔNG được vì lý do này mà đặt Confidence_Checklist [2]=KHÔNG hay [4]=CÒN THIẾU.
- `Failed password`/`Failed publickey`/`authentication failure` → `sign_in_result = FAIL`.
- `auth_method`: `Accepted publickey` = xác thực bằng khoá bất đối xứng (KHÔNG brute-force được, mạnh hơn mật khẩu); `Accepted password` = mật khẩu.

**⛔ GATE 0-C — RECIPE structural-benign cho publickey quen (FP, existence-gated — khớp ĐỦ MỌI điều kiện mới fire):**
Khi ĐỦ CẢ: `auth_method = Accepted publickey` (thành công) VÀ `ip:{source_ip}` sạch (VT 0 malicious + AbuseIPDB score thấp, không proxy/TOR xấu) VÀ `environment_prevalence.identity_baseline.known` chứa ĐÚNG `source_ip` này cho ĐÚNG user (đăng nhập lặp lại đã thành nếp, `count` cao) VÀ KHÔNG có tín hiệu follow-on xấu THẬT nêu trong alert (không risky sign-in/impossible travel/data-exfil/OAuth consent/mail-forwarding) → **False Positive, Confidence 85**. Lý do: khoá bất đối xứng + IP sạch + lịch sử đăng nhập lặp lại từ đúng IP = đặc trưng service/automation hợp lệ (vd CI/git, backup, deploy). Chuỗi cấu trúc (method publickey + IP-clean + baseline-known cho đúng IP) CHÍNH LÀ bằng chứng quyết định (common_rule_intent.md §structural-identity); follow-on-log VẮNG là XÁC NHẬN THIẾU (nguồn alert không kèm follow-on), KHÔNG phải bước then chốt → nếu muốn thì đưa vào `Investigation_Requests` như tham khảo, KHÔNG giữ Need Enrichment vì nó.

⛔ **KHOÁ CỨNG — KHÔNG áp GATE 0-C** (giữ nhánh TP/NE hiện hành) khi BẤT KỲ điều sau:
- `source_ip` nước ngoài/lạ HOẶC KHÔNG nằm trong `identity_baseline.known` cho user này (kể cả IP clean) — theo Rule 12/§"Không được FP nếu", login success từ IP lạ vẫn `True Positive - Phản ứng nguy cơ`.
- `source_ip` ở `identity_baseline.new_for_identity` (IP lần đầu với user có lịch sử) — novelty, nghiêng nghi ngờ.
- `auth_method = Accepted password` (chỉ **publickey** đủ điều kiện GATE 0-C; password dù có baseline vẫn KHÔNG auto-FP).
- `ip:{source_ip}` malicious/suspicious, HOẶC có follow-on xấu/risky sign-in/impossible travel/MFA abuse trong alert.
- Tài khoản đặc quyền (Domain/Enterprise/Schema Admins…) hoặc `context_tags.principal.tier = privileged` — cần xác minh, KHÔNG auto-FP.
Cap 85 (< ngưỡng auto-close 95) — vẫn qua QA reviewer + Attack Hunter (chạy trên FP) để soi độc lập.

* **Bước 1: Xác định thông tin cảnh báo**
    * **Rule Intent Match:** đánh giá rule bắt loại public-auth anomaly nào (impossible travel/spray/MFA fail/atypical sign-in/IP lạ) và alert có khớp intent không — ghi `match`/`mismatch`/`insufficient_data` và ảnh hưởng verdict/confidence.

    Hướng dẫn này phục vụ các hành động tấn công xác thực từ IP Public như VPN, Microsoft, SSO, cloud portal hoặc remote access.

    Cần trả lời:
    * Cảnh báo phát sinh tại thời điểm nào.
    * Description/rule/category của cảnh báo.
    * IP thực hiện hành động, quốc gia/ASN/ISP, IP có độc/VPN/proxy/Tor/VPS hay không.
    * User bị tác động.
    * Hành động phát sinh cảnh báo: Atypical Travel, Unfamiliar sign-in properties, Risky Signin, password fail/success, MFA fail/success.
    * Vì sao rule phát sinh cảnh báo và rule intent có đúng mục tiêu không.
    * Hành vi có dấu hiệu tấn công hoặc rủi ro tài khoản không.

    **Mục tiêu:** Hiểu rõ thông tin, xác định nguyên nhân phát sinh cảnh báo và hướng xử lý.

    **Result:** `informational`

* **Bước 2: Kiểm tra thông tin IP**
    * Dùng enrichment `ip:{ip}` đã có. Step_2 = `malicious` chỉ khi có evidence mạnh như AbuseIPDB high score + nhiều reports, VT nhiều vendor malicious, threat intel rõ, hoặc kết quả `playbook_check_ip` kết luận IP malicious có provenance.
    * Tor/anonymous proxy/high-risk hosting/VPS/VPN có provenance nhưng thiếu reputation/threat intel mạnh -> `suspicious`, không tự nâng thành `malicious`. Approved VPN/corporate IP có evidence rõ -> có thể `clean`.
    * Nếu chưa rõ role/outcome của IP và cần SOC/customer xác minh IP có phải nguồn tấn công hay nguồn hợp lệ hay không, ghi yêu cầu xác minh cụ thể trong `Enrichment_Requests`. Không đưa xác minh IP làm action đầu tiên trong `Response_Actions` khi các bước sau đã đủ điều kiện `True Positive - Phản ứng nguy cơ`.
    * Clean -> kiểm tra tiếp hành vi đăng nhập, baseline user/device/app và follow-on activity; không tự FP chỉ vì IP sạch.
    * IP nước ngoài/country lạ/chưa từng xuất hiện với user/không phải corporate VPN -> `suspicious`.
    * IP Việt Nam/ISP lớn không tự động FP; cần baseline/approved evidence hoặc action xác minh hành vi đăng nhập có nhánh điều kiện.
    * Thiếu reputation/country/ASN/ISP hoặc chưa rõ IP role -> `unknown` và yêu cầu enrich/check IP.

    **Result:** `malicious | suspicious | clean | unknown`

* **Bước 3: Kiểm tra hành vi đăng nhập**
    * Search tất cả sự kiện đăng nhập từ user tương ứng với IP thực hiện hành động.
    * Nếu là tấn công mật khẩu nhưng thất bại như password fail nhiều lần/password spray/bruteforce:
        - Tần suất lớn hoặc nhiều lần trong thời gian ngắn -> `suspicious`; ghi nhận action chặn IP/kiểm tra user khác theo phần `### Phản ứng`.
        - Tần suất nhỏ/lẻ tẻ -> `suspicious` hoặc `unknown` tùy evidence; monitor thêm và yêu cầu sign-in logs +/-24h nếu thiếu tần suất.
    * Nếu đăng nhập mật khẩu thành công + MFA thất bại như MFA fail/denied/repeated prompt:
        - Từ IP nước ngoài/IP lạ/không phải corporate VPN/không có approved evidence rõ -> `malicious` và kết luận `True Positive - Phản ứng nguy cơ`.
        - Từ IP Việt Nam hoặc ISP lớn -> không tự động FP; xác minh hành vi với người dùng/khách hàng/admin. Nếu không phải hành động hợp lệ của user/service/admin hoặc không có approved context -> `malicious` và kết luận `True Positive - Phản ứng nguy cơ`; nếu xác nhận hợp lệ và không có follow-on suspicious -> có thể FP/giảm rủi ro theo approved activity.
    * Nếu đăng nhập thành công:
        - Từ IP nước ngoài/IP lạ/không phải corporate VPN/không có approved evidence rõ -> `malicious` và kết luận `True Positive - Phản ứng nguy cơ`.
        - Từ IP Việt Nam -> không tự động FP; xác minh hành vi với người dùng/khách hàng/admin và kiểm tra follow-on activity. Nếu không phải hành động hợp lệ hoặc không có approved context -> `malicious` và kết luận `True Positive - Phản ứng nguy cơ`; nếu xác nhận hợp lệ và không có follow-on suspicious -> có thể FP/giảm rủi ro theo approved activity.
    * **Nếu có `auth_events` (chuỗi per-event):** TỰ tính từ chuỗi — impossible-travel (geo+timestamp 2 sự kiện), password-spray (1 source_ip → nhiều username), fail-then-success (fail rồi success cùng user/IP). Chỉ có count gộp mà không có chuỗi → giữ cap + `Need Enrichment`.
    * **Baseline nội tại (existence-gated):** Nếu payload có `environment_prevalence.identity_baseline.known` chứa `logon_src` = đúng `source_ip` của alert → đây CHÍNH LÀ baseline đăng nhập của user: trích `count`/`first_seen`/`last_seen` thành một dòng evidence, KHÔNG ghi "thiếu baseline" và KHÔNG đưa baseline vào `Enrichment_Requests`. Chỉ khi block VẮNG hoặc IP nằm ở `new_for_identity` mới ghi thiếu baseline. ⚠️ `known` chỉ chứng minh LẶP LẠI trong alert-stream (không tự chứng minh hợp lệ — khoá lộ dùng lặp cũng tạo count cao): nó GỠ lý do "thiếu baseline", nhưng để FP vẫn cần Bước 2 clean + không follow-on suspicious.
    * Nếu thiếu sign-in result, frequency, device/user agent hoặc follow-on logs -> `unknown` và đưa dữ liệu thiếu vào `Enrichment_Requests` (MFA đã bị GATE 0 Source-capability loại cho nguồn sshd/PAM; baseline chỉ ghi thiếu khi `environment_prevalence` VẮNG).

    **Result:** `malicious | suspicious | clean | unknown`

* **Bước 4: Tổng hợp thông tin và ra kết luận**
    * Cần trả lời: vì sao có hành vi này, đây có phải tấn công hoặc có rủi ro tài khoản không.
    * `True Positive` khi có evidence tấn công/rủi ro rõ: IP malicious + login success/password success + MFA fail, đăng nhập thành công hoặc password success + MFA fail từ IP nước ngoài/lạ không có approved evidence rõ, risky sign-in/impossible travel rõ, MFA abuse, password spray/bruteforce thành công, hoặc follow-on compromise.
    * Với đăng nhập thành công/password success + MFA fail từ IP nước ngoài/lạ không có approved evidence rõ -> `True Positive - Phản ứng nguy cơ`, kể cả khi còn thiếu một số context phụ như follow-on logs; các context thiếu phải đưa vào `Enrichment_Requests` để điều tra thêm, không hạ verdict xuống NE.
    * Với IP Việt Nam/ISP lớn, nếu user/customer/admin không xác nhận đây là hành động hợp lệ hoặc không có approved context -> `True Positive - Phản ứng nguy cơ`; nếu xác nhận hợp lệ và không có follow-on suspicious -> có thể FP/giảm rủi ro theo approved activity.
    * Nếu kết luận TP có đăng nhập thành công/password success + MFA fail, `Response_Actions` phải tham chiếu các bước phù hợp trong `### Phản ứng` như đổi mật khẩu, revoke sessions, kiểm tra MFA, kiểm tra follow-on activity và chặn IP khi tần suất/risk cao.
    * `False Positive` chỉ khi có evidence rõ cho approved VPN/travel/automation/baseline hợp lệ, rule intent mismatch/noise rõ, và không có follow-on suspicious.
    * Không xác định được -> `Need Enrichment`/Escalate; nêu rõ cần thu thập/xác minh gì và viết action có nhánh nếu đúng/sai khi action phụ thuộc xác nhận từ user/customer/admin.

`Enrichment_Requests` phải gồm dữ liệu còn thiếu cụ thể (existence-gated theo nguồn — bỏ field GATE 0 Source-capability đã loại): sign-in logs +/-24h, MFA details **chỉ cho nguồn Entra/M365 (KHÔNG cho sshd/PAM)**, device/user agent, baseline 7-30d **chỉ khi `environment_prevalence` VẮNG**, approved VPN/travel/corporate context nếu có, follow-on mail/cloud logs, và action xác minh hành vi đăng nhập với người dùng/khách hàng khi cần. Nếu TP có đăng nhập thành công/MFA fail thì `Response_Actions` phải khuyến nghị đổi mật khẩu, revoke sessions, kiểm tra MFA và follow-on activity.

---

### Phản ứng
* Khi không đủ dữ kiện để xác định outcome/IP/MFA hoặc với IP Việt Nam/nguồn có thể hợp lệ -> cần xác minh/bổ sung thông tin với khách hàng/người dùng gồm thời gian, user, IP, country, device, app, sign-in result, MFA result và log liên quan. Action xác minh phải chỉ rõ user/IP/thời điểm/app/service/client ID/thiết bị cần xác minh và nêu rõ nhánh nếu hợp lệ/không hợp lệ. Không áp dụng bước xác minh approval này cho TP từ IP nước ngoài/IP độc/cloud/VPS/datacenter.
* Với `True Positive - Phản ứng nguy cơ`, viết `Response_Actions` thành các item phản ứng trực tiếp: chặn IP theo chính sách, revoke/expire tất cả sessions hiện tại của tài khoản, yêu cầu user đổi mật khẩu, kiểm tra/bật MFA phù hợp, kiểm tra follow-on logs, mail forwarding rules/OAuth consent và hoạt động cloud/account sau đăng nhập.
* Login success / password success + MFA fail từ IP nước ngoài/lạ không có approved evidence rõ: verdict theo rule 12 và Bước 3/Bước 4 (`True Positive - Phản ứng nguy cơ`).
* Kiểm tra lịch sử 3 tháng gần đây để xác định user có bị lộ mật khẩu/lặp lại cảnh báo xác thực bất thường hay không.
* Nếu user bị lộ mật khẩu liên tục gần đây, phối hợp khách hàng chuẩn bị kế hoạch phản ứng:
    - Lập danh sách thiết bị sử dụng tài khoản và kiểm tra dấu hiệu độc hại trong phạm vi giám sát.
    - Kiểm tra khả năng người dùng bị phishing.
    - Kiểm tra lộ lọt thông tin tài khoản trên Dark Web nếu có nguồn dữ liệu.
    - Revoke/expire tất cả session đang sử dụng tài khoản.
    - Khách hàng cập nhật AV và scan toàn bộ thiết bị sử dụng tài khoản bị lộ.
    - Nếu phát hiện mã độc chưa được gỡ, hướng dẫn xử lý/gỡ bỏ; với mã độc phức tạp, khuyến nghị cài lại hệ điều hành để đưa thiết bị về trạng thái sạch.
    - Bật MFA nếu tài khoản đang dùng single factor.
    - Đổi mật khẩu, yêu cầu mật khẩu mạnh: tối thiểu 8 ký tự, có chữ hoa, chữ thường, số và ký tự đặc biệt.
* Nếu chưa thấy lộ mật khẩu lặp lại, gửi đề xuất phản ứng tối thiểu:
    - Đổi mật khẩu, yêu cầu mật khẩu mạnh: tối thiểu 8 ký tự, có chữ hoa, chữ thường, số và ký tự đặc biệt.
    - Bật MFA nếu đang single factor.
    - Revoke/expire tất cả session đang sử dụng tài khoản.
* Nếu cần chặn IP:
    - IP độc từ nước ngoài -> chặn Inbound vĩnh viễn.
    - Còn lại -> chặn Inbound tạm thời 5 ngày.

---

## Confidence guideline

> ⛔ TRƯỚC bảng này, BẮT BUỘC điền field `Confidence_Checklist` (5 phần tử — Confidence self-check ở Shared Rule); bảng dưới áp CHỒNG LÊN sàn checklist đó — lấy mức THẤP hơn. Đặc biệt: login success/password success + MFA fail từ IP nước ngoài/lạ thiếu approved evidence → checklist id=4 còn thiếu nhưng đây là rule cứng nghiêng TP (không hạ NE); baseline/approved 30-90 ngày là bằng chứng id=4 cho hướng FP.

| Confidence | Điều kiện |
|------------|-----------|
| 90-100 | Sign-in result, IP, (MFA khi nguồn Entra/M365), baseline/approved evidence hoặc follow-on compromise rõ; nguồn sshd/PAM đạt mức này qua auth_method + IP + baseline (MFA không áp) |
| 80-89 | IP/result/baseline rõ, thiếu một context phụ |
| 70-79 | Kết luận hợp lý nhưng thiếu approved evidence hoặc follow-on |
| 40-60 | Need Enrichment |

Không close FP cho login success/password success + MFA fail từ IP nước ngoài/lạ khi thiếu approved VPN/travel/baseline evidence; trường hợp này là `True Positive - Phản ứng nguy cơ`. Không dùng <60 cho TP/FP.
Confidence < 90 (mọi verdict TP/FP/NE) PHẢI nêu cụ thể cần bổ sung dữ liệu gì để nâng confidence, đưa vào `Enrichment_Requests`.
`Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

---

## Bổ sung discriminators TP/FP (category-specific)

Bổ sung cho các Bước ở trên (existence-gated: chỉ áp khi field/evidence có trong `alert_details`/`_source_evidence`; thiếu → ghi unavailable, không suy diễn; KHÔNG hardcode verdict).

- **(Bước 3) Error-code 4625 SubStatus:** `0xC0000064` user không tồn tại (spray/recon), `0xC000006A` sai mật khẩu (brute account thật), `0xC0000234` account khoá, `0xC0000072` disabled — phân biệt spray vs brute targeted; chỉ khi `sub_status`/`error_code` có.
- **(Bước 2) AbuseIPDB usage_type + num_distinct_users:** `Data Center/hosting` + nhiều user khác nhau = distributed credential abuse; corporate ISP / 1 user = ít nghi hơn.
- **(Bước 2) IP2Location proxy_type:** datacenter/VPN/proxy vs residential — login từ datacenter/anonymizer tới account thường dùng residential = nghi; chỉ khi `proxy_type`/`provider` có.
- **(Bước 1/3) Logon-type semantics:** 4624/4625 logon_type — Interactive(2)/RemoteInteractive(10) từ IP lạ khác Service(5)/Batch(4); logon type không hợp với account/service = nghi.
- **(Bước 3) Privileged + first-seen-IP + success:** account đặc quyền (`context_tags.principal.tier=privileged`) đăng nhập THÀNH CÔNG từ IP lần đầu thấy → escalation bắt buộc, KHÔNG FP confidence cao dù thiếu evidence khác.

---

### YÊU CẦU ĐẦU RA

BẮT BUỘC trả về JSON thuần:

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Xác định thông tin cảnh báo", "Detailed_Analysis": "- Evidence: thời điểm, description/rule/category, user, IP, country/ASN/ISP, app/service, result, MFA, risk reason.\n- Rule intent: rule bắt public auth/anomaly nào và có khớp event không.\n- Kết luận step: nguyên nhân phát sinh cảnh báo và dữ liệu còn thiếu.", "Result": "informational"},
    "Step_2": {"Step_Title": "Kiểm tra thông tin IP", "Detailed_Analysis": "- Evidence: enrichment ip:{ip}, reputation, country, ASN/ISP, VPN/proxy/Tor/VPS/corporate context.\n- Missing/Conflict: ghi rõ khi thiếu reputation/country/ASN/ISP hoặc chưa rõ IP role.\n- Kết luận step: IP làm tăng, giảm hay không đổi rủi ro đăng nhập.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_3": {"Step_Title": "Kiểm tra hành vi đăng nhập", "Detailed_Analysis": "- Evidence: failed/success, MFA, risky/unfamiliar/atypical travel, frequency, device/app, baseline, follow-on nếu có.\n- Missing/Conflict: ghi rõ khi thiếu outcome/MFA/device/baseline/follow-on hoặc cần xác minh hành vi đăng nhập với user/khách hàng/admin.\n- Kết luận step: hành vi đăng nhập đáng ngờ, hợp lệ hay cần làm rõ.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_4": {"Step_Title": "Tổng hợp thông tin và ra kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các step quyết định TP/FP/NE.\n- Missing/Conflict: dữ liệu thiếu hoặc conflict còn ảnh hưởng confidence.\n- Kết luận step: lý do cuối cùng; historical context chỉ để tham khảo.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Tóm tắt lý do kết luận"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["Chặn IP theo chính sách phản ứng nếu IP nước ngoài/IP độc/tần suất cao.", "Revoke/expire tất cả sessions hiện tại của tài khoản nếu có login success hoặc password success + MFA fail.", "Yêu cầu user đổi mật khẩu và kiểm tra/bật MFA phù hợp nếu có login success hoặc password success + MFA fail.", "Kiểm tra follow-on logs, mail forwarding rules, OAuth consent và hoạt động cloud/account sau đăng nhập.", "Kiểm tra các sự kiện đăng nhập liên quan từ cùng IP/dải IP và các user khác trong thời gian gần đây."],
  "Enrichment_Requests": ["NE (existence-gated theo nguồn — bỏ field GATE 0 Source-capability đã loại): sign-in logs +/-24h, MFA details CHỈ cho nguồn Entra/M365 (KHÔNG cho sshd/PAM), device/user agent, baseline 7-30d CHỈ khi environment_prevalence VẮNG, approved VPN/travel/corporate context, follow-on mail/cloud logs, xác minh hành vi đăng nhập với người dùng/khách hàng nếu cần"],
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
