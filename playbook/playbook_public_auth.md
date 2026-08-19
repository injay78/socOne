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
