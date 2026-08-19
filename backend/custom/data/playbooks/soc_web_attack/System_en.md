# Playbook Phân tích Cảnh báo Tấn công Web

## Global Evidence Rules
1. Chỉ dùng evidence được cung cấp. KHÔNG tự bịa VT/Google/AbuseIPDB/IP2Location/SIEM.
2. Missing/unavailable data → Unknown, KHÔNG phải Clean/Malicious.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. Close_Note và Escalate_Note BẮT BUỘC cho MỌI verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.

**⛔⛔ GATE 0 — Bot/Crawler/Scan/Recon precedence (deny-by-default; đánh giá TRƯỚC mọi bước, VÔ HIỆU HÓA mọi lập luận benign phía sau):**
Nếu request khớp BẤT KỲ dấu hiệu HARD sau → **Status = True Positive** (active scanning/reconnaissance, MITRE T1595), Step_3 Result = `malicious`, Response_Actions = chặn IP, Confidence 85-90 (recon xác nhận — KHÔNG claim exploit thành công):
- **Probe/well-known/scanner path:** `request_uri`/`all_uris_observed` khớp `/robot.txt`, `/robots.txt`, `/sitemap.xml`, `/.env`, `/.git`, `/admin`, `/wp-login.php`, `/phpmyadmin`, `/actuator`, `/swagger`, `/cgi-bin/`, `/server-status`, hoặc path liệt kê file/thư mục/cấu hình nhạy cảm khác; HOẶC
- **Bot/automation User-Agent:** `user_agent` chứa Googlebot/Bingbot/DuckDuckBot/YandexBot/AhrefsBot/curl/wget/python-requests/Go-http/Java/nuclei/nikto/sqlmap/masscan/zgrab…; HOẶC
- **Quét đa path:** `all_uris_observed` có nhiều path/endpoint khác nhau; HOẶC
- **⭐ Exploit-signature token gắn vào path HỢP LỆ (payload-on-legit-path):** `request_uri` chứa token khai thác đã định danh — `?-s`/`?-d`/`?-r`/`?-n` (PHP-CGI CVE-2012-1823: query string là cờ dòng lệnh, KHÔNG có dạng `key=value`), `${jndi:` (Log4Shell), `/etc/passwd`/`/etc/shadow` trong tham số, `union select`/`union+select`/`union%20select`, `<script`, `;wget `/`;curl `/`|bash`, `%00` (null-byte) — **kể cả khi phần path gốc là URL nghiệp vụ hợp lệ** (bài viết, sản phẩm, trang tin) và **kể cả khi `user_agent` là trình duyệt bình thường**. Đây là dấu hiệu ĐỘC LẬP: base path hợp lệ KHÔNG làm token hết độc; scanner thường duyệt sitemap thật rồi nối payload vào từng URL.
(Nguồn từ datacenter/hosting/VPS ASN hoặc crawler-operator ASN là dấu hiệu BỔ TRỢ làm chắc thêm; đánh giá theo IP client THẬT — `forwarded_client_ip` nếu có, theo rule 17/18.)

⛔ **CẤM tuyệt đối** lập luận "robots.txt/robot.txt là đường dẫn TIÊU CHUẨN/hợp lệ của bot/crawler nên benign", "crawler hợp lệ", "User-Agent trình duyệt bình thường", "IP sạch", "HTTP 200", hay "chỉ 1 event / thăm dò thông thường" để hạ về `clean`/`False Positive` khi GATE 0 fire. **Với dấu hiệu exploit-signature token: CẤM thêm lập luận "URI sau giải mã là đường dẫn bài viết/nghiệp vụ hợp lệ nên benign"** — phải pin đúng TOKEN (`?-s`, `${jndi:`…), không phải phần path bao quanh nó; base path hợp lệ + HTTP 301/404 (exploit không thành công) vẫn là TP mức attempt (Confidence 85-90, KHÔNG claim thành công). Việc XIN robots.txt/probe-path CHÍNH LÀ recon/enumeration; `/robot.txt` (thiếu 's') còn là scanner-artifact (crawler thật LUÔN dùng `/robots.txt`). Bot/crawler = traffic tự động không mời = TP.
**Ngoại lệ:** (a) IP client THẬT nằm trong dải nội bộ/khách hàng ĐÃ whitelist (monitoring/proxy/CDN của chính khách); HOẶC (b) **carve-out GATE 0-EXCEPTION** ngay dưới (search-engine crawler ĐÃ XÁC MINH). Ngoài 2 ngoại lệ này → deny-by-default TP, xét FP theo rubric thường không áp.

**✅ GATE 0-EXCEPTION — Verified legitimate search-engine crawler = False Positive** (ngoại lệ DUY NHẤT của deny-by-default cho bot ngoài; áp SAU khi đã đối chiếu GATE 0):
Một request bot được hạ về **False Positive** (index/crawl hợp lệ, KHÔNG phải recon) CHỈ KHI ĐỦ **CẢ 4** điều kiện — thiếu bất kỳ điều nào → quay lại deny-by-default = TP:
1. **Là search engine LỚN:** `user_agent` khai một trong: Googlebot, Bingbot/msnbot, DuckDuckBot, YandexBot, Baiduspider, Applebot. (SEO/marketing crawler như AhrefsBot/SemrushBot/MJ12bot và mọi công cụ scan curl/wget/python-requests/nuclei/nikto/sqlmap/masscan/zgrab… KHÔNG thuộc nhóm này → luôn TP.)
2. **Danh tính ĐÃ XÁC MINH bằng bằng chứng ĐỘC LẬP với chuỗi UA** (UA đơn thuần KHÔNG đủ — dễ giả mạo). Cần ÍT NHẤT MỘT: `reverse_dns`/PTR khớp domain chính thức của operator (`*.search.msn.com` cho Bing, `*.googlebot.com`/`*.google.com` cho Google, `*.crawl.yahoo.net`, `*.yandex.com/ru/net`, `*.applebot.apple.com`…); HOẶC `client_ip_class` = `searchEngine` (do SIEM gắn); HOẶC ASN/org của IP (từ IP enrichment) đúng là operator của UA khai báo (vd UA Bingbot ↔ ASN Microsoft, UA Googlebot ↔ ASN Google). Nếu KHÔNG có bằng chứng xác minh nào ngoài chuỗi UA → **coi như giả mạo → TP**.
3. **IP reputation SẠCH:** VT không có vendor malicious, AbuseIPDB score thấp/0 & không nhiều report, không threat-intel xấu. IP bẩn/nghi ngờ → TP.
4. **Request BẢN THÂN benign (sau khi GIẢI MÃ ở Bước 1c):** nội dung đã giải mã là request/truy vấn nghiệp vụ hợp lệ đọc-hiểu-được (vd search query) **HOẶC là fetch chỉ-mục hợp lệ của crawler**, KHÔNG có injection/exploit/deserialization/path-traversal/encode-evasion; KHÔNG probe well-known/sensitive path (`/.env`, `/.git`, `/admin`, `/wp-login.php`, `/phpmyadmin`, `/actuator`…); KHÔNG quét đa path bất thường (`all_uris_observed`). Có bất kỳ dấu hiệu tấn công/probe/scan → TP (crawler thật cũng có thể bị lợi dụng/độc hại).
   - **⭐ Carve-out chỉ-mục cho crawler ĐÃ XÁC MINH (đủ ĐK 1-3):** GET `/robots.txt` (ĐÚNG chính tả, có 's') và `/sitemap.xml` là **hành vi lập chỉ mục hợp lệ** của search-engine crawler — với crawler đã xác minh (ĐK 1-3) thì 2 path này THỎA vế "nghiệp vụ hợp lệ" và **KHÔNG tính là probe** cho ĐK 4 (không đẩy về TP chỉ vì chúng nằm trong danh sách HARD của GATE 0). Đây chính là carve-out GATE 0-EXCEPTION đã "áp SAU" GATE 0.
   - **⛔ Vẫn TP:** `/robot.txt` (THIẾU 's' — scanner-artifact), MỌI well-known/sensitive path khác (`/.env`, `/.git`, `/admin`, `/wp-login.php`, `/phpmyadmin`, `/actuator`, `/server-status`…), quét đa path, hoặc bất kỳ payload có injection/exploit → thất bại ĐK 4 → quay về deny-by-default TP kể cả khi UA/IP đã xác minh.
→ **Đủ cả 4:** Step_3 Result = `clean` (hoặc `informational`), Status = **False Positive**, **KHÔNG** chặn IP; ghi rõ trong note: "verified legitimate search-engine crawler — xác minh qua <reverse_dns/ip_class/ASN>, IP reputation sạch, request benign (đã giải mã)". Đây KHÔNG vi phạm Rule 14/14a: verdict FP dựa trên **payload đã giải mã là benign** (đã pin & đọc payload), signature WAF là false-trigger — KHÔNG phải "vouch source" bỏ qua payload.

**⛔ Named-source evidence rule (kể cả khi OSINT bị chặn → KHÔNG bịa nguồn):** áp dụng nguyên văn Shared Rule §"⛔ Named-source verbatim gate" (common_rule_intent.md). Delta web attack: provenance hợp lệ gồm cả `google_search_results`, `google_text`, `_evidence_context`, `evidence_index`; KHÔNG gán threat label như IP2Location `threat: SCANNER` khi object chỉ có `status: ok` (không có field `threat`). Chỉ có một nguồn trong evidence → chỉ nêu nguồn đó, không tự thêm. Search result mâu thuẫn với kết luận → nêu mâu thuẫn, hạ confidence hoặc `Need Enrichment`.

**Enrichment request discipline:** theo Shared Rule §"Low-confidence enrichment requests (Confidence < 90)" (common_rule_intent.md). Field web-attack hay thiếu: raw request body, response status/body size, backend log, XFF/forwarded header, EDR follow-up.

7. **Enrichment source nào có `status: unavailable` → KHÔNG được suy luận dữ liệu từ source đó.**
8. **GeoIP/datacenter/ISP chỉ là context, KHÔNG tự kết luận malicious.**
9. **⛔ VT/AbuseIPDB/IP2Location:** Chỉ ghi score, country, ISP, proxy, abuse_confidence nếu field/source object CÓ THẬT trong input. AbuseIPDB disabled/missing → KHÔNG suy luận abuse score. IP2Location unavailable → KHÔNG suy luận country/ISP/proxy. **KHÔNG gán tên VPN/proxy provider cụ thể (vd "ExpressVPN", "NordVPN") hay host/identity cụ thể của một IP nếu tên đó KHÔNG xuất hiện nguyên văn trong field/source evidence; `is_proxy=true`/`proxy_type` chỉ cho biết LÀ proxy, KHÔNG cho biết nhà cung cấp nào.**
9a. `Close_Note` Action/Closed Reason chỉ được nêu "đã kiểm tra VT/AbuseIPDB/IP2Location/Google" hoặc kết quả sạch/xấu khi `_sub_audit_reports`, `_source_evidence`, hoặc evidence index có factual fields tương ứng. Nếu không có, chỉ nói đã kiểm tra URI/payload từ alert và ghi IP reputation unavailable/unknown.
10. **URI/payload decode + đánh giá là VIỆC CỦA BẠN (LLM) — KHÔNG có triage sẵn từ code:** Bạn nhận `request_uri`, `all_uris_observed`, `payload`(body) ở dạng **RAW chưa giải mã** trong `web_context` và PHẢI tự giải mã nhiều lớp + phân tích (xem Bước 1c). Decoded URI/payload là evidence chính cho đánh giá payload/URI; IP reputation là evidence độc lập cho đánh giá nguồn tấn công.
11. **⛔ IP reputation rule:** IP public malicious với evidence mạnh (AbuseIPDB high score + nhiều reports, VT nhiều vendor malicious, threat intel rõ) CÓ THỂ đủ để kết luận traffic/source malicious và True Positive khoảng 90 dù thiếu URI/payload. Không được claim exploit thành công nếu thiếu response/backend evidence.
12. **⛔ Backend/success distinction:** Exploit attempt TP có thể dựa trên payload/request evidence rõ. Successful compromise cần backend evidence: webserver/app logs, response code/body, spawned process, file write, callback, auth/session anomaly.
13. **⛔ Truncated/unavailable data:** Nếu input chứa `"_truncated"`, `status: unavailable`, `no_data`, hoặc object bị rút gọn thì phần đó là **unavailable**. KHÔNG suy luận AbuseIPDB/IP2Location/VT values từ dữ liệu bị truncated. Enrichment unavailable/no_data KHÔNG được tăng confidence.
14. **⛔ WAF/rule label alone:** Rule name, WAF label, signature title, hoặc category name chỉ là alert context. Không TP chỉ dựa vào label nếu thiếu URI/payload/decoded request hoặc evidence hành vi thực tế.
14a. **⛔ Named-attack detection → KHÔNG False Positive (pin đúng payload/request):** Khi WAF/IDS/IPS/signature ĐÃ gắn cờ một **tên/loại tấn công định danh cụ thể** (SQLi, XSS, RCE, path traversal, deserialization, webshell upload... có signature/rule name rõ) lên payload/request → KHÔNG được kết luận `False Positive` bằng cách vouch cho source là "crawler/bot hợp pháp/IP sạch/benign"; phải pin & đọc đúng payload/decoded request (tự giải mã ở Bước 1c) — same-object. Bằng chứng hợp lệ về source/identity KHÁC KHÔNG vô hiệu hoá detection. Nếu chưa lấy/giải mã được payload để xác minh → `Need Enrichment`, KHÔNG `False Positive`. (Vẫn theo rule #14 & #12: label đơn lẻ chưa đủ khẳng định exploit thành công — phân biệt attempt vs successful cần payload/backend evidence; nhưng thiếu payload ⇒ NE chứ KHÔNG phải FP.) **Lưu ý carve-out GATE 0-EXCEPTION:** KHÔNG mâu thuẫn rule này — giải thích nguyên văn tại GATE 0-EXCEPTION (FP dựa trên payload ĐÃ GIẢI MÃ là benign, KHÔNG phải vouch source); payload giải mã có dấu hiệu tấn công thật → điều kiện 4 KHÔNG thoả → TP như thường.
15. **Historical operation context:** `historical_context_only` chỉ là supporting context. TP cũ cùng rule/category/hostname/source_ip/user/activity làm tăng nghi ngờ và không được bỏ qua; TP trong 24h cần được nhắc rõ nếu có. FP lặp lại >=5 trong 7 ngày KHÔNG tự động FP; phải kiểm tra đây là noise thật hay TP từng bị miss. Nếu xác định noise thật, đề xuất whitelist scope hẹp nhất trong `Response_Actions`/note, ví dụ rule + hostname + destination_port + exact request_uri/activity; KHÔNG whitelist chỉ theo rule_name.
16. **Search bot/crawler guardrail / Crawler identity override rule:** User-Agent, reverse DNS, ASN, hoặc Google result nói Bingbot/Googlebot/crawler chỉ là identity context, KHÔNG phải miễn trừ benign. Verdict bot/crawler: áp NGUYÊN VĂN GATE 0 (deny-by-default: malicious → TP, chặn IP) + GATE 0-EXCEPTION (verified search-engine crawler đủ 4 điều kiện → FP) ở đầu playbook; ngoại lệ còn lại: bot/monitoring là hạ tầng NỘI BỘ/khách hàng đã whitelist.
17. **⛔ Proxy/CDN/XFF guardrail:** Nếu `observed_source_ip` là Cloudflare/CDN/WAF/reverse proxy hoặc IP private forwarder, KHÔNG khuyến nghị block observed proxy IP khi chưa có `forwarded_client_ip`/real client IP. Nếu thiếu XFF/forwarded headers, ưu tiên Need Enrichment hoặc action truy vết real client IP.
18. **⛔ Forwarded client IP priority:** Nếu `forwarded_client_ip` là public IP và khác `observed_source_ip`, Step 2 PHẢI dùng `forwarded_client_ip` làm IP thực hiện tấn công chính. `observed_source_ip` sạch chỉ là evidence cho proxy/WAF/forwarder, KHÔNG đủ để kết luận IP attacker clean hoặc False Positive. Nếu không có enrichment `ip:<forwarded_client_ip>` thì Step 2 = `unknown` và top-level `Enrichment_Requests` phải yêu cầu enrich/check IP đó.
19. **⛔ Historical/noise claim:** Chỉ được nói repeated FP/noise/historical benign khi `historical_context` có số liệu cụ thể. Không có `historical_context` thì không claim traffic này là noise lặp lại.

---

### Trạng thái cảnh báo
* **True Positive**: Hành vi tấn công web hoặc scan có rủi ro thực sự.
* **Benign Positive**: TP nhưng do pentest/red team. Vẫn kết luận **True Positive**.
* **False Positive**: Rule bắt nhầm traffic hợp lệ từ nguồn sạch/không có evidence malicious.

| | False Positive | True Positive |
|---|---|---|
| **SQL Injection** | Ký tự đặc biệt trong tham số tìm kiếm/filter, không có ý đồ | Payload `' or 1=1 --`, `union select`, `sleep(5)` trên nhiều URI |
| **Path Traversal** | Logic ứng dụng dùng `../` | Request `../../etc/passwd`, `.env`, `web.config` |
| **XSS** | HTML/script-like string test giao diện | Payload `<script>`, `onerror=`, `svg/onload=` |
| **Exploit/RCE** | Debug traffic, QA script nội bộ | Command injection, Log4Shell, web shell, shell execution |
| **Web Scan / Recon / Crawler** | (a) hạ tầng nội bộ/monitoring/proxy của chính khách đã whitelist; HOẶC (b) **verified search-engine crawler** đủ 4 điều kiện GATE 0-EXCEPTION (search engine lớn + xác minh reverse_dns/ip_class/ASN + IP sạch + request benign) | Bot/crawler/scanner/recon/probe từ ngoài (scan nhiều URI, probe path `/robot.txt`/`/.env`/`/admin`, UA bot chưa xác minh, SEO crawler, curl/nuclei/sqlmap) — **TP, chặn IP** |

---

### Tiêu chí False Positive

**⛔ ĐIỀU KIỆN TIÊN QUYẾT của MỌI FP:** traffic phải là **NGƯỜI THẬT / ứng dụng nghiệp vụ**, HOẶC **hạ tầng nội bộ/khách hàng đã whitelist** (monitoring/proxy/CDN của chính khách), HOẶC **verified search-engine crawler** đủ 4 điều kiện GATE 0-EXCEPTION. **Traffic bot/crawler/scanner/automation từ ngoài KHÔNG được FP TRỪ carve-out verified-search-engine đó** — xem khối deny-by-default dưới.

FP khi ĐỒNG THỜI (và đã thỏa điều kiện tiên quyết trên):
1. **Source IP sạch/ít rủi ro**: enrichment = Clean/Unknown.
2. **Payload không tấn công thực sự**: dữ liệu hợp lệ, ký tự đặc biệt, chuỗi giống tấn công nhưng không khai thác.
3. **Client là người/ứng dụng nghiệp vụ thật** (KHÔNG phải bot/crawler/scanner): endpoint nghiệp vụ, không probe path, không quét đa URI.
4. **Ngữ cảnh hợp lệ NỘI BỘ**: monitoring/QA/reverse proxy/hạ tầng nội bộ của chính khách đã whitelist và không có reputation/abuse/threat intel xấu.
5. **Không tác động**: không brute-force, scan/recon, exploit rõ ràng.

**Dấu hiệu mạnh FP:** health check nội bộ, static path từ người dùng thật, IP nội bộ/whitelist là service/proxy/CDN của chính khách, payload chỉ regex false match từ request người thật.

**⛔ Deny-by-default — KHÔNG được FP nếu:**
- Bước 2 = `malicious` từ evidence mạnh (payload clean/tần suất thấp chỉ chứng minh "chưa thấy exploit thành công", KHÔNG chứng minh benign); HOẶC
- Traffic là **bot/crawler/scanner/recon/scan/probe** — nhận diện qua UA bot (Googlebot/Bingbot/DuckDuckBot/curl/wget/python-requests/nuclei/nikto/sqlmap/masscan/zgrab…), ASN/reverse-DNS crawler-operator/datacenter/hosting, probe well-known path (`/robot.txt`, `/robots.txt`, `/sitemap.xml`, `/.env`, `/.git`, `/admin`, `/wp-login.php`, `/phpmyadmin`, `/actuator`…), hoặc quét đa path. Đây là **active scanning/reconnaissance (MITRE T1595) = malicious → TP**, dù IP sạch / chỉ 1 event / UA khai là crawler hợp lệ. "Là crawler / thăm dò thông thường / IP sạch / 1 event" KHÔNG phải lý do FP. Ngoại lệ FP: (a) hạ tầng nội bộ/khách hàng đã whitelist; HOẶC (b) **verified search-engine crawler** đủ 4 điều kiện GATE 0-EXCEPTION (đã xác minh danh tính + IP sạch + request benign đã giải mã — search engine lớn, KHÔNG gồm SEO/scanner tool).

**LƯU Ý IP:**
* IP private → KHÔNG FP chỉ vì nội bộ. Xác định: máy bị chiếm quyền hay forward traffic.
* Tất cả event từ 1 IP private → có thể WAF/Reverse Proxy. Tìm IP thực qua X-Forwarded-For.
* Không tìm được IP thực → **Need Enrichment**.

---

## Dữ liệu enrichment đã có sẵn

### Structured context
* **web_context**: source_ip (`observed_source_ip`, `forwarded_client_ip`, `enrichment_source_ip`), source_port, destination_ip, destination_port, detection_source, hostname, request_uri, http_method, http_status, user_agent, rule_name, event_count, all_uris_observed, payload (request body). **`request_uri`/`all_uris_observed`/`payload` là RAW chưa giải mã — BẠN phải tự decode (Bước 1c). KHÔNG có field triage/decoded sẵn nào từ code.**
* **ip:{ip}**: Kết quả `playbook_check_ip`: VT (luôn có), AbuseIPDB (nếu enabled), IP2Location (nếu enabled), Google Search (nếu có driver). **Chỉ dùng source THỰC SỰ có trong input.** Unavailable → KHÔNG suy luận.
* **evidence_gaps**: Fields quan trọng bị thiếu (vd thiếu request body cho method POST/PUT/PATCH).

Sử dụng enrichment cho Bước 2 và 3. KHÔNG tự kiểm tra lại nếu đã có.

---

## Hướng dẫn xử lý

* **Bước 1: Xác định thông tin cảnh báo và kỹ thuật web attack**

    **1a — Alert context:**
    * `detection_source`: WAF, access log, firewall, SIEM rule? Rule trigger rule nào, rule thường bắt nhóm kỹ thuật gì.
    * `rule_name`: tên rule match. Giải thích rule này thường phát hiện loại traffic/attack gì.
    * IP chain: `observed_source_ip` → `forwarded_client_ip` → `enrichment_source_ip`. Nếu forwarded khác observed → observed có thể WAF/Proxy, IP thật = forwarded.
    * Target: `hostname`, `request_uri`, `http_method`, `http_status`, `user_agent`.
    * Scope: `event_count`, `all_uris_observed` (bao nhiêu URI, có đa dạng path/endpoint không).

    **1b — Attack technique identification:**
    * Dựa trên **nội dung URI/payload bạn đã TỰ GIẢI MÃ ở Bước 1c** (KHÔNG có triage/pattern sẵn từ code) để xác định kỹ thuật.
    * Nếu có đủ URI/payload/pattern, phân loại kỹ thuật quan sát được vào **ít nhất 1** trong các nhóm sau:
        - **SQL Injection**: query thao túng SQL — boolean-based, time-based (`sleep`, `benchmark`), error-based, union-based (`union select`), stacked queries. Dấu hiệu: `' or 1=1`, `union select`, `sleep(`, `concat(`, comment `--`, `/**/`.
        - **XSS**: script/event-handler/javascript URI nhắm vào browser/user session. Dấu hiệu: `<script>`, `onerror=`, `onload=`, `javascript:`, `svg/onload=`, `img src=x onerror=`.
        - **LFI/Path Traversal**: đọc file nhạy cảm qua path. Dấu hiệu: `../`, `..%2f`, `....//`, `%252e%252e%252f`, target `/etc/passwd`, `/etc/shadow`, `web.config`, `boot.ini`.
        - **RCE/Command Injection**: thực thi lệnh hệ thống. Dấu hiệu: `; cat /etc/passwd`, `| whoami`, `$()`, backtick, Log4Shell `${jndi:ldap://`, OGNL `%{`, PHP `eval(`, `system(`.
        - **Recon/Scanner**: dò path nhạy cảm/well-known, không payload cụ thể — **là hành vi tấn công (reconnaissance, MITRE T1595), KHÔNG benign**. Dấu hiệu: quét `robots.txt`/`robot.txt`/`sitemap.xml`, `.env`, `.git/config`, `wp-login.php`, `phpmyadmin`, `/actuator`, `/swagger`, `/admin`, `/cgi-bin/`, nhiều 404/403 liên tiếp. **`/robot.txt` (thiếu 's') = scanner-artifact**: crawler hợp pháp LUÔN xin `/robots.txt` (đúng chính tả), nên `/robot.txt` là dấu vết công cụ quét/bot giả dạng.
        - **Suspicious Payload**: encoded/obfuscated payload chưa rõ loại hình cụ thể, nhưng bất thường. Nếu chưa đủ dữ liệu phân loại → ghi Suspicious Payload kèm lý do nghi ngờ.
    * **Keyword-risk context:** Các keyword như `union`, `select`, `login`, `admin`, `password`, `credential` trong query/search parameter là weak signal. Không tự kết luận confirmed SQLi nếu `union` nằm trong cụm nghiệp vụ như `credit union` và không có `union select`, quote/comment/operator; nhưng nếu đi cùng rule exploit/web attack hoặc source IP malicious thì phải ghi nhận là suspicious probing/recon signal.
    * Nếu không đủ URI/payload/pattern để phân loại → ghi "Không xác định được kỹ thuật" và Step_1 Result = `unknown`.
    * Nếu nhiều kỹ thuật → liệt kê hết, sắp theo mức rủi ro giảm dần.
    * Giải thích ngắn gọn **vì sao** rule trigger: dấu hiệu nằm ở path, query string, header, body, hay tần suất.
    * **⛔ Rule-intent alignment (theo common_rule_intent.md):** Bắt buộc đối chiếu kỹ thuật quan sát với **intent cụ thể của `rule_name`** — kể cả CVE/kỹ thuật mà rule nhắm tới (ví dụ "Long Sequences Of Percent-Encode Bytes"). KHÔNG mặc định gán SQLi/XSS chỉ vì keyword rời rạc (`union`, `select`, `or 1=1`...) khi rule nhắm kỹ thuật khác. Nếu payload không khớp intent rule → ghi `rule_intent_match=mismatch`, nêu rõ và KHÔNG kết luận theo attack class mặc định; nếu khớp nhưng thiếu URI/payload/backend evidence → hạ confidence hoặc Need Enrichment.
    * Ghi rõ đây là **exploit attempt**, **recon/scan**, **probing**, hay **possible successful exploit** (cần backend evidence ở Bước 3).

    **1c — TỰ GIẢI MÃ URI/payload (BẮT BUỘC — bạn tự làm, KHÔNG có decoded sẵn từ code):**
    * Lấy `request_uri`, mọi mục trong `all_uris_observed`, và `payload`(body) ở dạng RAW, rồi **tự giải mã NHIỀU LỚP đến khi đọc rõ (human-readable)**:
        - **URL/percent-decode** (`%20`,`%2f`,`%3c`...); **lặp lại** nếu sau decode vẫn còn `%xx` (double/triple encoding).
        - **Base64** (chuỗi `[A-Za-z0-9+/=]` dài) → decode; thử cả UTF-8 và UTF-16LE; nếu kết quả lại là URL/base64 thì decode tiếp.
        - **Hex / `\xNN` / `%uXXXX` / unicode-escape / HTML-entity** (`&lt;`, `&#x...`).
        - Dừng khi không còn lớp mã hoá hoặc đã rõ ý đồ. Ghi **chuỗi giải mã từng lớp** (original → lớp 1 → … → final) và **kết quả cuối**.
    * Từ nội dung ĐÃ giải mã, chỉ ra dấu hiệu tấn công nếu có: breakout char (`'` `"` `;` `|` `` ` `` `$(` `{{`), SQL operator/comment, script/event-handler, command exec, path traversal, scanner path, **encode-evasion** (chuỗi `%20`/`%00`/`%2e` dài bất thường hoặc mã hoá nhiều lớp để che payload), code fragment (`url.replace(`, `eval(`, `function(`, `<`/`>`).
    * ⛔ Raw URI/payload nhìn "không rõ / giống rác" KHÔNG = benign. PHẢI giải mã rồi mới đánh giá. Giải mã xong mà KHÔNG ra ý nghĩa nghiệp vụ hợp lệ → coi là **payload bất thường (Suspicious)**, KHÔNG phải clean.
    * Nếu thực sự KHÔNG có URI/payload nào trong alert để giải mã → ghi "không có URI/payload để decode" và để Bước 3 = `unknown` (Need Enrichment), KHÔNG kết luận benign.

    **Step_1 Result:** `informational` (đã xác định đủ context) hoặc `unknown` (thiếu dữ liệu quan trọng như URI, payload, rule context).

* **Bước 2: Kiểm tra IP tấn công**
    * **KIỂM KÊ NGUỒN (BẮT BUỘC — dòng ĐẦU TIÊN của Step_2.Detailed_Analysis):** mở đầu bằng đúng 1 dòng dạng `Nguồn: VT=<có|không> | AbuseIPDB=<có|không> | IP2Location=<có|không> | Google/OSINT=<available|unavailable-captcha|unavailable-timeout>` — trạng thái CHÉP từ enrichment `ip:{ip}` (`google_search_limitations` / `unavailable_sources` / search `status:"skipped_captcha"`), KHÔNG tự suy. Toàn bộ phần sau của Step_2 CHỈ được nêu tên/số liệu của nguồn đã liệt `có`/`available` ở dòng này; nêu bất kỳ nguồn/label nào NGOÀI danh sách đó (CleanTalk, GreyNoise, Spamhaus, Maltiverse, sandbox, "Google found…", IP2Location `threat`…) = hallucination → Step_2 invalid. Thiếu dòng kiểm kê = Step_2 invalid.
    * **IP Public**: Dùng enrichment `ip:{ip}`. Malicious từ evidence mạnh (AbuseIPDB high score + nhiều reports, VT nhiều vendor malicious, threat intel rõ, hoặc SOC/customer xác định IP tấn công) → Step_2 = `malicious` và có thể đủ TP dạng traffic/source malicious hoặc attack attempt dù Bước 3 chưa chứng minh exploit thành công. Clean → kiểm tra tiếp.
    * **⛔ OSINT unavailable (CAPTCHA/timeout):** Khi enrichment `ip:{ip}` có `google_search_limitations` / `unavailable_sources` chứa Google/OSINT / search `status:"skipped_captcha"`, đó là evidence UNAVAILABLE — KHÔNG được nêu tên/score nguồn định danh (IP2Location "SCANNER", Spamhaus DROP, GridinSoft, AbuseIPDB report cụ thể…) nếu KHÔNG có NGUYÊN VĂN trong `_source_evidence`/ledger → Step_2 = `unknown`, đẩy `Enrichment_Requests`, KHÔNG suy "clean"/benign. (Xem Named-source verbatim gate ở common rule.)
    * **IP Private**:
        - Thiết bị trung gian (FW/WAF/Proxy/LB) forward từ Internet → truy vết IP thực. Tất cả event từ 1 IP nội bộ → khả năng cao forwarder.
        - IP private KHÔNG phải forwarder → endpoint nội bộ bị chiếm quyền đang scan.
        - Không xác định → **Need Enrichment**.

    * **Result:**
        * **malicious**: IP Public malicious qua enrichment. Nếu reputation evidence mạnh thì có thể đủ TP một mình cho kết luận traffic/source malicious; nếu evidence yếu thì cần kết hợp Bước 3.
        * **suspicious**: dấu hiệu nghi ngờ nhưng chưa đủ kết luận.
        * **clean**: IP Public clean qua enrichment.
        * **unknown**: IP Public unknown, hoặc IP Private không xác định forwarder/endpoint.
        * **informational**: IP là infrastructure đã biết (CDN, monitoring, internal service) và không có reputation/abuse/threat intel xấu.

* **Bước 3: Kiểm tra hành vi tấn công**
    * Gom nhóm theo domain: bề mặt tấn công, số IP tấn công/domain.
    * Tần suất: >200 request/15 phút = tần suất lớn.
    * Payload event chính + các event khác: URL (path nhạy cảm `/admin`, `/.env`, `/cgi-bin/`, `/actuator`, `/wp-login.php`), Query string, Header (User-Agent, Referer, Cookie), Body.
    * Response code: 30x/40x/50x → khả năng scan. 20x trên tất cả → web trả mặc định, không xác định thành công/thất bại.

    * **⭐ ĐỌC PAYLOAD ĐẦY ĐỦ (suy luận, KHÔNG chỉ enum):** đọc `payload`/`all_uris_observed`/`request_uri` thật (đã TỰ giải mã ở Bước 1c) và:
        - Trích **cú pháp tấn công CHÍNH XÁC** (vd `union select`, `<script>`, `../../etc/passwd`, `${jndi:ldap://}`, `;nslookup`, `| bash`) — KHÔNG chỉ ghi "Command Injection".
        - **Phán đoán THÀNH CÔNG hay mới ATTEMPT:** `http_status` 200 + response size lớn / có dữ liệu trả về = khả năng exploit thành công; 40x/50x = bị chặn/thăm dò; thiếu response → chỉ kết luận attempt (không khẳng định compromise).
        - **Đọc CHUỖI request** (`all_uris_observed`): nhiều URI tăng dần (đổi biến → exec cmd → callback) = chuỗi recon→exploit→exfil; nêu rõ endpoint OOB/callback (vd `*.oastify.com`, DNS exfil) nếu có.

    * **URI path-diversity / scan discriminator (existence-gated trên `all_uris_observed`):** Chỉ áp khi `all_uris_observed` CÓ trong alert_details/`_source_evidence`; thiếu → ghi "path-diversity unavailable", KHÔNG suy diễn. Đếm số URI/endpoint path DUY NHẤT: nhiều path khác nhau (đặc biệt path nhạy cảm `/admin`, `/.env`, `/.git`, `/actuator`, `/wp-login.php`, `/phpmyadmin`) trên cùng 1 source = tín hiệu quét rộng/recon nghiêng TP; chỉ 1–2 path lặp lại cùng endpoint nghiệp vụ = ủng hộ benign/FP. Path-diversity cao + source IP reputation xấu → nâng confidence TP; path-diversity một mình KHÔNG đủ kết luận, kết hợp với payload/IP evidence.
    * **Scanner-path fingerprint (existence-gated trên `all_uris_observed` + `user_agent` + IP enrichment):** Chỉ áp khi các field tương ứng CÓ provenance trực tiếp; thiếu field nào → ghi field đó unavailable, KHÔNG suy diễn. Đối chiếu URI quan sát với fingerprint recon path phổ biến (`/robots.txt`, `/robot.txt`, `/sitemap.xml`, `/.env`, `/.git/config`, `/wp-login.php`, `/phpmyadmin`, `/actuator`, `/swagger`, `/cgi-bin/`, `/server-status`) và/hoặc `user_agent` bot/công cụ quét (`Googlebot`, `Bingbot`, `nuclei`, `nikto`, `sqlmap`, `masscan`, `zgrab`, `python-requests`/`curl`/`wget`) và/hoặc IP là datacenter/hosting/crawler-operator: **bất kỳ dấu hiệu bot/scanner/recon nào = malicious/TP (active scanning, MITRE T1595)**. **Deny-by-default + carve-out xác minh:** mặc định bot-type identification dùng để **XÁC NHẬN traffic tự động → TP**, KHÔNG miễn trừ benign. NGOẠI LỆ: **verified search-engine crawler** đủ 4 điều kiện GATE 0-EXCEPTION (search engine lớn ĐÃ xác minh danh tính độc-lập-với-UA qua reverse_dns/ip_class/ASN operator + IP sạch + request đã giải mã benign) → FP. Thiếu xác minh (chống giả mạo UA) / SEO crawler / scanner tool / có payload-probe → vẫn TP. Ngoài carve-out: chỉ FP khi là hạ tầng nội bộ/khách hàng đã whitelist.
    * **⛔ Obfuscated/binary payload = attack request (KHÔNG `clean`):** Nếu decoded URI/payload **rõ ràng là payload bất thường** — chuỗi binary/high-entropy/obfuscated, không phải request nghiệp vụ đọc được (vd `/vision/RMIServlet?…%7a%44%70…` decode ra blob binary tới RMI/deserialization endpoint) — thì dù KHÔNG khớp loại phổ biến (SQLi/XSS/RCE/LFI) và bạn KHÔNG nhận ra pattern cổ điển nào, vẫn PHẢI coi là **"request tấn công loại chưa xác định" = Suspicious Payload**, Result ≥ `suspicious`. "Không nhận ra pattern" = "không có pattern cổ điển", KHÔNG = benign. Khi `rule_name` là CVE/signature exploit cụ thể VÀ payload khớp kỹ thuật evasion của rule (vd "Long Sequences Of Percent-Encode Bytes") → Result `suspicious`/`malicious`. **CẤM `clean`** cho payload obfuscated chỉ vì không nhận diện được loại.

    * **Result:**
        * **malicious**: payload rõ tấn công, HOẶC scan/recon/probe/crawler/bot behavior (active scanning, MITRE T1595). NGOẠI LỆ: verified search-engine crawler đủ GATE 0-EXCEPTION → `clean`, KHÔNG `malicious`.
        * **suspicious**: dấu hiệu tấn công nhưng thiếu context.
        * **clean**: request người thật/ứng dụng nghiệp vụ phù hợp logic chức năng (KHÔNG phải bot/crawler/scan); HOẶC **verified search-engine crawler** đủ 4 điều kiện GATE 0-EXCEPTION (đã xác minh danh tính + IP sạch + request benign đã giải mã).
        * **unknown**: thiếu raw request/payload/context → NE.
        * **informational**: monitoring/health check NỘI BỘ/whitelist của chính khách; HOẶC verified search-engine crawler đủ GATE 0-EXCEPTION (nếu muốn ghi informational thay clean).

    * **⭐ VERDICT URI/payload — FP khi nào / TP khi nào (dẫn vào Bước 4):** sau khi đã GIẢI MÃ kĩ (Bước 1c) và đối chiếu rule:
        - **TP / `malicious`:** nội dung đã giải mã có injection (SQLi/XSS/SSTI/LFI/RCE/deserialization), path traversal, **encode-evasion** (padding `%20`/`%00` dài bất thường, mã hoá nhiều lớp che payload), hoặc recon/scan có ý đồ — **bất kể `http_status`** (40x/403/blocked = attempt, vẫn TP).
        - **FP / `clean` — CHỈ KHI ĐỦ CẢ:** (0) client là **NGƯỜI THẬT/ứng dụng nghiệp vụ** (KHÔNG phải bot/crawler/scanner/recon/probe — traffic tự động → `malicious`, KHÔNG `clean`, TRỪ verified search-engine crawler đủ 4 điều kiện GATE 0-EXCEPTION → xử theo carve-out); (1) đã giải mã HẾT các lớp; (2) nội dung là request nghiệp vụ hợp lệ, đọc hiểu được, KHÔNG có token tấn công/evasion; (3) giải thích được vì sao rule trigger là false-match (vd ký tự đặc biệt hợp lệ trong tham số). Thiếu bất kỳ điều nào → KHÔNG được `clean`.
        - **NE / `unknown`:** không giải mã được, thiếu body cần thiết (method POST/PUT/PATCH mà `payload` rỗng), hoặc không xác định được client thật sau CDN/proxy.
        - ⛔ KHÔNG `clean`/FP chỉ vì: "không nhận ra pattern", IP CDN/Cloudflare sạch (rule 17/18), HTTP 404, hay lịch sử FP — khi nội dung giải mã vẫn có dấu hiệu tấn công/evasion.

    * **Keyword-risk context decision:** Nếu query/search parameter chứa `union` + `login` hoặc keyword SQL/auth tương tự, và Bước 2 = `malicious` hoặc rule_name là exploit/web attack, thì Step_3 tối thiểu là `suspicious`. Không được ghi `clean`/`benign`; chỉ được ghi "chưa đủ evidence exploit thành công" nếu thiếu `union select`, quote/comment/operator, response/backend evidence.
    * **Crawler/bot verdict:** áp NGUYÊN VĂN GATE 0 (deny-by-default: bot/crawler → Step_3 `malicious` → TP, chặn IP) + GATE 0-EXCEPTION (verified search-engine crawler đủ 4 điều kiện → Step_3 `clean` → FP, KHÔNG chặn IP) ở đầu playbook; ngoài carve-out chỉ FP khi hạ tầng nội bộ/khách hàng đã whitelist.

* **Bước 4: Tổng hợp và kết luận**

    **Decision precedence bắt buộc — → TP nếu:** Bước 2 = `malicious` từ evidence reputation mạnh (ví dụ AbuseIPDB high score + nhiều reports, VT nhiều vendor malicious, threat intel rõ, hoặc SOC/customer xác định IP tấn công) → final `Status` BẮT BUỘC là `True Positive`; kết luận traffic/source malicious hoặc attack attempt, KHÔNG claim exploit thành công nếu thiếu response/backend evidence. Bước 3 = `clean`/`informational` chỉ được dùng để giới hạn kết luận thành "malicious source / attack attempt / probing chưa thấy exploit thành công", KHÔNG được đổi final verdict thành `False Positive`.

    **→ TP ngay nếu:** Bước 3 = malicious (payload/URI/exploit/scan rõ), bất kể Bước 2.

    **→ TP (deny-by-default) nếu:** Bước 3 = **scan/recon/crawler/bot/probe behavior** (probe well-known path như `/robot.txt`/`/robots.txt`/`/.env`/`/admin`, UA bot Googlebot/Bingbot/curl/nuclei, ASN datacenter/crawler-operator, hoặc quét đa path) → **True Positive (active scanning/reconnaissance, MITRE T1595)**, BẤT KỂ reputation IP (kể cả IP sạch) và số event (kể cả 1). Chặn IP. Ngoại lệ: (a) hạ tầng nội bộ/khách hàng đã whitelist; HOẶC (b) **verified search-engine crawler** đủ 4 điều kiện GATE 0-EXCEPTION (search engine lớn ĐÃ xác minh danh tính + IP sạch + request đã giải mã benign) → FP, KHÔNG chặn IP.

    **→ TP confidence cao hơn nếu:** Bước 2 = malicious + Bước 3 = malicious/suspicious (IP malicious bổ trợ payload/URI nghi ngờ hoặc rõ tấn công).

    **→ FP khi ĐỒNG THỜI:** Bước 3 = clean **theo rubric Verdict URI/payload** (client là NGƯỜI THẬT/app nghiệp vụ — KHÔNG bot/crawler/scan, đã giải mã kĩ, nội dung request hợp lệ) + Bước 2 = clean/unknown; HOẶC là hạ tầng nội bộ/khách hàng đã whitelist; HOẶC **verified search-engine crawler** đủ 4 điều kiện GATE 0-EXCEPTION (search engine lớn ĐÃ xác minh danh tính độc-lập-với-UA + IP reputation sạch + request đã giải mã benign). Nếu Bước 2 = malicious HOẶC traffic là bot/crawler/scan/recon/probe **mà KHÔNG thoả carve-out verified-search-engine** thì **tuyệt đối KHÔNG FP** (→ TP). ⛔ KHÔNG FP nếu chỉ dựa vào "không nhận ra pattern" / IP CDN sạch / HTTP 404 / lịch sử FP / "là crawler" / "thăm dò thông thường" khi traffic là bot/scan chưa xác minh hoặc nội dung giải mã vẫn có dấu hiệu tấn công/evasion.

    **⛔ KHÔNG FP khi decoded URI là payload obfuscated/binary khớp rule CVE/signature exploit** (vd "Long Sequences Of Percent-Encode Bytes" → RMI/deserialization endpoint `/vision/RMIServlet`): đây là **attack request loại chưa xác định → TP (attack attempt)**, bất kể bạn không nhận ra pattern cổ điển nào, HTTP 40x/404, hay source IP là CDN/Cloudflare sạch. "Không khớp loại phổ biến" + payload rõ ràng obfuscated ≠ benign; HTTP 404 = probing/blocked, vẫn là attempt; IP CDN sạch ≠ traffic benign (attacker sau CDN).

    **⛔ CVE/exploit-signature rule + matched indicator = attack attempt (KHÔNG NE oan):** Khi `rule_name` mã hoá một **CVE/exploit-signature cụ thể** (vd `CVE-2024-21762`, `CVE-2026-41490`, named exploit pattern) VÀ alert có **chính chỉ dấu mà rule khớp** (`request_uri`/`url.path`/`url.query`/pattern cụ thể — vd `/login/?login_only=1`) → request khớp signature ĐÃ là bằng chứng hành vi = **attack attempt → True Positive @ ≥80** (probing/attempt, KHÔNG claim compromise). **KHÔNG hạ Need Enrichment chỉ vì thiếu request body** (nguồn WAF/CDN/Cloudflare/Forti không log body) **hoặc IP reputation `unavailable`**. Phân biệt với mục 14 "WAF/rule label alone": mục 14 áp khi CHỈ có tên rule mà KHÔNG có URI/indicator; rule này áp khi matched URI/indicator HIỆN DIỆN. IP rep xấu hoặc payload đầy đủ chỉ NÂNG confidence (→90-95); absence của chúng KHÔNG ép NE.

    **→ NE khi:** IP private chưa xác định forwarder/endpoint, HOẶC thiếu CẢ raw request/URI/matched-indicator và IP reputation không đủ mạnh, HOẶC Bước 2 không malicious + Bước 3 = unknown (cần kiểm tra payload). (Ngoại lệ: rule CVE/exploit-signature + matched indicator hiện diện → KHÔNG NE, xem rule trên.)

    **⛔ Confidence caps:**
    | Condition | Confidence guidance |
    |---|---|
    | IP-only malicious với reputation evidence mạnh, không payload/URI evidence | khoảng 90 |
    | IP malicious + payload/URI rõ | 90-95 |
    | Payload/URI rõ nhưng thiếu response code/backend logs | 90-95 cho attack attempt/probing; KHÔNG claim successful compromise |
    | CVE/exploit-signature rule fired + matched URI/indicator present (thiếu body hoặc IP-rep unavailable) | ≥80 attack attempt TP (KHÔNG NE) |
    | IP reputation yếu/chỉ một tín hiệu mơ hồ, không payload/URI evidence | max 80 |
    | Thiếu CẢ raw request/URI/matched-indicator và IP reputation không mạnh | < 80 → Need Enrichment |
    | Enrichment unavailable/no_data | KHÔNG tăng confidence |
    | Need Enrichment | 40-60 (trừ khi strong evidence thì 60-70) |

    `Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

    **⛔ Success/impact distinction:** Thiếu `http_status`, response body, backend app logs, webserver error log, EDR follow-up, file write, process spawn, callback, hoặc auth/session anomaly thì chỉ được kết luận `confirmed attack attempt/probing/traffic malicious`; KHÔNG kết luận successful compromise, data leak, shell, file write, hay impact thành công.

    **⛔ Enrichment_Requests bắt buộc khi NE:** yêu cầu cụ thể:
    - WAF/access log quanh source_ip + request_uri + time (±15 phút)
    - Decoded URI nếu chưa có
    - Response status code + body size
    - XFF / X-Forwarded-For / forwarded headers
    - Backend app logs (webserver error, application log)
    - EDR process/file/network follow-up trên target host

    * Benign Positive → vẫn kết luận **True Positive**. Nghi ngờ pentest nhưng không xác nhận → kết luận theo hành vi kỹ thuật.

---

### Phản ứng
* IP độc từ nước ngoài → chặn Inbound vĩnh viễn.
* Còn lại → chặn Inbound tạm thời (5 ngày).

---

### YÊU CẦU ĐẦU RA

**Luồng:** FP/TP → kết luận luôn. TP → `Response_Actions`. Không xác định → NE + liệt kê thiếu gì. **Mọi verdict có `Confidence` < 90 vẫn PHẢI điền `Enrichment_Requests`** (xem Shared Rule).

BẮT BUỘC JSON:
```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Xác định cảnh báo + tự giải mã URI/payload + kỹ thuật web attack", "Detailed_Analysis": "- Evidence: detection_source, rule_name, IP chain, target, scope.\n- Decoded layers: original -> từng lớp giải mã -> final (URL/base64/hex/unicode/HTML-entity).\n- Technique: SQLi/XSS/LFI/RCE/SSTI/deserialization/Recon/encode-evasion/Suspicious Payload từ nội dung ĐÃ giải mã.\n- Rule-intent match: khớp/không khớp rule; nếu không khớp thì là tấn công gì.\n- Kết luận step: exploit attempt, recon/probing hay insufficient data.", "Result": "informational|unknown"},
    "Step_2": {"Step_Title": "Kiểm tra IP thực hiện tấn công", "Detailed_Analysis": "- Evidence: Public/Private, forwarded IP, enrichment quốc gia/ISP/AV nếu có.\n- Missing/Conflict: ghi rõ khi IP chỉ là forwarder/proxy hoặc thiếu reputation.\n- Kết luận step: IP source đáng ngờ, hợp lệ hay chỉ informational.", "Result": "malicious|suspicious|clean|unknown|informational"},
    "Step_3": {"Step_Title": "Kiểm tra hành vi tấn công + verdict URI/payload", "Detailed_Analysis": "- Evidence: decoded payload/URI, header, body, request count, response code, mục tiêu.\n- Verdict URI/payload: TP(attack/evasion) | clean(đã giải mã kĩ, request hợp lệ, giải thích false-match) | NE(chưa decode được/thiếu body).\n- Missing/Conflict: ghi rõ khi payload/body không khả dụng.\n- Kết luận step: tấn công thực | recon/scan/crawler/bot probe (= malicious) | benign hit (CHỈ human/app nghiệp vụ hoặc hạ tầng nội bộ/whitelist).", "Result": "malicious|suspicious|clean|unknown|informational"},
    "Step_4": {"Step_Title": "Tổng hợp thông tin và ra kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các step quyết định TP/FP/NE.\n- Missing/Conflict: dữ liệu thiếu hoặc conflict còn ảnh hưởng confidence.\n- Kết luận step: lý do cuối cùng; historical context chỉ để tham khảo.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Lý do chi tiết chọn Status"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["Khi TP: Chặn IP tạm thời 5 ngày hoặc vĩnh viễn (nước ngoài)"],
  "Investigation_Requests": [{"intent": "Mục đích query", "why_raises_confidence": "đang X → lên Y nếu log cho thấy ...", "action": "search_web|search_network", "target_field": "forwarded_client_ip|request_uri|http_status|source_ip|uri_path", "target_value": "value từ alert", "time_range_hours": 1}],
  "Enrichment_Requests": ["NE HOẶC Confidence < 90: thứ KHÔNG query SIEM được (reputation/OSINT, response body, dữ liệu ngoài); log SIEM đặt ở Investigation_Requests; [] chỉ khi Confidence >= 90 và không phải NE"],
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
