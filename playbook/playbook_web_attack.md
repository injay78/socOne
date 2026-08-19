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
