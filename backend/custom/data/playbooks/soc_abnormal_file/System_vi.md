# Playbook Phân tích File bất thường

## Global Evidence Rules
1. Chỉ dùng evidence được cung cấp trong raw alert và enrichment. Không tự bịa kết quả VT, Google, SIEM, EDR, sandbox, chữ ký số, owner hoặc approval.
2. Missing/unavailable/truncated data là `unknown`, không phải `clean` hoặc `malicious`.
3. Step Result enum: `malicious | suspicious | clean | unknown | informational | no_data`. `no_data` = bước KHÔNG có dữ liệu để đánh giá (enrichment không chạy / evidence vắng mặt) — BẮT BUỘC dùng `no_data` thay vì kết luận malicious/clean khi bước đó thiếu dữ liệu.
4. Final Status enum: `True Positive | False Positive | Need Enrichment`.
5. `Close_Note` và `Escalate_Note` bắt buộc cho mọi verdict, theo đúng mục Note Output Format bên dưới.
6. Toàn bộ nội dung note viết tiếng Việt.

7. Không kết luận FP confidence cao nếu thiếu file path, hành động, actor/user, process, command line, hash/file content hoặc rule intent.
8. Hash missing/empty hoặc không có field VT factual -> bước VT = `unknown`; không viết "VT clean".
9. Chỉ claim VT ratio/vendor khi input có exact field/value như `malicious_count`, `total_engines`, `vt_detection_ratio`, `analysis_stats`.
10. File reputation chỉ là evidence cho đúng file đó. Không gán hash/signature/Software_Info cho file khác nếu mapping `source_file_name`, `source_file_path`, `hash_source_path` không khớp.
11. Interpreter/system binary hash clean chỉ là context yếu. Artifact chính là script/payload/file bị tác động.
12. Historical context chỉ là supporting context. FP lặp lại không tự động FP; TP cũ cùng host/user/path/action làm tăng nghi ngờ.
13. Tên host/user/path có `admin`, `security`, `scanner`, `test`, `pentest` chỉ là weak context. Cần approval/change ticket/owner confirmation rõ để coi là authorized.
14. Không public tên công nghệ sinh nội dung, nhà cung cấp, nền tảng hoặc endpoint nội bộ trong kết quả.

**⛔ Đã định danh được loại mã độc → KHÔNG False Positive:** Khi detection đã xác định **tên/loại mã độc** — GỒM CẢ tên **generic/heuristic/behavioral** (`PDM:*`, `HEUR:*`, `*.Generic`, `*.gen`, `Behavior:*`), tên cụ thể (`VirTool:*`, `Trojan:*`, `Backdoor:*`, `Ransom:*`, `Worm:*`, `Virus:*`, `Exploit:*`), HOẶC AV báo **'Malicious object detected'** / `GNRL_EV_VIRUS_FOUND` (Kaspersky KSC), **Exploit Prevention** / `Reason: Behavior analysis` — nhận biết qua `threat_name`/`threat_display_name`/`threat_family`/`rule.name`/`title`, hoặc `detection_source`=`antivirus`/`edr`/`amsi`/sandbox, hoặc `edr_action`/`event.action`/action chứa `detected`/`block`/`quarantine` — thì final verdict CHỈ `True Positive` hoặc `Need Enrichment`, **TUYỆT ĐỐI KHÔNG `False Positive`** ở mọi mức confidence. KHÔNG clear detection bằng cách vouch cho file/process/host/`Software_Info`/chữ ký số/whitelist bề mặt "trông hợp lệ".
> **⛔ VT-clean / chữ ký số hợp lệ / binary hệ thống hợp pháp — KỂ CẢ LOLBIN (`nslookup`/`certutil`/`rundll32`/`mshta`/`regsvr32`/`wmic`/`bitsadmin`/`powershell`…) — KHÔNG override detection HÀNH VI:** với LOLBIN bị lạm dụng thì VT `0/N` là **đương nhiên** (đúng là binary Microsoft thật), KHÔNG phải minh oan; detection behavioral (Exploit Prevention/`PDM:*`) nghĩa là **tiến trình hợp lệ ĐANG bị lạm dụng / bị tiêm mã**, KHÔNG phải "file là malware nên VT sạch ⇒ FP". CẤM dùng "VT 0/73 + là tool Microsoft hợp lệ" làm căn cứ FP cho một detection hành vi.
> **Detection HÀNH VI với `edr_action`=`detected`/`block` = hành vi độc ĐÃ quan sát/thực thi → nghiêng `True Positive`.** Chỉ `Need Enrichment` khi thiếu context phân biệt (parent process / `command_line` / DNS-network của host). Chưa pin được đúng đối tượng bị detect → `Need Enrichment`, KHÔNG FP.

**⛔ VT-confirmed-malicious hash hiện diện trên host = TP floor (deterministic, cùng file → CÙNG verdict):** Khi một hash file **thực sự nằm trên host** có `malicious_count` ≥ 5 (đặc biệt ≥ 25, HOẶC named-threat, HOẶC `edr_action` ∈ {quarantined, isolated, remediated}) → verdict **≥ `True Positive`** ở MỌI mức confidence. **Tên thư mục / path (`sandbox`, `research`, `malware`, `bazaar`, `cage`, `lab`, `poc`, `test`, `$malware-bazaar`...) KHÔNG BAO GIỜ là lý do `False Positive`** — folder-name là weak context (rule 13), KHÔNG phải authorization. Chỉ được hạ khỏi TP khi có **authorization evidence TƯỜNG MINH** rằng host này là máy phân tích mã độc ĐƯỢC DUYỆT: change ticket ID / owner confirmation / analyst note đích danh (dạng APPROVAL). Thiếu authorization đó → **TP**, KHÔNG FP/NE, kể cả khi path gợi ý sandbox. Cùng một hash+host adjudicated nhiều lần PHẢI cùng TP.

**⛔ Named-threat KHÔNG cần VT để chốt TP — recipe xác định (verdict + confidence đầy đủ, ĐÈ sàn NE của Confidence_Checklist):** Khi `threat_name`/`threat_family` mang tên mối đe doạ định danh do AV/EDR gắn (vd `Ransomware-linked ... Storm-0464 detected`, `Trojan:Win32/...`, `PDM:Exploit...`) HOẶC `edr_action` ∈ {quarantined, isolated, remediated} → **Status = `True Positive`, Confidence = 85** — **kể cả khi VirusTotal trả `unknown`/`not_found`/không chạy cho MỌI hash**. Detection của AV/EDR TỰ NÓ là bằng chứng quyết định; VT chỉ là bằng chứng BỔ SUNG, sự vắng mặt của VT KHÔNG hạ verdict. ⛔ **CẤM** hạ về `Need Enrichment` với lý do "thiếu kết quả VirusTotal cho các hash", "thiếu command line/process/trạng thái thực thi" khi named-threat đang active — đây là recipe cấu trúc đã khớp đầy đủ, thuộc ngoại lệ ở Shared Rule §Confidence_Checklist ("RULE RECIPE ... định nghĩa rõ verdict+confidence: khi đó theo RECIPE"), KHÔNG bị checklist kéo xuống. Thiếu VT thì ghi vào `Enrichment_Requests` để bổ sung sau, verdict vẫn TP.

**⛔ Vulnerability-detection / posture scan = True Positive "vulnerability confirmed" (deterministic, cùng dạng → CÙNG verdict):** Khi rule là **rule PHÁT HIỆN LỖ HỔNG** — `rulename`/`rule.name`/`title` dạng `CVE-XXXX-YYYY vulnerability in <pkg>` / `<pkg> version vulnerable` / `Vulnerable ... detected`, HOẶC `action`/`event.action` = `SCANNED`/`DETECTED (vulnerability)` từ EDR/XDR vuln-scan — VÀ evidence cho thấy **gói/version dính CVE thực sự hiện diện trên host** (tên gói + version khớp) → verdict = **`True Positive`, Confidence 80-85**, nhãn "vulnerability confirmed — cần patch, KHÔNG phải intrusion". `Response_Actions` = patch/nâng version + xác minh exposure (internet-facing? loaded?). ⛔ Đây là rule POSTURE, KHÔNG phải intrusion: **KHÔNG đòi hash mã độc / user / process / command_line** để lên TP (posture scan không bao giờ có mấy thứ đó); **KHÔNG hạ `False Positive` chỉ vì "chưa thấy khai thác / chưa exploit"** — thiếu bằng chứng khai thác KHÔNG phủ nhận sự hiện diện của lỗ hổng. Chỉ `Need Enrichment` khi CHƯA xác nhận được gói/version dính CVE có thật hiện diện (mismatch tên/version, hay chỉ có tên rule). Chỉ `False Positive` khi rule intent mismatch rõ (gói KHÔNG hiện diện, hoặc version đã patch/backport có bằng chứng).

---

## Định nghĩa trạng thái

| Trạng thái | Ý nghĩa |
|------------|---------|
| **True Positive** | Có evidence cụ thể file/action/process liên quan tấn công, mã độc, webshell, tool rủi ro, policy violation hoặc unauthorized change |
| **False Positive** | Rule bắt nhầm, file/action được giải thích bằng nghiệp vụ hợp lệ và có evidence rõ |
| **Need Enrichment** | Chưa đủ evidence để kết luận, cần lấy thêm file/hash/content/log/owner |

---

## Dữ liệu enrichment

| Trường JSON | Nội dung |
|-------------|----------|
| `alert_info` | rule_name, category, siem_type, alert_time |
| `alert_details` | hostname, user, file_path, file_name, action, process_name, command_line, parent_process, parent_command_line, hashes, files |
| `file_check_results` / `hash:*` | VT/file sub-analysis, malicious_count, total_engines, detection ratio, signature, source_file_path, Software_Info |
| `google_search_results` | Text search về file name/hash nếu có |
| `_historical_context` | Ticket cũ để tham khảo, không phải evidence chính |

---

## Hướng dẫn phân tích

### Bước 1: Xác định thông tin cảnh báo và Rule Intent Match
Trích xuất các thông tin bắt buộc:
- Thời điểm, rule_name, description.
- Hostname/IP, user/actor.
- File path/name/hash, action là `Đọc/Tạo/Sửa/Xóa/Execute/Quarantine`.
- Process/command line/parent đã tác động file.
- Rule bắt vì file path, file type, hash reputation, webshell, ransomware, mass delete, sensitive read hay tamper.

Đánh giá rule intent:
- Nội dung file/action có khớp mục tiêu rule không.
- Nếu rule intent mismatch và không có evidence độc hại -> nghiêng FP.
- Nếu rule intent match nhưng thiếu context cốt lõi -> Need Enrichment.

**Result:** `informational`

### Bước 2: Kiểm tra file/hash reputation
Chỉ dùng field factual trong file enrichment:
- `malicious_count >= 25`: `malicious`, khả năng cao là mã độc. **⛔** hash hiện diện trên host + con số này = bằng chứng QUYẾT ĐỊNH TP; tên thư mục KHÔNG trung hoà (TP-floor GATE ⛔ đầu file + BLOCKER Bước 6).
- `malicious_count >= 5` và `< 25`: `malicious` hoặc `suspicious`, thường là crack, riskware, attack tool hoặc malware.
- `0 < malicious_count <= 5`: `suspicious`, tỉ lệ độc thấp nhưng phải xem path/action/process.
- `malicious_count = 0` với hash đúng file đang xét: có thể `clean`, nhưng không đủ để FP nếu path/action/process đang nghi.
- Hash không tìm thấy hoặc không có hash: `unknown`, cần lấy file/hash/content.
- Threat labels, contacted URLs/IPs, dropped files, behavior, community comment chỉ được dùng nếu có trong input.
- Attack tool/riskware/crack/keygen/activator rõ ràng -> `malicious` dù VT thấp.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 3: Kiểm tra đường dẫn, tên file và webshell indicator
Đánh giá file path/name:
- Path nhạy cảm: `C:\`, `Windows`, `System32`, `SysWOW64`, `Windows\Temp`, `Windows\Tasks`, `System32\Tasks`, `ProgramData`, `%AppData%`, `%LocalAppData%`, `%Temp%`, `Users\Public`, web root/upload/static folder.
- File thực thi/DLL/script trong path nhạy cảm mà hash không có reputation -> `suspicious`.
- File thực thi chuẩn nằm trong thư mục nhạy cảm có thể bị lợi dụng bằng **DLL Sideloading** hoặc **Search Order Hijacking**; không FP nếu thiếu signature/hash/content/process tree.
- File name giả mạo system/app hợp lệ, double extension, random name, extension script trong upload/static folder -> `suspicious`.
- Webshell indicator: file trong web directory/upload/static, tên giả mạo `css/js/style/index/test/404/403/500`, request parameter có command, content length thay đổi bất thường, code có execute/upload/download/obfuscation. Nếu đạt >=2 nhóm indicator hoặc content chắc chắn webshell -> `malicious`.
- Nếu file path đúng chuẩn ứng dụng và có owner/change evidence rõ -> có thể `clean`.
- **⭐ ĐỌC `file_content_signature`:** nếu raw cấp marker nội dung (`<?php`, `<%`, `eval(`, `system(`, base64→eval, script header) → ĐỌC và suy luận đây là loại gì (webshell/dropper/script) và LÀM GÌ, thay vì chỉ đếm indicator.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 4: Kiểm tra user tạo/tác động file và process liên quan
Đánh giá user và process:
- Admin/user đăng nhập/TrustedInstaller/installer/patch process có action phù hợp, trong maintenance/change window rõ -> `clean`.
- User chạy dịch vụ như Web, Database, IIS, MSSQL, Tomcat, nginx tạo/sửa/xóa script/executable/web file bất thường -> `suspicious` hoặc `malicious` vì có thể bị exploit.
- Process đọc credential/sensitive file, drop executable, mass delete/encrypt/rename, sửa startup/service/task -> `malicious`.
- Command line có download cradle, reverse shell, credential dump, obfuscation, tool tấn công, crack/license bypass -> `malicious`.
- Thiếu command line/process/parent khi verdict phụ thuộc các field này -> `unknown`.
- **⭐ TRACE NGUỒN GỐC + THỰC THI:** dùng `file_origin` + `process_lineage_evidence` dựng chuỗi *file tới bằng cách nào* (download từ URL → drop tới path → execute bởi process → spawn child). `executed`="no"/quarantined → file mới bị phát hiện/chặn, KHÔNG FP chỉ vì thiếu process; `executed`="yes" → đánh giá hậu quả thực thi.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 5: Kiểm tra tần suất, timeline và tác động
Nếu có log frequency/timeline:
- Nhiều file bị tạo/sửa/xóa/rename/encrypt trong thời gian ngắn -> `malicious` nếu giống ransomware/wiper, `suspicious` nếu chưa đủ context.
- File được tạo ngay trước process/network/auth bất thường -> `suspicious`/`malicious` tùy evidence.
- Một action đơn lẻ có giải thích nghiệp vụ rõ -> có thể `clean`.
- Không có timeline/frequency -> `unknown`, không suy diễn.

**Result:** `malicious | suspicious | clean | unknown`

### Bước 6: Tổng hợp và kết luận
Kết luận `True Positive` khi có một trong các evidence:
- Hash/file reputation malicious, attack tool, riskware/crack/policy violation rõ.
- Webshell evidence rõ hoặc >=2 nhóm indicator webshell.
- File/action liên quan credential dump, persistence, execution, ransomware/mass delete, tamper security, unauthorized sensitive read.
- Service/Web/Database account tạo/sửa file executable/script bất thường trong web/system/temp path mà không có authorization.
- Rule intent match và process/command/action cho thấy tấn công.
- **Vulnerability-detection rule + gói/version dính CVE hiện diện** = `True Positive` 80-85 "vulnerability confirmed" (theo GATE Vulnerability-detection đầu file) — KHÔNG đòi hash/process, KHÔNG hạ FP vì "chưa khai thác".

**⛔ BLOCKER (kiểm TRƯỚC khi xét ngoại lệ research):** nếu `malicious_count` ≥ 5 HOẶC named-threat HOẶC `edr_action` ∈ {quarantined, isolated, remediated} → **NGOẠI LỆ research/PoC KHÔNG áp ở mọi mức**, verdict = `True Positive`; tên thư mục gợi ý research/sandbox/bazaar/malware/cage KHÔNG mở lại nhánh FP. Ngoại lệ research CHỈ dành cho hash unknown/`not_found` + KHÔNG execution/persistence + reputation không xấu.

**⛔ NGOẠI LỆ đích danh — research/PoC context (chỉ áp khi KHÔNG có named-threat/EDR action VÀ hash KHÔNG malicious trên VT):** file nằm trong thư mục `demo`/`test`/`poc`/`lab`/`research` (hoặc project path developer nhận diện rõ) **VÀ** không có evidence execution/persistence/lateral/exfil **VÀ** reputation chỉ là unknown/`not_found` → KHÔNG chốt TP chỉ vì tên/pattern file "giống malware/PoC"; verdict = `Need Enrichment` (xác nhận với chủ máy mục đích research) hoặc `False Positive` 80-85 khi có thêm bằng chứng research được phép (user là dev/researcher, file PoC tự viết cục bộ, không lan sang host khác).
Kết luận `False Positive` chỉ khi:
- Không có step `malicious`.
- File reputation/path/action/process đều phù hợp nghiệp vụ.
- Có evidence benign rõ: owner/change ticket/maintenance, signed/trusted installer đúng file, approved deployment, backup/patch/scan job.
- Rule intent mismatch rõ.

Kết luận `Need Enrichment` khi:
- Thiếu hash/content/file path/process/command line/actor mà verdict phụ thuộc vào đó.
- File trong path nhạy cảm hoặc service account tác động file nhưng chưa có content/hash/owner.
- VT thấp/unknown nhưng path/action/process đang suspicious.
- Cần xác minh owner, change ticket, business justification, collect file, EDR timeline.

`Enrichment_Requests` phải nêu rõ cần lấy gì: file hash/content, signature, owner, change ticket, EDR process tree, file timeline +/-1h, web access log nếu nghi webshell.

---

## Confidence guideline

| Confidence | Điều kiện |
|------------|-----------|
| 90-100 | Evidence TP/FP rõ, file/action/process/path khớp và có factual reputation/authorization |
| 80-89 | Đủ step chính, chỉ thiếu step phụ |
| 70-79 | < 80 → Need Enrichment (chưa đủ tin cho TP/FP) |
| 40-60 | Need Enrichment |

FP thiếu command line/process/hash/content → Need Enrichment (không đạt sàn 80). FP thiếu owner/change evidence không vượt 80. FP cho file config nhạy cảm (web.xml, *.conf, file cấu hình ứng dụng) mà KHÔNG có nội dung file để loại trừ injection/sửa đổi → Need Enrichment, yêu cầu nội dung file.
`Confidence_Reason` phải giải thích rõ evidence/step nào làm tăng confidence, missing/unknown/conflict nào làm giảm hoặc cap confidence. Với `Need Enrichment`, phải nêu cụ thể thiếu dữ liệu nào khiến confidence nằm ở mức đó. Không ghi chung chung kiểu "dựa trên phân tích ở trên".

---

### YÊU CẦU ĐẦU RA

## Bổ sung discriminators TP/FP (category-specific)

Bổ sung cho các Bước ở trên (existence-gated: chỉ áp khi field/evidence có trong `alert_details`/`_source_evidence`; thiếu → ghi unavailable, không suy diễn; KHÔNG hardcode verdict).

- **(Bước 2) VT contacted-URL/domain ratio:** khi VT relations có `contacted_urls`/`contacted_domains` + malicious ratio cao → behavioral malicious-support; coi là telemetry tổng hợp của hash, không khẳng định host này đã liên hệ.
- **(Bước 3) DLL sideloading path:** file `.dll` ở thư mục cha chứa LOLBin/app hợp lệ NHƯNG hash không khớp baseline DLL hệ thống → nghiêng sideload TP.
- **(Bước 4) File origin/download-context:** `file_origin`/download source = internet/email attachment/temp + executed = nghiêng nghi; origin từ installer/update hợp lệ = giảm nghi.
- **(Bước 4) Execution-chain/parent:** parent đáng ngờ (rundll32 + DLL lạ, powershell -enc, cmd /c payload, service account exec bất thường) → TP-support.
- **(Bước 4) Persistence context:** chuỗi drop file rồi đăng ký scheduled-task/service/autostart → TP-support.
- **(Bước 6) Legitimacy positive-list:** hash thuộc whitelist HOẶC chữ ký hợp lệ của trusted publisher → benign-support (≥5 prior-FP chỉ cap, KHÔNG auto-FP).

BẮT BUỘC trả về JSON thuần:

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Xác định thông tin cảnh báo và Rule Intent Match", "Detailed_Analysis": "- Evidence: thời điểm, rule, host, user, file, action, process.\n- Rule intent: rule trigger vì điều kiện nào và có khớp evidence không.\n- Kết luận step: nêu rule_intent_match và dữ liệu còn thiếu.", "Result": "informational"},
    "Step_2": {"Step_Title": "Kiểm tra file/hash reputation", "Detailed_Analysis": "- Evidence: VT/hash/signature/behavior factual fields.\n- Missing/Conflict: ghi unknown nếu thiếu provenance hoặc kết quả mâu thuẫn.\n- Kết luận step: reputation hỗ trợ malicious/suspicious/clean ở mức nào.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_3": {"Step_Title": "Kiểm tra đường dẫn, tên file và webshell indicator", "Detailed_Analysis": "- Evidence: path, file name, web root/upload, sensitive path.\n- Missing/Conflict: ghi rõ khi thiếu path hoặc không có webshell indicator.\n- Kết luận step: path/name có bất thường hay phù hợp nghiệp vụ.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_4": {"Step_Title": "Kiểm tra user, process và command line", "Detailed_Analysis": "- Evidence: user, process, parent, command line.\n- Missing/Conflict: ghi rõ khi thiếu process lineage hoặc command line.\n- Kết luận step: execution context có phù hợp action không.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_5": {"Step_Title": "Kiểm tra tần suất, timeline và tác động", "Detailed_Analysis": "- Evidence: timeline, mass action, related process/network/auth evidence.\n- Missing/Conflict: ghi rõ dữ liệu tần suất/tác động không khả dụng.\n- Kết luận step: phạm vi ảnh hưởng và mức độ rủi ro.", "Result": "malicious|suspicious|clean|unknown"},
    "Step_6": {"Step_Title": "Tổng hợp và kết luận", "Detailed_Analysis": "- Evidence tổng hợp: các step quyết định Status.\n- Missing/Conflict: dữ liệu còn thiếu có thể đổi verdict/confidence.\n- Kết luận step: lý do chọn TP/FP/NE; historical context chỉ để tham khảo.", "Result": "True Positive|False Positive|Need Enrichment"},
    "Summary": "Tóm tắt lý do kết luận"
  },
  "Status": "True Positive|False Positive|Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Lý do chọn confidence: evidence mạnh/yếu, missing evidence, conflict, confidence cap nếu có.",
  "Response_Actions": ["TP/NE: hành động khuyến nghị"],
  "Investigation_Requests": [{"intent": "Mục đích query", "why_raises_confidence": "đang X → lên Y nếu log cho thấy ...", "action": "search_process|search_file", "target_field": "file_path|process_name|user|hostname|uri_path|http_status", "target_value": "value từ alert", "time_range_hours": 1}],
  "Enrichment_Requests": ["NE HOẶC Confidence < 90: field thiếu / reputation / enrichment KHÔNG query SIEM được (log SIEM đặt ở Investigation_Requests); [] chỉ khi Confidence >= 90 và không phải NE"],
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
