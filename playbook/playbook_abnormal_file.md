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
