# CLAUDE.md

File này cung cấp hướng dẫn cho Claude Code (claude.ai/code) khi làm việc với mã nguồn trong repository này.

## Cấu trúc repository

Monorepo với hai git submodule nằm ở repo GitHub riêng:

- `backend/` — API Django 6 + DRF + Channels, các worker, và agentic runtime.
- `frontend/` — SPA Vite + React 19 + Ant Design 6 (pnpm).
- `cli/` — `asp-cli` (Typer/httpx), publish lên PyPI dưới lệnh `asp`; gọi vào `/api/agent/v1/`.
- `deploy/` — công cụ release (`release_tool.py`, `release-manifest.json`) và bundle production `asp-compose`.
- `development/docker/compose.yaml` — dependency local: Postgres 17 / redis-stack / RustFS.
- `docs/specs/<version>/` — spec ở mức triển khai (tiếng Trung). Spec `Confirmed` là **binding**; không tự ý thay đổi hành vi đã confirmed.
- `asp-doc/` (submodule) — site tài liệu VitePress. `asp-marketplace/` (submodule) — code plugin Claude Code. Cả hai thường chưa init; chỉ chạy `git submodule update --init <name>` khi người dùng yêu cầu.
- `AGENTS.md` — guideline hành vi chung cho LLM coding (simplicity, surgical changes); nội dung project-specific đã được hợp nhất vào đây.

## Lệnh thường dùng

Backend (chạy từ `backend/`, Python 3.14, quản lý dependency bằng `uv`; interpreter của venv là `backend/.venv/Scripts/python.exe`):

```powershell
uv sync
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver           # WSGI, không có websocket
.\.venv\Scripts\python.exe -m uvicorn asp.asgi:application --host 127.0.0.1 --port 8001   # ASGI, cần cho /ws
.\.venv\Scripts\python.exe manage.py test                # toàn bộ test
.\.venv\Scripts\python.exe manage.py test apps.webhook   # theo app / module / TestCase
.\.venv\Scripts\python.exe manage.py spectacular --file openapi.yaml
.\.venv\Scripts\python.exe manage.py createsuperuser     # admin ASP là Django superuser
```

Worker (mỗi worker là một management command; tất cả đều nhận `--once` và `--interval`, nên `--once` là cách nhanh nhất để chạy thử một vòng lặp):

```powershell
manage.py run_agentic_module_worker          # đọc Redis stream -> Module
manage.py run_agentic_case_analysis_worker   # job phân tích case bằng LLM
manage.py run_agentic_playbook_worker        # chạy Playbook
manage.py run_elk_action_worker              # action cho alert ELK
manage.py run_dashboard_cache_worker         # snapshot dashboard
manage.py run_qradar_offense_worker          # poll QRadar offense
manage.py run_trellix_detection_worker       # poll Trellix EDR detection
manage.py run_notification_worker            # gửi Telegram notification
```

Frontend (chạy từ `frontend/`, Node 24, pnpm 10):

```powershell
pnpm install
pnpm dev            # proxy /api và /ws sang http://localhost:8001
pnpm exec eslint .
pnpm exec tsc -b
```

CI (`.github/workflows/ci.yml`) chạy: `python deploy/release_tool.py check`, backend `manage.py check` + `spectacular` + `test`, frontend `eslint` + `tsc -b` + `build`, và bước validate compose package — bước này **fail nếu Module/Playbook/định nghĩa SIEM mẫu của môi trường dev lọt vào release template**.

Mock data: `manage.py shell -c "from mock.import_mock_data import run; run()"` (idempotent, mỗi lần chạy tạo một batch mới).

Seed: `manage.py seed_branding --fixture-dir <dir>` (nạp identity thương hiệu từ fixture), `manage.py seed_soc_automation` (nạp 13 rule automation mặc định, thêm `--disable` nếu chưa muốn bật).

## Kiến trúc

### Pipeline tiếp nhận alert

Webhook (`apps/webhook`) nhận payload từ Splunk / Kibana / QRadar và ghi từng event vào một **Redis Stream đặt tên theo detection rule** (`search_name` / `rule.name` / rule name của QRadar offense). `run_agentic_module_worker` phát hiện các script Module, đọc stream tương ứng qua consumer group, và mỗi Module map event thô sang domain object của ASP thông qua `apps.agentic.services.alerts.create_alert_with_context` — hàm này correlate vào Case đang tồn tại theo `correlation_uid` (được bảo vệ bằng Postgres advisory lock), tạo Alert, Artifact, Enrichment, rồi enqueue một `CaseAnalysisJob`. `run_agentic_case_analysis_worker` sau đó chạy điều tra bằng LLM (`apps/agentic/analysis/`) và ghi ngược các field `*_ai` (verdict/severity/impact/priority/confidence) cùng báo cáo có cấu trúc vào Case.

Tóm lại: **tên stream chính là hợp đồng** giữa một rule của SIEM và Module xử lý nó. Mọi nguồn alert mới (QRadar offense, Trellix detection) đều phải tuân theo hợp đồng này, không mở đường đi tắt.

### Runtime của script (Module và Playbook)

`apps/agentic/runtime/loader.py` nạp file `.py` thuần theo đường dẫn và lấy ra class có tên đúng là `Module` hoặc `Playbook`, kế thừa `BaseModule` / `BasePlaybook` (`runtime/base.py`). Relative import trong file script bị từ chối.

- Module: chỉ nằm ở `backend/custom/modules/`. Khoá theo `STREAM_NAME`.
- Playbook: `backend/playbooks/` (built-in) được phủ bởi `backend/custom/playbooks/` — trùng tên file thì bản trong custom **che** bản built-in. `RISK_LEVEL` phải là một trong Low/Medium/High/Critical, nếu không định nghĩa sẽ bị từ chối lúc scan.
- Prompt và data file nằm dưới `backend/custom/data/{modules,playbooks,siem}/<slug>/`, phân giải theo ngôn ngữ qua `BasePlaybook.read_prompt()` (`<name>_<lang>.md`).
- Dependency pip bổ sung cho script custom khai báo trong `backend/custom/requirements.txt`; ở production, compose stack cài chúng vào một volume riêng nằm trên `PYTHONPATH`.

Playbook run là các hàng trong DB (`apps.playbooks.Playbook` với `job_status`), claim bằng `select_for_update`; tiến độ báo qua `self.add_run_message(...)`, và message/remark được scrub các pattern `authorization`/password/token/secret trước khi lưu. Các hàng `Running` mồ côi bị đánh fail khi worker khởi động.

**SOC playbooks (bộ 20 playbook markdown):** wrapper mỏng `custom/playbooks/soc_*.py` (12 phân tích theo category alert, 5 check IOC, 3 meta), tất cả dùng chung runner `apps/agentic/services/soc_playbook.py`: serialize case theo budget của provider → bổ sung TI enrichment cho artifact → LLM với system prompt là file markdown (`custom/data/playbooks/soc_*/System_<lang>.md`) → bóc/repair JSON → lưu Enrichment (`type=OBSERVATION`, `provider=ASP`, uid `soc-playbook:<slug>:<id>`).

**Playbook automation:** rule trong DB (`PlaybookAutomationRule` — keywords khớp substring trên title+rule name, `min_severity`, `priority`, cờ `fallback`) + singleton bật/tắt và trần số playbook/case. Engine `schedule_automatic_playbooks` chạy trong `create_alert_with_context` khi tạo case, dedup theo (case, playbook name), lỗi bị nuốt để không hỏng pipeline ingest. Seed mặc định: `manage.py seed_soc_automation`. UI: Settings → Playbook Automation.

### Worker

Tất cả worker đi qua `apps.common.worker_runner.run_worker`, lo phần vòng lặp, interval, `--once`, invalidate cache runtime-config mỗi vòng, vai trò ghi log file, và báo heartbeat về Redis qua `apps.common.worker_health` (hiển thị trong admin UI). Worker mới **phải** dùng cơ chế này thay vì tự viết vòng lặp.

### Notification (`apps/notifications`)

Outbox pattern: event trong hệ thống (case mới, verdict thay đổi, playbook xong…) tạo `NotificationEvent`, routing rule map event → channel (hiện chỉ Telegram). `run_notification_worker` đọc outbox, **gộp event trong cửa sổ thời gian** (bắt buộc, không phải tuỳ chọn) để chống bão tin, render message (escape HTML cho Telegram), gửi, và ghi kết quả. Lỗi gửi Telegram **không được** làm hỏng pipeline triage — bắt exception, ghi log, retry sau.

Quy ước message triage (xem template `custom/data/notifications/triage.*_<lang>.md`):
- **Khối field render tất định từ DB** (payload build trong `service.emit_triage_result`); LLM chỉ đóng góp `reasoning_vi` (cắt 3–5 câu, FP/benign 1–2 câu). Field trống hiện `— (không có dữ liệu)`, không ẩn.
- Template engine: `{{var}}` escape tự động, `{{{var}}}` chèn HTML dựng sẵn (title link, missing block), comment `<!-- -->` bị lọc — danh sách thuật ngữ **không dịch** nằm trong comment của template.
- Title là link tới case; nếu `asp_base_url` rỗng/localhost thì hiện `[link chưa cấu hình]`, không render `<a>`. Emoji theo verdict: 🔴 TP High/Critical, 🟠 TP còn lại, 🟡 needs_human/needs_more_info, 🟢 FP/benign.
- Notify được emit từ `store_assessment` (triage/assessment.py) qua `on_commit`; `min_confidence` của destination **không áp** cho event `needs_human` (bản chất event là confidence thấp).
- Nút verdict inline trên Telegram: **roadmap**, chưa làm (bot token hiện bị consumer khác poll getUpdates → 409).

### Cấu hình

Hai lớp: env của process (`backend/.env`, xem `.env.example` — Postgres, Redis, RustFS/S3, Django) và **runtime config lưu trong database** (`apps/settings/models.py`: LLM provider, Splunk/ELK/QRadar, Trellix EDR, OTX/OpenCTI, MCP server, MSSP, Telegram, LDAP, CMDB, biến custom). Runtime config đọc qua `apps.settings.runtime_config`, có `lru_cache` — mọi thay đổi các model đó **bắt buộc gọi `invalidate()`**, và worker refresh lại mỗi vòng lặp.

### Môi trường chạy

- **Local dev:** `development/docker/compose.yaml` chỉ chạy dependency (Postgres 17, redis-stack, RustFS). Backend và frontend chạy trực tiếp trên host. Không có local venv trên Windows khi dùng Docker full-stack.
- **Production / full-stack:** `deploy/asp-compose/compose.yaml` — 12 service: frontend (nginx), web (gunicorn), asgi (uvicorn), 8 worker, postgres, redis-stack, rustfs, plus init/migrate container. Image build: `asp-backend:local`, `asp-frontend:local`. Custom script/data mount qua `./custom:/app/custom`.
- **Test:** Django test runner (`manage.py test`), không dùng pytest. Frontend không có test framework — CI chỉ chạy `eslint` + `tsc -b` + `vite build`.

### Integration layer (`backend/integrations/`)

Sáu module tích hợp bên ngoài, tất cả đọc cấu hình qua `runtime_config`:

- `siem/` — multi-SIEM: QRadar (Ariel + offense), Splunk, ELK. `registry.py` phân phối query builder theo backend. `siem/guard.py` (`aql_guard`) chặn cú pháp ghi/xoá cho query AQL do LLM sinh ra. Mọi query qua `siem/audit.py`.
- `edr/` — Trellix EDR: OAuth2 client-credentials qua IAM (`trellix_auth.py`), token cache Redis, tự refresh. `trellix_guard.py` chặn hành động containment khi cờ tắt.
- `llm/` — lớp gọi LLM dùng chung, **mọi LLM call trong hệ thống đi qua đây**:
  - `llmapi.py`: wrapper OpenAI-compatible, timeout/retry riêng, audit metadata (`model_name`, tokens, latency). **Failover đa model**: mỗi provider row có `model` chính + `fallback_models` (list); `FailoverChatModel` thử mọi cặp (provider, model) theo priority, cặp dính quota/5xx/timeout vào cooldown Redis 120s, model không hỗ trợ json_mode tự bị gỡ `response_format`. Chỉ raise khi tất cả candidate đều lỗi.
  - `structured.py`: gọi LLM và parse output có cấu trúc — mô tả schema trong prompt, **không dùng** native tool calling hay `json_schema` strict.
  - `extraction.py`: trích xuất + repair JSON từ response (bóc code fence, sửa trailing comma, cắt phần thừa).
  - `budget.py`: cắt/ưu tiên input theo ngân sách token cấu hình.
  - `anonymization.py`: ẩn danh hoá dữ liệu trước khi gửi LLM, mặc định tắt, bật qua cờ runtime.
- `threat_intel/` — OTX + OpenCTI + VirusTotal provider, tra cứu IOC. VirusTotal nhận **nhiều API key** (`api_keys` list trong `ThreatIntelVirusTotalConfig`), xoay vòng qua Redis counter dùng chung mọi worker; key 429/401 bị bỏ qua trong phút hiện tại. Provider tự đăng ký vào `get_providers()` khi enabled + có key, từ đó chảy vào TI enrichment playbook và IOC verification.
- `mcp/` — MCP client cho IOC verification qua web tool.
- `cmdb/` — tra cứu asset/identity từ CMDB.

### Branding

Branding cấu hình được qua `BrandingConfig` (singleton model trong `apps/settings/models.py`): tên sản phẩm, màu primary/accent, logo (full/compact/mark/dark), favicon, ảnh nền login. Frontend load qua API GET `/api/settings/branding/` (public, không cần auth), apply vào Ant Design theme (`ThemedApp.tsx`), document title, và favicon (`BrandingProvider.tsx`). Giá trị mặc định neutral ("SOC Platform" / "SOC" / `#1677ff`) nằm trong `brandingContext.ts`; identity SHB được nạp qua `manage.py seed_branding --fixture-dir <path>` từ fixture JSON + file ảnh.

### Quy ước API

- REST dưới `/api/` (auth bằng JWT hoặc API key, `apps.accounts.authentication.ApiKeyAuthentication`), OpenAPI tại `/api/schema/`, Swagger tại `/api/docs/`.
- Một surface riêng, cố ý giữ ổn định, dành cho agent nằm ở `/api/agent/v1/` (`apps/agent_api`) phục vụ CLI, plugin Claude Code và các harness agent khác — tìm kiếm SIEM, threat intel, CMDB, case, playbook run, upload file. `cli/src/asp_cli/spec/operations.json` phản chiếu surface này và **phải được cập nhật cùng lúc**.
- `apps/common` chứa các phần cross-cutting: cursor pagination, backend query `advanced_filters` dạng JSON, `metadata.py` (điều khiển cấu hình cột/filter của frontend từ field model Django qua `RESOURCE_CONFIGS`), ID dễ đọc (`case_000123`, dựa trên Postgres sequence), audit signal, exception handler.
- Realtime: Channels trên Redis; `apps/realtime` publish sự kiện comment/inbox tới group theo user và theo record. Websocket chỉ hoạt động dưới ASGI server.

### Frontend

Các UI dạng bản ghi đều **điều khiển bằng cấu hình**: `src/config/resources.tsx` khai báo từng resource (cột, tab, filter, view chi tiết) và các component generic `ResourceListPage` / `DataTable` / `ResourceDetailRoute` render ra. Metadata cột và filter lấy từ API metadata của backend. Thêm một field vào list/detail thường chỉ là sửa `resources.tsx` (cộng serializer/metadata phía backend), không phải viết page mới. Trạng thái auth là một zustand store nhỏ (`src/stores/auth.ts`); axios interceptor gắn JWT và redirect về login khi gặp 401.

---

## Môi trường triển khai tại SHB

Đây là bối cảnh khách hàng mà mọi hạng mục đang phát triển phải bám theo. Các dữ kiện dưới đây **đã được xác nhận**, dùng làm căn cứ thiết kế, không cần hỏi lại.

- **SIEM: IBM QRadar on-prem.** API token của ASP có **toàn quyền đọc**, không có quyền ghi. Client QRadar phải read-only tuyệt đối; mọi khả năng ghi (đóng offense, thêm note, sửa reference set) chỉ để interface, đặt sau cờ `allow_write` mặc định `False`.
- **EDR: Trellix EDR bản SaaS.** Xác thực OAuth2 client-credentials qua Trellix IAM, token cache trong Redis và tự refresh. Không làm nhánh ePO on-prem. Scope hành động chỉ xin khi `allow_containment` được bật.
- **MSSP: Viettel Cyber Security (VCS).** Tier 1 của VCS xử lý alert/case/ticket trên SOAR của họ. SOAR có API đọc alert/case/ticket và xuất báo cáo. ASP là **lớp AI độc lập**: triage lại toàn bộ alert và audit chất lượng xử lý của Tier 1.
- **LLM: mô hình tự build, endpoint tương thích OpenAI** (`/v1/chat/completions`), chạy nội bộ SHB.
- **Ngôn ngữ người dùng cuối: tiếng Việt.** Mọi prompt/template phải có tối thiểu `_vi` và `_en`.
- Splunk và ELK vẫn phải hoạt động bình thường. QRadar và Trellix là integration **bổ sung ngang hàng**, không thay thế.

### Ràng buộc khi gọi LLM

Vì LLM là mô hình self-host tương thích OpenAI:

- Không hard-code endpoint hay tên model của bất kỳ nhà cung cấp nào. `base_url`, `model`, `api_key` đều lấy từ runtime config.
- **Không phụ thuộc vào `response_format: json_schema` strict, cũng không phụ thuộc vào native tool/function calling** — model self-host thường không hỗ trợ hoặc hỗ trợ không ổn định. Mô tả schema trong prompt, bật `response_format: {"type":"json_object"}` chỉ khi cờ `supports_json_mode` được bật, rồi **luôn** đi qua lớp trích xuất + repair JSON (bóc code fence, cắt phần thừa đầu/cuối, sửa dấu phẩy thừa) trước khi validate schema.
- Mọi prompt phải có cơ chế cắt/ưu tiên input theo ngân sách token cấu hình được; giả định context window và throughput hạn chế hơn model thương mại.
- Timeout và retry riêng cho LLM call; LLM lỗi không được làm hỏng pipeline tiếp nhận alert.
- Dữ liệu không rời khỏi SHB khi gọi LLM, nên lớp ẩn danh hoá mặc định **tắt** — nhưng vẫn phải implement ở tầng gọi LLM dùng chung để bật lại được bằng một cờ.

### Guardrail bắt buộc cho phần AI

- Mọi query do LLM sinh ra, trước khi chạy vào QRadar/Trellix, phải qua **sanitizer read-only**: chặn cú pháp ghi/xoá, ép time range trong trần cấu hình, ép `LIMIT`, giới hạn số dòng trả về. Query bị từ chối phải trả lý do rõ ràng để LLM tự sửa và retry có giới hạn, không được im lặng bỏ qua.
- Mọi query đã chạy và mọi LLM call phải vào **audit log**: ai, cái gì, khi nào, tokens, số dòng, thời gian chạy.
- Nội dung lấy từ web/MCP/log của attacker là **dữ liệu không tin cậy**. Bọc trong delimiter, gắn nhãn rõ, không bao giờ coi là instruction, và có bước lọc prompt-injection.
- **Không tự động thực hiện hành động containment.** Mọi hành động thay đổi trạng thái hệ thống nằm sau cờ runtime + Playbook `RISK_LEVEL = "Critical"` + phê duyệt của người, mặc định trả về dry-run plan.
- Kết quả AI dùng để ra quyết định phải kèm metadata truy vết: `model_name`, `prompt_version`, `prompt_hash`, tokens, latency, raw response.
- Evidence trong output của LLM phải **tham chiếu tới bản ghi thật** trong DB. Không chấp nhận evidence do model tự mô tả mà không truy ngược được.

---

## Các hạng mục đang phát triển

Chi tiết triển khai nằm trong `docs/specs/<version>/`. Phần dưới chỉ là bản đồ để định vị; khi có mâu thuẫn, spec `Confirmed` thắng.

| Mã | Hạng mục | Phạm vi chính |
|---|---|---|
| S1 | QRadar connector | Client Ariel/offense read-only, `aql_guard`, webhook `POST /api/webhook/qradar/` + `run_qradar_offense_worker`, dùng chung `normalize_offense()` |
| S2 | Trellix EDR connector | OAuth2 IAM + cache token, detection/host/RTS/historical search, `run_trellix_detection_worker`, containment sau cờ |
| S3 | AI Triage toàn bộ alert | Tầng pre-triage tất định (dedup, allowlist có hạn, CMDB/LDAP/intel), kết quả triage có cấu trúc + MITRE + evidence, ngưỡng confidence → `needs_human`, cho phép người override |
| S4 | Clustering + Threat hunting | `run_agentic_correlation_worker` gom alert theo entity graph; `HuntPlan`/`HuntQuery`/`HuntFinding`; hai chế độ `advisory` (mặc định) và `auto` có budget |
| S5 | Attack Discovery | Worker định kỳ sinh `AttackDiscovery` từ alert đang mở, dedup theo fingerprint entity+technique, promote thành Case |
| S6 | IOC verification qua Web MCP | MCP client dùng chung, pipeline normalize → cache → OTX/OpenCTI → web MCP → LLM tổng hợp; verdict phải có reference thật, không có nguồn thì `unknown` |
| S7 | MSSP audit | Sync ticket VCS SOAR qua API (upsert + lịch sử trạng thái), matching engine, `AuditFinding` theo category, rubric chấm closure note, dashboard + export |
| S8 | Thông báo Telegram | Cấu hình bot token/chat id/topic id trên dashboard, outbox + `run_notification_worker`, gộp tin chống bão, escape HTML, gửi tóm tắt + link |

### Nguyên tắc nghiệp vụ không được vi phạm

- **S3:** verdict `false_positive` phải nêu được thuộc nhóm lý do nào. Thiếu context tối thiểu thì trả `needs_more_info`, không đoán.
- **S4:** chế độ mặc định là `advisory` — sinh query và lý do cho SOC Tier 3, không tự chạy. Bật `auto` là quyết định có ý thức, kèm budget.
- **S6:** không bao giờ truy cập trực tiếp chính IOC đang điều tra (không fetch URL nghi ngờ). Chỉ tra qua nguồn trung gian.
- **S7:** đây là quy trình **hai chiều**. Mỗi `AuditFinding` phải có người review; khi người review xác định AI mới là bên sai thì ghi nhận vào chỉ số độ chính xác của AI, và dashboard hiển thị song song tỉ lệ sai của Tier 1 lẫn của AI. Thống kê mặc định ở mức tổng hợp/đội, không xếp hạng cá nhân. Không có chức năng tự động gửi kết quả audit sang VCS.
- **S8:** lỗi Telegram không bao giờ được làm hỏng pipeline triage. Gộp sự kiện trong cửa sổ thời gian là bắt buộc, không phải tuỳ chọn.

---

## Quy ước dự án

- Không chạy `superpower` skills trừ khi người dùng yêu cầu rõ ràng. Khi `superpower:writing-plan` bị tắt, triển khai trực tiếp từ spec.
- Không viết test code khi đang implement một tính năng, trừ khi người dùng yêu cầu.
- `docs/TODO.md` do người dùng tự bảo trì — không được sửa, và không nhắc tới nó trong commit.
- Mọi thay đổi model phải kèm Django migration trong cùng commit.
- Frontend: ưu tiên tính năng sẵn có của Ant Design và CSS mặc định; chỉ customize khi mặc định không làm được. Không bao giờ chạy `pnpm build` chỉ để kiểm tra một thay đổi.
- Docs (`asp-doc`): cập nhật trang `zh` trước, chốt xong rồi mới mirror sang `en`. Placeholder ảnh không có caption, đặt tên `img.png`, `img_1.png`, … Không build VitePress trừ khi được yêu cầu.
- Release theo `docs/release-runbook.md` — bump version ở CLI, compose env và docs đều do `deploy/release-manifest.json` + `deploy/release_tool.py` điều khiển, không bao giờ sửa tay. Version hiện tại xem trong `deploy/release-manifest.json`.
- Resource mới hiển thị trên UI phải đăng ký ở cả `apps/common/metadata.py` (`RESOURCE_CONFIGS`) và `frontend/src/config/resources.tsx`.
- Endpoint mới ở `/api/agent/v1/` phải đồng bộ vào `cli/src/asp_cli/spec/operations.json` trong cùng commit.
- Script mẫu/demo phải đặt đúng chỗ theo cơ chế mà `deploy/release_tool.py check` kiểm tra; kiểm tra trước khi thêm file để không làm fail bước validate compose package.

## Cách dùng subagent

Repo này lớn và nhiều lớp trừu tượng, nên việc khảo sát dễ làm ngập context của phiên chính. Quy tắc:

- **Delegate cho subagent** những việc sinh ra nhiều output mà sau đó không cần đọc lại: quét toàn repo tìm call site, đọc hàng loạt file để trả lời một câu hỏi kiến trúc, chạy test và tóm tắt lỗi, khảo sát cách một integration hiện có được viết. Subagent chạy trong context riêng và chỉ trả về bản tóm tắt.
- **Giữ ở phiên chính** phần thiết kế và phần sửa file thực sự. Không giao cho subagent việc implement xuyên nhiều file, vì phiên chính chỉ nhận được tóm tắt chứ không nhận được ngữ cảnh đầy đủ của các quyết định đã đưa ra.
- Trước khi bắt đầu một hạng mục S1–S8, nếu cần hiểu code hiện có thì mở subagent khảo sát trước, rồi mới thiết kế trong phiên chính.
- Đọc `docs/specs/<version>/` là việc của phiên chính, không delegate — spec `Confirmed` là binding và cần nằm nguyên văn trong context khi implement.

## Checklist trước khi kết luận đã xong một hạng mục

1. `manage.py makemigrations --check --dry-run` — mọi thay đổi model đã có migration chưa?
2. Config runtime mới đã có chỗ gọi `invalidate()` chưa?
3. Worker mới có dùng `run_worker` không, `--once` chạy được không?
4. Resource mới đã đăng ký ở `metadata.py` và `resources.tsx` chưa?
5. Endpoint `/api/agent/v1/` mới đã vào `operations.json` chưa?
6. `python deploy/release_tool.py check`, `manage.py check`, `manage.py spectacular`, `pnpm exec eslint .`, `pnpm exec tsc -b` — pass hết chưa?
7. Có file sample nào nguy cơ lọt vào release template không?
8. Mọi query LLM sinh ra có qua sanitizer không? Mọi query đã chạy có vào audit log không?
9. Có chỗ nào dùng output LLM trực tiếp mà không validate schema không?
10. Liệt kê các giả định đã tự đặt và những gì cần verify với hệ thống thật của SHB/VCS.