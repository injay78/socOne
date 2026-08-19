<h1 align="center">SOC One</h1>

<p align="center"><b>Nền tảng vận hành SOC ứng dụng Agentic AI — triage, điều tra và làm giàu cảnh báo tự động</b></p>

<p align="center">
  <a href="https://github.com/injay78/socOne">github.com/injay78/socOne</a>
</p>

<!-- screenshot: trang Login với branding -->

**SOC One** là nền tảng vận hành an ninh (SOC platform) xây trên nền Agentic AI: AI chủ động tham gia phân loại (triage), điều tra, làm giàu ngữ cảnh và tích lũy tri thức, giúp đội SOC thoát khỏi cảnh ngập alert và chuyển sang ra quyết định có AI hỗ trợ. Dự án phát triển từ mã nguồn mở [Agentic SOC Platform](https://github.com/funnywolf/agentic-soc-platform) (MIT) và được mở rộng cho môi trường vận hành thực tế của ngân hàng: QRadar, Trellix EDR, mô hình LLM self-host, quy trình playbook SOC tiếng Việt và cảnh báo Telegram.

---

## Khả năng chính

### 1. Gom bão alert thành số ít case xử lý được

Module tiếp nhận alert từ SIEM / EDR / Webhook qua Redis Stream, bóc tách IOC, và **gom các tín hiệu liên quan theo threat + host** vào cùng một Case (correlation có khóa ổn định + cửa sổ trượt 24h). Hàng trăm detection trùng lặp hội tụ về một case duy nhất kèm đầy đủ Alert, Artifact, Enrichment.

<!-- screenshot: danh sách Cases -->

### 2. AI điều tra tự động, có kiểm soát

Mỗi case mới được AI điều tra tự động: verdict (`true_positive` / `false_positive` / `benign_true_positive` / `needs_more_info`), severity, impact, priority, confidence và báo cáo có cấu trúc — dựng trên **dữ kiện tất định** (facts, CMDB asset context) với guardrail: evidence phải tham chiếu bản ghi thật trong DB, confidence thấp tự động chuyển `needs_human` chờ người xem.

<!-- screenshot: chi tiết case với báo cáo AI -->

### 3. Thư viện playbook SOC tiếng Việt tự vận hành

20 playbook phân tích chuẩn SOC viết bằng markdown (phishing, bruteforce, tấn công web, IP/domain độc, process/file bất thường, multicloud, kiểm tra IOC, attack hunter, QA review…). **Engine automation** tự chọn playbook phù hợp cho mỗi case mới theo keyword + severity (deterministic, không tốn LLM), có trần số playbook/case và rule fallback — cấu hình toàn bộ trên UI.

<!-- screenshot: Settings → Playbook Automation -->

### 4. Đa SIEM + EDR, một điểm điều tra

- **SIEM:** Splunk, Elastic, **IBM QRadar** (Ariel + offense, read-only tuyệt đối)
- **EDR:** **Trellix EDR** (SaaS, OAuth2 IAM, poll detection tự động)
- Mọi query do AI sinh ra đi qua **sanitizer read-only** và vào audit log

### 5. Threat intelligence tự động

AlienVault OTX, OpenCTI và **VirusTotal với pool nhiều API key xoay vòng** (tự né key hết quota). Kết quả TI chảy vào enrichment của artifact và pipeline xác minh IOC — verdict không có nguồn tham chiếu thật sẽ trả `unknown`, không đoán.

### 6. Thiết kế cho LLM self-host, chịu lỗi

- Endpoint bất kỳ tương thích OpenAI (kể cả proxy gom nhiều nguồn như 9router)
- **Failover đa provider / đa model**: mỗi provider khai báo model chính + danh sách model dự phòng; call tự chuyển qua từng cặp (provider, model) khi gặp quota/lỗi, kèm cooldown thông minh
- Cắt input theo ngân sách token của từng model; structured output qua mô tả schema trong prompt + JSON repair — **không phụ thuộc** native tool calling
- LLM chết không bao giờ làm hỏng pipeline tiếp nhận alert

<!-- screenshot: Settings → LLM Providers -->

### 7. Cảnh báo Telegram đọc được

Tin nhắn triage render **tất định từ DB** (LLM chỉ viết phần diễn giải tiếng Việt): title link về case kèm emoji theo verdict, khối field in đậm nhãn (Verdict/Severity/Hostname/Process/SHA256/MITRE…), field trống ghi rõ "— (không có dữ liệu)", escape HTML + scrub secret, và **gộp tin bắt buộc khi bão alert**. Lọc theo destination: min confidence, min severity, verdict.

<!-- screenshot: tin nhắn Telegram -->

### 8. Tích hợp sâu với Harness Agent (Claude Code, Codex…)

CLI `asp` (PyPI) phủ toàn bộ surface `/api/agent/v1/`: thao tác case/alert/artifact, search SIEM, tra threat intel, chạy playbook, upload file. Agent như Claude Code dùng trực tiếp CLI này để vận hành SOC bằng ngôn ngữ tự nhiên.

```bash
pip install asp-cli
asp auth login --api-url https://<host> --api-key asp_xxx
asp case list --page-size 10
asp ti query 1.2.3.4
```

### 9. Branding cấu hình runtime

Tên sản phẩm, màu sắc, logo, favicon đều là cấu hình trong DB — mã nguồn giữ nhận diện trung tính, identity nạp lúc triển khai bằng `manage.py seed_branding --fixture-dir <dir>`.

---

## Kiến trúc

```
SIEM/EDR/Webhook → Redis Stream (tên = detection rule)
    → Module worker (map event → Case/Alert/Artifact, correlation theo threat+host)
    → CaseAnalysisJob → AI investigation (facts + CMDB + TI → verdict, report)
    → Playbook automation (chọn playbook SOC theo category)
    → Notification outbox → Telegram
```

- **Backend:** Django 6 + DRF + Channels, PostgreSQL 17, Redis, RustFS (S3), 8 worker qua `run_worker` chung (heartbeat, `--once`, invalidate cache)
- **Frontend:** React 19 + Ant Design 6 + Vite, UI dạng bản ghi điều khiển bằng cấu hình (`resources.tsx`)
- **Runtime config trong DB:** LLM provider, SIEM, EDR, TI, Telegram, LDAP, CMDB, automation rule, branding — đổi trên UI, worker tự nhận sau mỗi vòng lặp

## Triển khai nhanh

```bash
# Full stack (12 service): frontend, web, asgi, 8 worker, postgres, redis, rustfs
cd deploy/asp-compose
cp .env.example .env        # chỉnh mật khẩu, S3, domain
docker compose up -d        # migrate tự chạy

# Seed
docker compose exec asp-web python manage.py createsuperuser
docker compose exec asp-web python manage.py seed_soc_automation   # 13 rule automation mặc định
docker compose exec asp-web python manage.py seed_branding --fixture-dir /app/custom/fixtures/<brand>/
```

Truy cập `https://<host>:8443`. Script custom (Module/Playbook/prompt/template) mount qua `./custom:/app/custom` — sửa không cần build lại image.

## Phát triển

```bash
# Dependency local: Postgres 17 / redis-stack / RustFS
docker compose -f development/docker/compose.yaml up -d

# Backend (Python 3.14, uv)
cd backend && uv sync
python manage.py migrate && python manage.py runserver

# Frontend (Node 24, pnpm 10)
cd frontend && pnpm install && pnpm dev
```

## Roadmap

- [ ] Nút xác nhận verdict (TP / FP nghiệp vụ / FP cảnh báo sai) ngay trên tin nhắn Telegram
- [ ] Clustering alert theo entity graph + threat hunting hai chế độ advisory/auto
- [ ] Attack Discovery: tự phát hiện chiến dịch từ các alert đang mở
- [ ] MSSP audit: đối soát chất lượng xử lý Tier 1 hai chiều

## Ghi nhận

Dự án kế thừa [Agentic SOC Platform](https://github.com/funnywolf/agentic-soc-platform) của [@funnywolf](https://github.com/funnywolf) — giấy phép MIT. Toàn bộ phần mở rộng trong repo này cũng phát hành theo MIT.
