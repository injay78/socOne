<!--
QUY TẮC TEMPLATE (không gửi sang Telegram — comment bị lọc khi render):
- parse_mode=HTML: dùng <b>/<a>/<code>, KHÔNG dùng Markdown.
- {{{var}}} = HTML dựng sẵn đã escape (title_line, missing_block). {{var}} = giá trị được escape tự động.
- KHÔNG DỊCH các thuật ngữ sau, giữ nguyên tiếng Anh:
  Verdict, Confidence, Severity, Source, Rule, Hostname, Username, Process,
  Parent process, Command line, SHA256, Threat intel, MITRE, Asset context,
  needs_more_info, true_positive, false_positive, benign_true_positive, needs_human,
  tên process, tên rule, tên host, tên user.
- Không dịch "máy chủ"/"máy trạm" — nhãn giữ nguyên Hostname; loại thiết bị lấy từ device_type.
- Emoji title theo verdict (tính sẵn trong verdict_emoji/title_line):
  🔴 true_positive High/Critical, 🟠 true_positive Medium/Low,
  🟡 needs_more_info hoặc needs_human, 🟢 false_positive/benign_true_positive.
- Field trống hiển thị "— (không có dữ liệu)", không ẩn.
- Khối field là dữ liệu tất định từ DB; LLM chỉ viết reasoning_vi.
-->
{{{title_line}}}

<b>Verdict:</b> {{verdict}} ({{confidence}})
<b>Severity:</b> {{severity_source}} → AI: {{severity_ai}}
<b>Source:</b> {{source}}
<b>Rule:</b> {{rule_name}}

<b>Hostname:</b> {{hostname}} — {{device_type}}, {{asset_owner}} (Asset context: {{asset_context_source}})
<b>Username:</b> {{username}}
<b>Process:</b> {{process_path}}
<b>Parent process:</b> {{parent_process}}
<b>Command line:</b> {{cmdline}}
<b>SHA256:</b> {{sha256}} {{threat_intel_summary}}
<b>MITRE:</b> {{mitre}}

{{reasoning_vi}}
{{{missing_block}}}
