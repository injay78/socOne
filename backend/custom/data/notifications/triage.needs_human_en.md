<!--
TEMPLATE RULES (never sent to Telegram — comments are stripped at render time):
- parse_mode=HTML: use <b>/<a>/<code>, NOT Markdown.
- {{{var}}} = pre-escaped HTML (title_line, missing_block). {{var}} = auto-escaped value.
- DO NOT TRANSLATE these terms, keep them in English:
  Verdict, Confidence, Severity, Source, Rule, Hostname, Username, Process,
  Parent process, Command line, SHA256, Threat intel, MITRE, Asset context,
  needs_more_info, true_positive, false_positive, benign_true_positive, needs_human,
  process names, rule names, host names, user names.
- Title emoji by verdict (computed in verdict_emoji/title_line):
  🔴 true_positive High/Critical, 🟠 true_positive Medium/Low,
  🟡 needs_more_info or needs_human, 🟢 false_positive/benign_true_positive.
- Empty fields render as "— (không có dữ liệu)", never hidden.
- The field block is deterministic DB data; the LLM only writes reasoning_vi.
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
