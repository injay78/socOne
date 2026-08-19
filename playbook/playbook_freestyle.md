# Playbook — Phân tích Freestyle (alert không map được category)

Alert này KHÔNG thuộc category có playbook chuyên biệt (vd `Khác` hoặc category lạ). Hãy phân tích
tổng quát, khách quan, **CHỈ dựa trên dữ liệu được cung cấp** (`alert_details`, `raw_excerpt`, và mục
`IOC reputation facts` nếu có). KHÔNG giả định loại tấn công khi thiếu bằng chứng.

## Nguyên tắc
- **Mặc định Need Enrichment.** Vì không có playbook chuyên biệt và thường thiếu context, kết luận
  mặc định là `Need Enrichment`. Chỉ nêu dấu hiệu malicious/benign khi có bằng chứng TRỰC TIẾP (vd
  `IOC reputation facts` cho thấy VT/AbuseIPDB malicious rõ ràng) — và vẫn ưu tiên Need Enrichment trừ
  khi bằng chứng đủ mạnh.
- Tuân thủ evidence contract ở phần Shared Rule phía trên: KHÔNG bịa VT ratio/score/nguồn; thiếu
  evidence → `unknown` + `Enrichment_Requests`.
- `Enrichment_Requests` PHẢI cụ thể: cần phân loại đúng category nào, field/log/IOC nào để chọn được
  playbook phù hợp và nâng confidence cho chính alert này.

## Các bước (Audit_Report)
- **Step_1 — Tóm tắt & rule intent:** alert là gì (rule_name, các field chính), có thể thuộc nhóm hành
  vi nào; ghi `rule_intent_match` nếu suy được. Nếu chỉ có rule name → chỉ là context định hướng.
- **Step_2 — IOC reputation:** đối chiếu domain/IP quan sát được với `IOC reputation facts` (VT/AbuseIPDB/
  IP2Location). Chỉ claim khi có provenance trong facts; thiếu → `unknown`.
- **Step_3 — Đánh giá rủi ro tổng quát:** dấu hiệu đáng ngờ/benign rút ra từ dữ liệu có sẵn; nêu RÕ các
  khoảng trống dữ liệu khiến chưa kết luận được.
- **Step_4 — Kết luận:** mặc định `Need Enrichment`; giải thích vì sao chưa đủ cơ sở phân loại/đánh giá.

BẮT BUỘC trả về JSON thuần:

```json
{
  "Audit_Report": {
    "Step_1": {"Step_Title": "Tóm tắt & rule intent", "Detailed_Analysis": "- Evidence: rule_name, field chính, ngữ cảnh.\n- Missing/Conflict: dữ liệu còn thiếu.\n- Step conclusion: alert có thể thuộc nhóm hành vi nào (nếu suy được).", "Result": "unknown"},
    "Step_2": {"Step_Title": "IOC reputation", "Detailed_Analysis": "- Evidence: từng domain/IP + fact VT/AbuseIPDB/IP2Location nếu có (trích đúng số liệu).\n- Missing: IOC không có trong facts → unknown.\n- Step conclusion: mức độ độc hại của IOC (nếu provenance đủ).", "Result": "malicious|suspicious|clean|unknown|no_data"},
    "Step_3": {"Step_Title": "Đánh giá rủi ro tổng quát", "Detailed_Analysis": "- Evidence: dấu hiệu đáng ngờ/benign từ dữ liệu có sẵn.\n- Missing: khoảng trống dữ liệu.\n- Step conclusion: mức rủi ro sơ bộ.", "Result": "suspicious|clean|unknown|informational|no_data"},
    "Step_4": {"Step_Title": "Tổng hợp & kết luận", "Detailed_Analysis": "- Evidence tổng hợp.\n- Missing: vì sao chưa đủ cơ sở.\n- Step conclusion: mặc định Need Enrichment.", "Result": "Need Enrichment"},
    "Summary": "Lý do chọn Status (mặc định Need Enrichment vì không có playbook chuyên biệt + thiếu cơ sở)."
  },
  "Status": "Need Enrichment",
  "Confidence": "<0-100>",
  "Confidence_Reason": "Vì sao confidence ở mức này; dữ liệu/IOC nào còn thiếu.",
  "Response_Actions": [],
  "Enrichment_Requests": ["Cụ thể: phân loại đúng category / field / log / enrichment cần bổ sung để chọn playbook và nâng confidence."],
  "Close_Note": "JSON string multi-line theo Note Output Format - Close_Note.",
  "Escalate_Note": "JSON string multi-line theo Note Output Format - Escalate_Note."
}
```
