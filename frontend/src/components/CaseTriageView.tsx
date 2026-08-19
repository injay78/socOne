import {useCallback, useEffect, useMemo, useState} from 'react'
import {Alert, Button, Card, Collapse, Descriptions, Empty, Modal, Select, Space, Spin, Table, Tag, Typography} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'
import {choiceTag, formatDateTime, severityTag} from '../utils/recordDisplay'

type RecordRow = Record<string, unknown>

interface TriageEvidence {
  kind?: string
  source?: string
  summary?: string
  reference?: string
}

interface TriageAction {
  category?: string
  description?: string
}

interface FactRow {
  label: string
  value: string
}

interface FactSection {
  key: string
  title: string
  rows: FactRow[]
}

interface MissingContext {
  field: string
  label: string
  tried: string
  reason: string
  question: string
}

interface AssetContext {
  cmdb_matched: boolean
  asset_context_source: string
  asset_context_source_label: string
  device_type: string
  environment: string
  criticality: string
  owner: string
}

interface QualityFlag {
  flag: string
  terms?: string[]
  count?: number
}

interface TriageResult {
  id: string
  verdict: string
  effective_verdict: string
  false_positive_class: string
  severity_ai: string
  impact_ai: string
  priority_ai: string
  confidence: number
  needs_human: boolean
  mitre_tactics: string[]
  mitre_techniques: string[]
  kill_chain_phase: string
  evidence: TriageEvidence[]
  recommended_actions: TriageAction[]
  reasoning_vi: string
  reasoning_en: string
  prompt_family: string
  facts: { sections: FactSection[]; missing_count: number } | null
  entities: { entities: Record<string, string[]>; source_identifiers: { type: string; value: string }[] } | null
  asset_context: AssetContext | null
  missing_context: MissingContext[]
  quality_flags: QualityFlag[]
  error: string
  human_verdict: string
  human_verdict_by_name: string
  human_verdict_at: string | null
  human_verdict_note: string
  ai_was_overridden: boolean
  model_name: string
  tokens_in: number | null
  tokens_out: number | null
  latency_ms: number | null
  created_at: string
}

const VERDICT_OPTIONS = [
  {label: 'True Positive', value: 'true_positive'},
  {label: 'Benign True Positive', value: 'benign_true_positive'},
  {label: 'False Positive', value: 'false_positive'},
  {label: 'Needs More Info', value: 'needs_more_info'},
]

function apiErrorMessage(error: unknown, fallback: string) {
  const response = error as { response?: { data?: unknown } }
  const data = response.response?.data
  if (!data) return fallback
  if (typeof data === 'string') return data
  if (typeof data === 'object') {
    const detail = (data as { detail?: unknown }).detail
    if (typeof detail === 'string') return detail
    return JSON.stringify(data)
  }
  return fallback
}

export default function CaseTriageView({record}: { record: RecordRow }) {
  const caseId = useMemo(() => String(record?.id ?? ''), [record])
  const caseReadableId = useMemo(() => String(record?.case_id ?? ''), [record])
  const [result, setResult] = useState<TriageResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [running, setRunning] = useState(false)
  const [overrideOpen, setOverrideOpen] = useState(false)
  const [overrideVerdict, setOverrideVerdict] = useState<string>('true_positive')

  const loadResult = useCallback(async () => {
    if (!caseId) return
    setLoading(true)
    try {
      const {data} = await client.get('/triage-results/', {params: {case: caseId, ordering: '-created_at'}})
      const rows = (data?.results ?? []) as TriageResult[]
      setResult(rows.length ? rows[0] : null)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load triage result'))
    } finally {
      setLoading(false)
    }
  }, [caseId])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadResult()
  }, [loadResult])

  const runTriage = async () => {
    if (!caseReadableId) return
    setRunning(true)
    try {
      await client.post(`/agent/v1/cases/${caseReadableId}/triage/`, {})
      message.success('Triage completed')
      await loadResult()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to run triage'))
    } finally {
      setRunning(false)
    }
  }

  const submitOverride = async () => {
    if (!result) return
    try {
      await client.post(`/triage-results/${result.id}/override/`, {verdict: overrideVerdict})
      message.success('Verdict overridden')
      setOverrideOpen(false)
      await loadResult()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to override verdict'))
    }
  }

  if (loading) return <Spin />

  if (!result) {
    return (
      <Empty description="No triage result yet">
        <Button type="primary" loading={running} onClick={runTriage}>Run triage</Button>
      </Empty>
    )
  }

  return (
    <Space direction="vertical" size="middle" style={{width: '100%'}}>
      {result.needs_human ? (
        <Alert
          type="warning"
          showIcon
          message="This verdict needs human review"
          description={`AI confidence ${result.confidence.toFixed(2)} is below the review threshold.`}
        />
      ) : null}

      {result.ai_was_overridden ? (
        <Alert
          type="info"
          showIcon
          message="An analyst overrode the AI verdict"
          description={`${result.human_verdict_by_name || 'Analyst'} set ${result.human_verdict} on ${formatDateTime(result.human_verdict_at || '')}. ${result.human_verdict_note}`}
        />
      ) : null}

      {(result.quality_flags || []).some((flag) => flag.flag === 'unverified_asset_claim') ? (
        <Alert
          type="error"
          showIcon
          message="Nhận định về tài sản chưa được xác minh"
          description={
            <>
              Model dùng từ ngữ mô tả vai trò máy ({(result.quality_flags || [])
                .filter((flag) => flag.flag === 'unverified_asset_claim')
                .flatMap((flag) => flag.terms || [])
                .join(', ')}) trong khi không có bản ghi CMDB nào khớp. Đừng tin phần mô tả tài sản trong nhận định bên dưới.
            </>
          }
        />
      ) : null}

      {result.error ? <Alert type="error" showIcon message={result.error} /> : null}

      {result.facts?.sections?.length ? (
        <Card
          size="small"
          title="Dữ kiện xác minh"
          extra={
            <Space size="small">
              <Tag color={result.asset_context?.cmdb_matched ? 'green' : 'orange'}>
                {result.asset_context?.asset_context_source_label || 'Unknown'}
              </Tag>
              {result.facts.missing_count ? <Tag>{result.facts.missing_count} field thiếu dữ liệu</Tag> : null}
            </Space>
          }
        >
          <Typography.Paragraph type="secondary" style={{marginBottom: 12}}>
            Khối này được render trực tiếp từ bản ghi trong database, không do model sinh ra.
          </Typography.Paragraph>
          {result.facts.sections
            .filter((section) => section.key !== 'identifiers')
            .map((section) => (
              <div key={section.key} style={{marginBottom: 12}}>
                <Typography.Text strong>{section.title}</Typography.Text>
                <Table
                  size="small"
                  showHeader={false}
                  pagination={false}
                  rowKey={(row: FactRow) => `${section.key}-${row.label}`}
                  dataSource={section.rows}
                  columns={[
                    {dataIndex: 'label', width: 200, render: (v: string) => <Typography.Text type="secondary">{v}</Typography.Text>},
                    {
                      dataIndex: 'value',
                      render: (v: string) => (
                        <span style={{opacity: v.startsWith('—') ? 0.5 : 1}}>{v}</span>
                      ),
                    },
                  ]}
                />
              </div>
            ))}
          <Collapse
            ghost
            size="small"
            items={[
              {
                key: 'identifiers',
                label: 'Định danh nguồn',
                children: (
                  <Space direction="vertical" size={2}>
                    {(result.entities?.source_identifiers || []).length
                      ? result.entities?.source_identifiers.map((item) => (
                          <Typography.Text key={`${item.type}-${item.value}`} code>
                            {item.type}: {item.value}
                          </Typography.Text>
                        ))
                      : <Typography.Text type="secondary">— (không có dữ liệu)</Typography.Text>}
                  </Space>
                ),
              },
            ]}
          />
        </Card>
      ) : null}

      {(result.missing_context || []).length ? (
        <Card size="small" title="Ngữ cảnh còn thiếu sau khi đã thử bổ sung">
          <Space direction="vertical" size="small" style={{width: '100%'}}>
            {result.missing_context.map((item) => (
              <div key={item.field}>
                <Space size="small">
                  <Tag color="orange">{item.label}</Tag>
                  <Typography.Text type="secondary">đã thử: {item.tried}</Typography.Text>
                </Space>
                <div><Typography.Text type="secondary">{item.reason}</Typography.Text></div>
                <div>{item.question}</div>
              </div>
            ))}
          </Space>
        </Card>
      ) : null}

      <Card
        size="small"
        title="Verdict"
        extra={
          <Space>
            <Button size="small" loading={running} onClick={runTriage}>Re-run</Button>
            <Button size="small" type="primary" onClick={() => setOverrideOpen(true)}>Override</Button>
          </Space>
        }
      >
        <Descriptions size="small" column={2}>
          <Descriptions.Item label="AI verdict">{choiceTag(result.verdict)}</Descriptions.Item>
          <Descriptions.Item label="Confidence">{result.confidence.toFixed(2)}</Descriptions.Item>
          <Descriptions.Item label="Severity">{severityTag(result.severity_ai)}</Descriptions.Item>
          <Descriptions.Item label="Impact">{result.impact_ai || '—'}</Descriptions.Item>
          <Descriptions.Item label="Priority">{result.priority_ai || '—'}</Descriptions.Item>
          <Descriptions.Item label="Kill chain">{result.kill_chain_phase || '—'}</Descriptions.Item>
          {result.false_positive_class ? (
            <Descriptions.Item label="FP class">{result.false_positive_class}</Descriptions.Item>
          ) : null}
          <Descriptions.Item label="MITRE">
            {(result.mitre_techniques || []).length
              ? result.mitre_techniques.map((item) => <Tag key={item} color="purple">{item}</Tag>)
              : '—'}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Card size="small" title="Reasoning">
        <Typography.Paragraph style={{whiteSpace: 'pre-wrap', marginBottom: 8}}>
          {result.reasoning_vi || result.reasoning_en || '—'}
        </Typography.Paragraph>
        {result.reasoning_vi && result.reasoning_en ? (
          <Typography.Paragraph type="secondary" style={{whiteSpace: 'pre-wrap', marginBottom: 0}}>
            {result.reasoning_en}
          </Typography.Paragraph>
        ) : null}
      </Card>

      <Card size="small" title={`Evidence (${(result.evidence || []).length})`}>
        {(result.evidence || []).length ? (
          <Space direction="vertical" size="small" style={{width: '100%'}}>
            {result.evidence.map((item, index) => (
              <div key={index}>
                <Space size="small">
                  <Tag>{item.kind || 'evidence'}</Tag>
                  {item.reference ? <Tag color="blue">{item.reference}</Tag> : null}
                  <Typography.Text type="secondary">{item.source}</Typography.Text>
                </Space>
                <div>{item.summary}</div>
              </div>
            ))}
          </Space>
        ) : '—'}
      </Card>

      <Card size="small" title="Recommended actions">
        {(result.recommended_actions || []).length ? (
          <Space direction="vertical" size="small" style={{width: '100%'}}>
            {result.recommended_actions.map((item, index) => (
              <div key={index}>
                <Tag color={item.category === 'contain' ? 'red' : item.category === 'close' ? 'green' : 'blue'}>
                  {item.category}
                </Tag>
                {item.description}
              </div>
            ))}
          </Space>
        ) : '—'}
      </Card>

      <Card size="small" title="Provenance">
        <Descriptions size="small" column={3}>
          <Descriptions.Item label="Prompt family">{result.prompt_family || '—'}</Descriptions.Item>
          <Descriptions.Item label="Model">{result.model_name || '—'}</Descriptions.Item>
          <Descriptions.Item label="Latency">{result.latency_ms ? `${result.latency_ms} ms` : '—'}</Descriptions.Item>
          <Descriptions.Item label="Tokens in">{result.tokens_in ?? '—'}</Descriptions.Item>
          <Descriptions.Item label="Tokens out">{result.tokens_out ?? '—'}</Descriptions.Item>
          <Descriptions.Item label="Triaged at">{formatDateTime(result.created_at)}</Descriptions.Item>
        </Descriptions>
      </Card>

      <Modal
        open={overrideOpen}
        title="Override AI verdict"
        onCancel={() => setOverrideOpen(false)}
        onOk={submitOverride}
        okText="Save"
      >
        <Typography.Paragraph type="secondary">
          Both verdicts are kept. The difference feeds the AI accuracy metric.
        </Typography.Paragraph>
        <Select
          style={{width: '100%'}}
          value={overrideVerdict}
          onChange={setOverrideVerdict}
          options={VERDICT_OPTIONS}
        />
      </Modal>
    </Space>
  )
}
