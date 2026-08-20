import {useCallback, useEffect, useState} from 'react'
import {Alert, Button, Card, Collapse, Descriptions, Empty, Modal, Space, Spin, Tag, Typography} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'
import {choiceTag, formatDateTime} from '../utils/recordDisplay'

type RecordRow = Record<string, unknown>

interface HuntQuery {
    id: string
    target: string
    query_text: string
    purpose: string
    expected_evidence: string
    negative_interpretation: string
    status: string
    row_count: number | null
    sample_rows: unknown[]
    duration_ms: number | null
    guard_rejection_reason: string
    executed_at: string | null
    error: string
}

interface HuntFinding {
    id: string
    conclusion: string
    summary: string
    evidence: unknown[]
    created_at: string
}

interface HuntHypothesis {
    id: string
    statement: string
    mitre_technique: string
    rationale: string
    status: string
    queries: HuntQuery[]
    findings: HuntFinding[]
}

interface HuntPlanDetail {
    id: string
    status: string
    mode: string
    stop_reason: string
    error: string
    budget_snapshot: Record<string, unknown>
    hypotheses: HuntHypothesis[]
}

const CONCLUSION_COLOR: Record<string, string> = {
    confirmed: 'red',
    refuted: 'green',
    inconclusive: 'default',
}

export default function HuntPlanTreeView({record}: { record: RecordRow }) {
    const planId = String(record.id || '')
    const [plan, setPlan] = useState<HuntPlanDetail | null>(null)
    const [loading, setLoading] = useState(false)
    const [running, setRunning] = useState<string>('')

    const load = useCallback(async () => {
        if (!planId) return
        setLoading(true)
        try {
            const response = await client.get(`/hunt-plans/${planId}/`)
            setPlan(response.data as HuntPlanDetail)
        } catch {
            message.error('Could not load the hunt plan.')
        } finally {
            setLoading(false)
        }
    }, [planId])

    useEffect(() => {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        void load()
    }, [load])

    const runQuery = useCallback((query: HuntQuery) => {
        Modal.confirm({
            title: 'Run this query?',
            content: (
                <Space direction="vertical" size="small">
                    <Typography.Text>
                        It runs read-only against {query.target === 'qradar' ? 'QRadar' : 'Trellix'} and
                        is recorded in the audit log.
                    </Typography.Text>
                    <Typography.Text type="secondary">{query.purpose}</Typography.Text>
                </Space>
            ),
            okText: 'Run',
            cancelText: 'Cancel',
            onOk: async () => {
                setRunning(query.id)
                try {
                    await client.post(`/hunt-plans/${planId}/queries/${query.id}/run/`)
                    await load()
                } catch {
                    message.error('The query could not be started.')
                } finally {
                    setRunning('')
                }
            },
        })
    }, [planId, load])

    if (loading && !plan) return <Spin/>
    if (!plan) return <Empty description="No hunt plan"/>
    if (!plan.hypotheses.length) {
        return (
            <Space direction="vertical" style={{width: '100%'}}>
                {plan.error ? <Alert type="error" showIcon message="Plan generation failed" description={plan.error}/> : null}
                <Empty description="This plan produced no hypotheses"/>
            </Space>
        )
    }

    return (
        <Space direction="vertical" size="middle" style={{width: '100%'}}>
            {plan.mode === 'advisory' ? (
                <Alert
                    type="info"
                    showIcon
                    message="Advisory mode"
                    description="Nothing has been executed. Run a query only after reading what a positive and a negative result would mean."
                />
            ) : null}
            {plan.stop_reason ? (
                <Alert type="warning" showIcon message="Plan stopped early" description={plan.stop_reason}/>
            ) : null}

            {plan.hypotheses.map((hypothesis) => (
                <Card
                    key={hypothesis.id}
                    size="small"
                    title={
                        <Space wrap>
                            {hypothesis.mitre_technique ? <Tag color="purple">{hypothesis.mitre_technique}</Tag> : null}
                            <Typography.Text strong>{hypothesis.statement || 'Hypothesis'}</Typography.Text>
                            {choiceTag(hypothesis.status)}
                        </Space>
                    }
                >
                    {hypothesis.rationale ? (
                        <Typography.Paragraph type="secondary">{hypothesis.rationale}</Typography.Paragraph>
                    ) : null}

                    <Collapse
                        size="small"
                        items={hypothesis.queries.map((query) => ({
                            key: query.id,
                            label: (
                                <Space wrap>
                                    <Tag>{query.target}</Tag>
                                    {choiceTag(query.status)}
                                    <Typography.Text>{query.purpose || 'Query'}</Typography.Text>
                                    {query.row_count === null ? null : <Tag color="blue">{query.row_count} rows</Tag>}
                                </Space>
                            ),
                            children: (
                                <Space direction="vertical" size="small" style={{width: '100%'}}>
                                    <Typography.Paragraph copyable={{text: query.query_text}} style={{marginBottom: 0}}>
                                        <pre style={{whiteSpace: 'pre-wrap', margin: 0}}>{query.query_text}</pre>
                                    </Typography.Paragraph>
                                    <Descriptions size="small" column={1} bordered>
                                        <Descriptions.Item label="If it returns rows">{query.expected_evidence || '—'}</Descriptions.Item>
                                        <Descriptions.Item label="If it returns nothing">{query.negative_interpretation || '—'}</Descriptions.Item>
                                        {query.guard_rejection_reason ? (
                                            <Descriptions.Item label="Rejected by guard">{query.guard_rejection_reason}</Descriptions.Item>
                                        ) : null}
                                        {query.error ? <Descriptions.Item label="Error">{query.error}</Descriptions.Item> : null}
                                        {query.executed_at ? (
                                            <Descriptions.Item label="Executed">{formatDateTime(query.executed_at)}</Descriptions.Item>
                                        ) : null}
                                        {query.duration_ms === null ? null : (
                                            <Descriptions.Item label="Duration">{query.duration_ms} ms</Descriptions.Item>
                                        )}
                                    </Descriptions>
                                    <Button
                                        size="small"
                                        type="primary"
                                        loading={running === query.id}
                                        onClick={() => runQuery(query)}
                                    >
                                        Run this query
                                    </Button>
                                </Space>
                            ),
                        }))}
                    />

                    {hypothesis.findings.map((finding) => (
                        <Alert
                            key={finding.id}
                            style={{marginTop: 12}}
                            type={finding.conclusion === 'confirmed' ? 'error' : finding.conclusion === 'refuted' ? 'success' : 'info'}
                            showIcon
                            message={<Tag color={CONCLUSION_COLOR[finding.conclusion] || 'default'}>{finding.conclusion}</Tag>}
                            description={finding.summary}
                        />
                    ))}
                </Card>
            ))}
        </Space>
    )
}
