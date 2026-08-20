import {useCallback, useEffect, useState} from 'react'
import {Alert, Button, Card, Col, Divider, Form, Input, InputNumber, Row, Select, Space, Switch} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'

interface TrellixConfig {
  enabled: boolean
  iam_token_url: string
  api_base_url: string
  client_id: string
  client_secret: string
  client_secret_configured?: boolean
  platform_gateway_url: string
  platform_api_key: string
  platform_api_key_configured?: boolean
  tenant_id: string
  read_scopes: string[]
  action_scopes: string[]
  timeout_seconds: number
  rate_limit_per_minute: number
  max_rows: number
  max_window_hours: number
  threat_severities: string[]
  threat_score_min: number
  ingest_lookback_days: number
  allow_containment: boolean
  poll_enabled: boolean
  poll_interval_seconds: number
}

interface EDRTestResult {
  success: boolean
  detail: string
  response_preview?: string
}

// Trellix grades a threat s0 to s5. Leaving the selection empty keeps the
// platform default of s3, s4 and s5, so low-grade noise is not ingested.
const SEVERITY_OPTIONS = [
  {value: 's0', label: 's0 — Informational'},
  {value: 's1', label: 's1 — Very low'},
  {value: 's2', label: 's2 — Low'},
  {value: 's3', label: 's3 — Medium'},
  {value: 's4', label: 's4 — High'},
  {value: 's5', label: 's5 — Critical'},
]

function trellixInitialValues(): TrellixConfig {
  return {
    enabled: false,
    iam_token_url: '',
    api_base_url: '',
    client_id: '',
    client_secret: '',
    platform_gateway_url: '',
    platform_api_key: '',
    tenant_id: '',
    read_scopes: [],
    action_scopes: [],
    timeout_seconds: 60,
    rate_limit_per_minute: 120,
    max_rows: 1000,
    max_window_hours: 24,
    threat_severities: [],
    threat_score_min: 30,
    ingest_lookback_days: 7,
    allow_containment: false,
    poll_enabled: false,
    poll_interval_seconds: 60,
  }
}

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

function showTestResult(result: EDRTestResult) {
  const preview = result.response_preview ? ` ${result.response_preview}` : ''
  if (result.success) {
    message.success(`${result.detail}${preview}`)
    return
  }
  message.error(`${result.detail}${preview}`)
}

export default function EDRSettings() {
  const [form] = Form.useForm<TrellixConfig>()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const allowContainment = Form.useWatch('allow_containment', form)

  const loadConfig = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await client.get<TrellixConfig>('/settings/edr/trellix/')
      form.setFieldsValue({ ...trellixInitialValues(), ...data })
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load Trellix configuration'))
    } finally {
      setLoading(false)
    }
  }, [form])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadConfig()
  }, [loadConfig])

  const saveConfig = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      const { data } = await client.patch<TrellixConfig>('/settings/edr/trellix/', values)
      form.setFieldsValue({ ...trellixInitialValues(), ...data, client_secret: values.client_secret || '' })
      message.success('Trellix configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save Trellix configuration'))
    } finally {
      setSaving(false)
    }
  }

  const testConfig = async () => {
    setTesting(true)
    try {
      const values = await form.validateFields()
      const { data } = await client.post<EDRTestResult>('/settings/edr/trellix/test/', values)
      showTestResult(data)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test Trellix configuration'))
    } finally {
      setTesting(false)
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0, overflow: 'auto' }}>
      <Card title="Trellix EDR" loading={loading}>
        <Form form={form} layout="vertical" initialValues={trellixInitialValues()}>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="enabled" label="Enabled" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="tenant_id" label="Tenant ID">
                <Input />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="iam_token_url" label="IAM Token URL">
                <Input placeholder="https://iam.trellix.com/iam/v1.1/token" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="api_base_url" label="API Base URL">
                <Input placeholder="https://api.trellix.com" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="client_id" label="Client ID">
                <Input />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="client_secret" label="Client Secret">
                <Input.Password autoComplete="new-password" />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>Platform API</Divider>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="platform_gateway_url"
                label="Platform gateway URL"
                tooltip="Gateway for the /edr/v2 API from the Trellix onboarding email, for example https://api.manage.trellix.com. Different from the base URL above, which serves the legacy /ft/api endpoints."
              >
                <Input placeholder="https://api.manage.trellix.com" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="platform_api_key"
                label="Platform API key (x-api-key)"
                tooltip="Required by the alerts, real-time search and historical search endpoints. Without it the gateway answers 403 even with a valid OAuth token."
              >
                <Input.Password autoComplete="new-password" placeholder="from the onboarding email or API Access Management" />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>Scopes</Divider>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="read_scopes" label="Read scopes">
                <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="edr.det.r edr.inv.r" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="action_scopes"
                label="Action scopes"
                tooltip="Requested only while containment is enabled. The platform does not ask for these privileges otherwise."
              >
                <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="edr.act.x" />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>Query limits</Divider>
          <Row gutter={16}>
            <Col span={6}>
              <Form.Item name="max_rows" label="Max rows">
                <InputNumber min={1} max={100000} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="max_window_hours" label="Max window (hours)">
                <InputNumber min={1} max={720} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="timeout_seconds" label="Timeout (s)">
                <InputNumber min={5} max={600} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="rate_limit_per_minute" label="Rate limit (per min)">
                <InputNumber min={1} max={10000} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>Ingestion</Divider>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="poll_enabled" label="Poll detections" valuePropName="checked" tooltip="Enables run_trellix_detection_worker.">
                <Switch />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="poll_interval_seconds" label="Poll interval (s)">
                <InputNumber min={5} max={3600} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="threat_severities"
                label="Severities to ingest"
                tooltip="Threats outside the selected grades are not pulled at all. Leave empty to keep the default of s3, s4 and s5."
              >
                <Select mode="multiple" allowClear options={SEVERITY_OPTIONS} placeholder="s3, s4, s5" />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="threat_score_min"
                label="Minimum score"
                tooltip="Threat score floor applied on top of the severity filter."
              >
                <InputNumber min={0} max={100} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="ingest_lookback_days"
                label="Lookback (days)"
                tooltip="How far back the first poll reaches before the watermark takes over."
              >
                <InputNumber min={1} max={90} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>Containment</Divider>
          {allowContainment ? (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              message="Containment actions are enabled"
              description="Host isolation, process kill and file quarantine become executable. They still require a Critical-risk playbook and human approval, and every attempt is written to the audit log."
            />
          ) : null}
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="allow_containment"
                label="Allow containment actions"
                valuePropName="checked"
                tooltip="Off by default. While off, containment calls return a dry-run plan and no action scope is requested."
              >
                <Switch />
              </Form.Item>
            </Col>
          </Row>

          <Space>
            <Button onClick={testConfig} loading={testing}>Test</Button>
            <Button type="primary" onClick={saveConfig} loading={saving}>Save</Button>
          </Space>
        </Form>
      </Card>
    </div>
  )
}
