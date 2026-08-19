import {useCallback, useEffect, useState} from 'react'
import {Button, Card, Form, Input, InputNumber, Select, Space, Switch, Tabs, Typography} from 'antd'
import {message} from '../utils/appMessage'
import {ChartNetwork, SatelliteDish, ShieldCheck} from 'lucide-react'
import client from '../api/client'

interface AlienVaultOTXConfig {
  enabled: boolean
  api_key: string
  api_key_configured: boolean
  base_url: string
  proxy: string
  updated_at?: string
}

interface OpenCTIConfig {
  enabled: boolean
  url: string
  token: string
  token_configured: boolean
  ssl_verify: boolean
  proxy: string
  updated_at?: string
}

interface VirusTotalConfig {
  enabled: boolean
  api_keys: string[]
  api_keys_configured: number
  base_url: string
  proxy: string
  timeout_seconds: number
  requests_per_minute_per_key: number
  updated_at?: string
}

interface ProviderTestResult {
  success: boolean
  detail: string
  response_preview?: string
}

function initialOTXValues(): AlienVaultOTXConfig {
  return {
    enabled: false,
    api_key: '',
    api_key_configured: false,
    base_url: 'https://otx.alienvault.com/api/v1',
    proxy: '',
  }
}

function initialVirusTotalValues(): VirusTotalConfig {
  return {
    enabled: false,
    api_keys: [],
    api_keys_configured: 0,
    base_url: 'https://www.virustotal.com/api/v3',
    proxy: '',
    timeout_seconds: 20,
    requests_per_minute_per_key: 4,
  }
}

function initialOpenCTIValues(): OpenCTIConfig {
  return {
    enabled: false,
    url: 'http://localhost:8080',
    token: '',
    token_configured: false,
    ssl_verify: false,
    proxy: '',
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

export default function ThreatIntelligenceSettings() {
  const [otxForm] = Form.useForm<AlienVaultOTXConfig>()
  const [openctiForm] = Form.useForm<OpenCTIConfig>()
  const [virustotalForm] = Form.useForm<VirusTotalConfig>()
  const [loading, setLoading] = useState(false)
  const [savingProvider, setSavingProvider] = useState<string | null>(null)
  const [testingProvider, setTestingProvider] = useState<string | null>(null)

  const loadConfig = useCallback(async () => {
    setLoading(true)
    try {
      const [otxResponse, openctiResponse, virustotalResponse] = await Promise.all([
        client.get<AlienVaultOTXConfig>('/settings/threat-intel/otx/', {
          params: { reveal_secrets: true },
        }),
        client.get<OpenCTIConfig>('/settings/threat-intel/opencti/', {
          params: { reveal_secrets: true },
        }),
        client.get<VirusTotalConfig>('/settings/threat-intel/virustotal/', {
          params: { reveal_secrets: true },
        }),
      ])
      otxForm.setFieldsValue({ ...initialOTXValues(), ...otxResponse.data })
      openctiForm.setFieldsValue({ ...initialOpenCTIValues(), ...openctiResponse.data })
      virustotalForm.setFieldsValue({ ...initialVirusTotalValues(), ...virustotalResponse.data })
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load threat intelligence configuration'))
    } finally {
      setLoading(false)
    }
  }, [openctiForm, otxForm, virustotalForm])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadConfig()
  }, [loadConfig])

  const saveOTXConfig = async () => {
    setSavingProvider('otx')
    try {
      const values = await otxForm.validateFields()
      const { data } = await client.patch<AlienVaultOTXConfig>('/settings/threat-intel/otx/', {
        ...values,
        api_key: values.api_key || '',
        proxy: values.proxy || '',
      })
      otxForm.setFieldsValue({ ...initialOTXValues(), ...data, api_key: values.api_key || '' })
      message.success('AlienVault OTX configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save AlienVault OTX configuration'))
    } finally {
      setSavingProvider(null)
    }
  }

  const testOTXConfig = async () => {
    setTestingProvider('otx')
    try {
      const values = await otxForm.validateFields()
      const { data } = await client.post<ProviderTestResult>('/settings/threat-intel/otx/test/', {
        ...values,
        api_key: values.api_key || '',
        proxy: values.proxy || '',
      })
      if (data.success) message.success(data.detail)
      else message.error(data.detail)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test AlienVault OTX configuration'))
    } finally {
      setTestingProvider(null)
    }
  }

  const saveOpenCTIConfig = async () => {
    setSavingProvider('opencti')
    try {
      const values = await openctiForm.validateFields()
      const { data } = await client.patch<OpenCTIConfig>('/settings/threat-intel/opencti/', {
        ...values,
        token: values.token || '',
        proxy: values.proxy || '',
      })
      openctiForm.setFieldsValue({ ...initialOpenCTIValues(), ...data, token: values.token || '' })
      message.success('OpenCTI configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save OpenCTI configuration'))
    } finally {
      setSavingProvider(null)
    }
  }

  const testOpenCTIConfig = async () => {
    setTestingProvider('opencti')
    try {
      const values = await openctiForm.validateFields()
      const { data } = await client.post<ProviderTestResult>('/settings/threat-intel/opencti/test/', {
        ...values,
        token: values.token || '',
        proxy: values.proxy || '',
      })
      if (data.success) message.success(data.detail)
      else message.error(data.detail)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test OpenCTI configuration'))
    } finally {
      setTestingProvider(null)
    }
  }

  const saveVirusTotalConfig = async () => {
    setSavingProvider('virustotal')
    try {
      const values = await virustotalForm.validateFields()
      const { data } = await client.patch<VirusTotalConfig>('/settings/threat-intel/virustotal/', {
        ...values,
        api_keys: values.api_keys || [],
        proxy: values.proxy || '',
      })
      virustotalForm.setFieldsValue({ ...initialVirusTotalValues(), ...data, api_keys: values.api_keys || [] })
      message.success('VirusTotal configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save VirusTotal configuration'))
    } finally {
      setSavingProvider(null)
    }
  }

  const testVirusTotalConfig = async () => {
    setTestingProvider('virustotal')
    try {
      const values = await virustotalForm.validateFields()
      const { data } = await client.post<ProviderTestResult>('/settings/threat-intel/virustotal/test/', {
        ...values,
        api_keys: values.api_keys || [],
        proxy: values.proxy || '',
      })
      if (data.success) message.success(data.detail)
      else message.error(data.detail)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test VirusTotal configuration'))
    } finally {
      setTestingProvider(null)
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0, overflow: 'auto' }}>
      <Tabs
        items={[
          {
            key: 'otx',
            label: 'AlienVault OTX',
            icon: <SatelliteDish size={16} />,
            children: (
              <Card loading={loading}>
                <Form form={otxForm} layout="vertical" initialValues={initialOTXValues()} style={{ maxWidth: 760 }}>
                  <Form.Item name="enabled" label="Enabled" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item name="base_url" label="Base URL" rules={[{ required: true }, { type: 'url' }]}>
                    <Input placeholder="https://otx.alienvault.com/api/v1" />
                  </Form.Item>
                  <Form.Item name="api_key" label="API Key" rules={[{ required: true, message: 'API key is required' }]}>
                    <Input.Password autoComplete="new-password" />
                  </Form.Item>
                  <Form.Item name="proxy" label="Proxy">
                    <Input placeholder="http://127.0.0.1:7890" />
                  </Form.Item>
                  <Space>
                    <Button onClick={testOTXConfig} loading={testingProvider === 'otx'}>Test</Button>
                    <Button type="primary" onClick={saveOTXConfig} loading={savingProvider === 'otx'}>Save</Button>
                  </Space>
                </Form>
              </Card>
            ),
          },
          {
            key: 'virustotal',
            label: 'VirusTotal',
            icon: <ShieldCheck size={16} />,
            children: (
              <Card loading={loading}>
                <Form form={virustotalForm} layout="vertical" initialValues={initialVirusTotalValues()} style={{ maxWidth: 760 }}>
                  <Form.Item name="enabled" label="Enabled" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item name="base_url" label="Base URL" rules={[{ required: true }, { type: 'url' }]}>
                    <Input placeholder="https://www.virustotal.com/api/v3" />
                  </Form.Item>
                  <Form.Item
                    name="api_keys"
                    label="API Keys"
                    tooltip="Nhiều key sẽ được xoay vòng theo từng request; key bị 429/401 tự động bỏ qua trong phút hiện tại."
                  >
                    <Select mode="tags" open={false} suffixIcon={null} tokenSeparators={[',', ' ', '\n']} placeholder="Dán từng API key rồi nhấn Enter" />
                  </Form.Item>
                  <Typography.Paragraph type="secondary" style={{ marginTop: -8 }}>
                    Mỗi key free tier chịu được 4 request/phút — thêm nhiều key để tăng thông lượng.
                  </Typography.Paragraph>
                  <Space size="large">
                    <Form.Item name="requests_per_minute_per_key" label="Requests/phút mỗi key">
                      <InputNumber min={1} max={1000} />
                    </Form.Item>
                    <Form.Item name="timeout_seconds" label="Timeout (giây)">
                      <InputNumber min={5} max={120} />
                    </Form.Item>
                  </Space>
                  <Form.Item name="proxy" label="Proxy">
                    <Input placeholder="http://127.0.0.1:7890" />
                  </Form.Item>
                  <Space>
                    <Button onClick={testVirusTotalConfig} loading={testingProvider === 'virustotal'}>Test</Button>
                    <Button type="primary" onClick={saveVirusTotalConfig} loading={savingProvider === 'virustotal'}>Save</Button>
                  </Space>
                </Form>
              </Card>
            ),
          },
          {
            key: 'opencti',
            label: 'OpenCTI',
            icon: <ChartNetwork size={16} />,
            children: (
              <Card loading={loading}>
                <Form form={openctiForm} layout="vertical" initialValues={initialOpenCTIValues()} style={{ maxWidth: 760 }}>
                  <Form.Item name="enabled" label="Enabled" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item name="url" label="Base URL" rules={[{ required: true }, { type: 'url' }]}>
                    <Input placeholder="http://localhost:8080" />
                  </Form.Item>
                  <Form.Item name="token" label="API Token" rules={[{ required: true, message: 'API token is required' }]}>
                    <Input.Password autoComplete="new-password" />
                  </Form.Item>
                  <Form.Item name="ssl_verify" label="SSL Verify" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item name="proxy" label="Proxy">
                    <Input placeholder="http://127.0.0.1:7890" />
                  </Form.Item>
                  <Space>
                    <Button onClick={testOpenCTIConfig} loading={testingProvider === 'opencti'}>Test</Button>
                    <Button type="primary" onClick={saveOpenCTIConfig} loading={savingProvider === 'opencti'}>Save</Button>
                  </Space>
                </Form>
              </Card>
            ),
          },
        ]}
      />
    </div>
  )
}
