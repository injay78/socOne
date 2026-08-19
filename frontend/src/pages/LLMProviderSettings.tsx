import {useMemo, useState} from 'react'
import {Button, Divider, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch} from 'antd'
import {message} from '../utils/appMessage'
import {CheckCircleOutlined, EditOutlined, PlusOutlined, StopOutlined, ThunderboltOutlined} from '@ant-design/icons'
import client from '../api/client'
import DataTable from '../components/DataTable'
import {getResourceConfig} from '../config/resources'

type LLMProviderConfig = Record<string, unknown> & {
  id: string
  name: string
  base_url: string
  model: string
  fallback_models: string[]
  api_key: string
  api_key_configured: boolean
  proxy: string
  tags: string[]
  enabled: boolean
  priority: number
  supports_json_mode: boolean
  supports_tool_calling: boolean
  context_window_tokens: number
  max_output_tokens: number
  request_timeout_seconds: number
  max_retries: number
  created_at: string
  updated_at: string
}

interface LLMProviderFormValues {
  name: string
  base_url: string
  model: string
  fallback_models?: string[]
  api_key?: string
  proxy?: string
  tags?: string[]
  enabled: boolean
  priority: number
  supports_json_mode: boolean
  supports_tool_calling: boolean
  context_window_tokens: number
  max_output_tokens: number
  request_timeout_seconds: number
  max_retries: number
}

interface LLMTestResult {
  success: boolean
  detail: string
  response_preview?: string
}

const LLM_TAG_OPTIONS = ['fast', 'powerful', 'tool_calling', 'structured_output'].map((tag) => ({
  label: tag,
  value: tag,
}))
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

function initialValues(): LLMProviderFormValues {
  return {
    name: '',
    base_url: '',
    model: '',
    fallback_models: [],
    api_key: '',
    proxy: '',
    tags: [],
    enabled: true,
    priority: 100,
    supports_json_mode: false,
    supports_tool_calling: false,
    context_window_tokens: 32768,
    max_output_tokens: 4096,
    request_timeout_seconds: 120,
    max_retries: 2,
  }
}

export default function LLMProviderSettings() {
  const config = useMemo(() => getResourceConfig('llm-providers'), [])
  const [form] = Form.useForm<LLMProviderFormValues>()
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<LLMProviderConfig | null>(null)
  const [saving, setSaving] = useState(false)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [testingForm, setTestingForm] = useState(false)
  const [refreshKey, setRefreshKey] = useState(0)
  const refresh = () => setRefreshKey((value) => value + 1)

  const openCreate = () => {
    setEditing(null)
    form.setFieldsValue(initialValues())
    setModalOpen(true)
  }

  const openEdit = async (record: LLMProviderConfig) => {
    setEditing(record)
    form.setFieldsValue({ ...initialValues(), ...record })
    setModalOpen(true)
    try {
      const { data } = await client.get<LLMProviderConfig>(`/settings/llm-providers/${record.id}/`, {
        params: { reveal_secrets: true },
      })
      setEditing(data)
      form.setFieldsValue({ ...initialValues(), ...data })
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load LLM provider'))
      setModalOpen(false)
    }
  }

  const closeModal = () => {
    setModalOpen(false)
    setEditing(null)
    form.resetFields()
  }

  const saveProvider = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      const payload = {
        ...values,
        tags: values.tags || [],
        fallback_models: values.fallback_models || [],
        proxy: values.proxy || '',
        api_key: values.api_key || '',
      }
      if (editing) {
        await client.patch(`/settings/llm-providers/${editing.id}/`, payload)
        message.success('LLM provider updated')
      } else {
        await client.post('/settings/llm-providers/', payload)
        message.success('LLM provider created')
      }
      closeModal()
      refresh()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save LLM provider'))
    } finally {
      setSaving(false)
    }
  }

  const showTestResult = (result: LLMTestResult) => {
    if (result.success) {
      message.success(result.detail)
    } else {
      message.error(result.detail)
    }
  }

  const updateProviderStatus = async (record: LLMProviderConfig, enabled: boolean) => {
    try {
      await client.patch(`/settings/llm-providers/${record.id}/`, { enabled })
      message.success(enabled ? 'LLM provider enabled' : 'LLM provider disabled')
      refresh()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to update LLM provider status'))
    }
  }

  const testSavedProvider = async (record: LLMProviderConfig) => {
    setTestingId(record.id)
    try {
      const { data } = await client.post<LLMTestResult>(`/settings/llm-providers/${record.id}/test/`)
      showTestResult(data)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test LLM provider'))
    } finally {
      setTestingId(null)
    }
  }

  const testFormProvider = async () => {
    setTestingForm(true)
    try {
      const values = await form.validateFields()
      const endpoint = editing
        ? `/settings/llm-providers/${editing.id}/test/`
        : '/settings/llm-providers/test/'
      const { data } = await client.post<LLMTestResult>(endpoint, {
        ...values,
        tags: values.tags || [],
        fallback_models: values.fallback_models || [],
        proxy: values.proxy || '',
        api_key: values.api_key || '',
      })
      showTestResult(data)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test LLM provider'))
    } finally {
      setTestingForm(false)
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0 }}>
      <DataTable
        key={refreshKey}
        endpoint={config.endpoint}
        tableKey={config.key}
        rowKey={config.rowKey}
        columns={config.columns}
        filters={config.filters}
        advancedFilters={config.advancedFilters}
        searchPlaceholder={config.searchPlaceholder}
        actions={<Button icon={<PlusOutlined />} onClick={openCreate} />}
        actionColumnWidth={136}
        rowActions={(record, defaults) => (
          <Space size={4} align="center" className="table-row-actions">
            <Button
              size="small"
              type="text"
              icon={<ThunderboltOutlined />}
              loading={testingId === record.id}
              onClick={(event) => {
                event.stopPropagation()
                testSavedProvider(record as LLMProviderConfig)
              }}
            />
            <Popconfirm
              title={record.enabled ? 'Disable LLM provider?' : 'Enable LLM provider?'}
              onConfirm={(event) => {
                event?.stopPropagation()
                return updateProviderStatus(record as LLMProviderConfig, !record.enabled)
              }}
              onCancel={(event) => event?.stopPropagation()}
            >
              <Button
                size="small"
                type="text"
                icon={record.enabled ? <StopOutlined /> : <CheckCircleOutlined />}
                onClick={(event) => event.stopPropagation()}
              />
            </Popconfirm>
            <Button
              size="small"
              type="text"
              icon={<EditOutlined />}
              onClick={(event) => {
                event.stopPropagation()
                openEdit(record as LLMProviderConfig)
              }}
            />
            {defaults.deleteAction}
          </Space>
        )}
        onRowClick={(record) => openEdit(record as LLMProviderConfig)}
        dense
        fillParent
      />
      <Modal
        title={editing ? `LLM Provider: ${editing.name}` : 'Add LLM Provider'}
        open={modalOpen}
        onCancel={closeModal}
        width={760}
        destroyOnHidden
        footer={(
          <Space>
            <Button onClick={testFormProvider} loading={testingForm}>Test</Button>
            <Button onClick={closeModal}>Cancel</Button>
            <Button type="primary" loading={saving} onClick={saveProvider}>Save</Button>
          </Space>
        )}
      >
        <Form form={form} layout="vertical" initialValues={initialValues()} style={{ paddingTop: 8 }}>
          <Form.Item name="name" label="Name" rules={[{ required: true }]}>
            <Input placeholder="Primary OpenAI-compatible provider" />
          </Form.Item>
          <Form.Item name="base_url" label="Base URL" rules={[{ required: true }, { type: 'url' }]}>
            <Input placeholder="https://example-compatible-openai-endpoint/v1" />
          </Form.Item>
          <Form.Item name="model" label="Model" rules={[{ required: true }]}>
            <Input placeholder="gpt-4.1" />
          </Form.Item>
          <Form.Item
            name="fallback_models"
            label="Fallback Models"
            tooltip="Các model dự phòng trên cùng endpoint, thử lần lượt khi model chính lỗi/hết quota."
          >
            <Select mode="tags" open={false} suffixIcon={null} tokenSeparators={[',']} placeholder="claude-sonnet-4-5, gemini-2.5-pro, ..." />
          </Form.Item>
          <Form.Item name="api_key" label="API Key">
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="proxy" label="Proxy">
            <Input placeholder="http://127.0.0.1:7890" />
          </Form.Item>
          <Form.Item name="tags" label="Tags" rules={[
            { required: true, message: 'Select at least one tag' },
            { type: 'array', min: 1, message: 'Select at least one tag' },
          ]}>
            <Select mode="tags" options={LLM_TAG_OPTIONS} placeholder="structured_output, powerful" tokenSeparators={[',']} />
          </Form.Item>
          <Space size="large" align="start">
            <Form.Item name="enabled" label="Enabled" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="priority" label="Priority" rules={[{ required: true }]}>
              <InputNumber min={0} max={100000} />
            </Form.Item>
          </Space>
          <Divider titlePlacement="start" plain>Model capabilities</Divider>
          <Space size="large" align="start" wrap>
            <Form.Item
              name="supports_json_mode"
              label="JSON mode"
              valuePropName="checked"
              tooltip="Enable only if the endpoint accepts response_format={'type':'json_object'}. Leave off for self-hosted models that ignore it."
            >
              <Switch />
            </Form.Item>
            <Form.Item
              name="supports_tool_calling"
              label="Tool calling"
              valuePropName="checked"
              tooltip="Informational. No platform skill requires tool calling."
            >
              <Switch />
            </Form.Item>
          </Space>
          <Space size="large" align="start" wrap>
            <Form.Item name="context_window_tokens" label="Context window" rules={[{ required: true }]}>
              <InputNumber min={1024} max={2000000} step={1024} />
            </Form.Item>
            <Form.Item name="max_output_tokens" label="Max output tokens" rules={[{ required: true }]}>
              <InputNumber min={256} max={200000} step={256} />
            </Form.Item>
          </Space>
          <Space size="large" align="start" wrap>
            <Form.Item name="request_timeout_seconds" label="Request timeout (s)" rules={[{ required: true }]}>
              <InputNumber min={5} max={3600} />
            </Form.Item>
            <Form.Item name="max_retries" label="Max retries" rules={[{ required: true }]}>
              <InputNumber min={0} max={5} />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </div>
  )
}
