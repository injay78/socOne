import {useCallback, useEffect, useState} from 'react'
import {
  Alert,
  Button,
  Card,
  Col,
  Divider,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Row,
  Select,
  Space,
  Switch,
  Table,
} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'

interface TelegramConfig {
  enabled: boolean
  bot_token: string
  bot_token_configured?: boolean
  asp_base_url: string
  retry_limit: number
  rate_limit_per_minute: number
  aggregation_window_seconds: number
  aggregation_threshold: number
  quiet_hours_start: number | null
  quiet_hours_end: number | null
}

interface Destination {
  id: string
  name: string
  chat_id: string
  message_thread_id: string
  language: string
  enabled: boolean
  event_types: string[]
  min_severity: string
  min_confidence: number
  verdict_filter: string[]
  source_filter: string[]
  min_asset_criticality: string
}

const EVENT_OPTIONS = [
  {label: 'Triage completed', value: 'triage.completed'},
  {label: 'Triage needs human', value: 'triage.needs_human'},
  {label: 'Attack discovery created', value: 'discovery.created'},
  {label: 'Hunt finding confirmed', value: 'hunt.finding_confirmed'},
  {label: 'Critical audit finding', value: 'audit.critical_finding'},
  {label: 'Worker unhealthy', value: 'system.worker_unhealthy'},
  {label: 'MSSP sync failed', value: 'mssp.sync_failed'},
  {label: 'Integration auth failed', value: 'integration.auth_failed'},
]

const SEVERITY_OPTIONS = ['Informational', 'Low', 'Medium', 'High', 'Critical'].map((item) => ({
  label: item,
  value: item,
}))

function configInitialValues(): TelegramConfig {
  return {
    enabled: false,
    bot_token: '',
    asp_base_url: '',
    retry_limit: 3,
    rate_limit_per_minute: 20,
    aggregation_window_seconds: 300,
    aggregation_threshold: 3,
    quiet_hours_start: null,
    quiet_hours_end: null,
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

export default function NotificationSettings() {
  const [form] = Form.useForm<TelegramConfig>()
  const [destinationForm] = Form.useForm<Destination>()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [destinations, setDestinations] = useState<Destination[]>([])
  const [editing, setEditing] = useState<Destination | null>(null)
  const [modalOpen, setModalOpen] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [config, list] = await Promise.all([
        client.get<TelegramConfig>('/settings/notifications/telegram/'),
        client.get('/notification-destinations/'),
      ])
      form.setFieldsValue({...configInitialValues(), ...config.data})
      setDestinations((list.data?.results ?? list.data ?? []) as Destination[])
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load notification settings'))
    } finally {
      setLoading(false)
    }
  }, [form])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load()
  }, [load])

  const saveConfig = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      const {data} = await client.patch<TelegramConfig>('/settings/notifications/telegram/', values)
      form.setFieldsValue({...configInitialValues(), ...data, bot_token: values.bot_token || ''})
      message.success('Telegram configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save Telegram configuration'))
    } finally {
      setSaving(false)
    }
  }

  const testDestination = async (destination: Destination) => {
    setTesting(true)
    try {
      const {data} = await client.post('/notifications/test/', {destination: destination.id})
      if (data?.success) message.success(data.detail || 'Test message delivered')
      else message.error(data?.detail || 'Test failed')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to send test message'))
    } finally {
      setTesting(false)
    }
  }

  const openModal = (destination: Destination | null) => {
    setEditing(destination)
    destinationForm.resetFields()
    if (destination) destinationForm.setFieldsValue(destination)
    setModalOpen(true)
  }

  const saveDestination = async () => {
    try {
      const values = await destinationForm.validateFields()
      if (editing) await client.patch(`/notification-destinations/${editing.id}/`, values)
      else await client.post('/notification-destinations/', values)
      message.success('Destination saved')
      setModalOpen(false)
      await load()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save destination'))
    }
  }

  const deleteDestination = async (destination: Destination) => {
    try {
      await client.delete(`/notification-destinations/${destination.id}/`)
      message.success('Destination removed')
      await load()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to remove destination'))
    }
  }

  return (
    <div style={{height: '100%', minHeight: 0, overflow: 'auto'}}>
      <Card title="Telegram" loading={loading}>
        <Alert
          type="warning"
          showIcon
          style={{marginBottom: 16}}
          message="Messages travel through Telegram infrastructure"
          description="Notifications carry internal hostnames and account names. The default posture is summary plus link, never raw logs. Treat channel membership like access to a sensitive system."
        />
        <Form form={form} layout="vertical" initialValues={configInitialValues()}>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="enabled" label="Enabled" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="bot_token" label="Bot Token" tooltip="Write-only. The API never returns the stored value.">
                <Input.Password autoComplete="new-password" placeholder="••••••••" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="asp_base_url" label="Platform Base URL" tooltip="Used to build deep links back into the platform.">
                <Input placeholder="https://soc.example.com" />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>Delivery</Divider>
          <Row gutter={16}>
            <Col span={6}>
              <Form.Item name="retry_limit" label="Retry limit">
                <InputNumber min={1} max={10} style={{width: '100%'}} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="rate_limit_per_minute" label="Rate limit (per min)">
                <InputNumber min={1} max={600} style={{width: '100%'}} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="aggregation_window_seconds" label="Aggregation window (s)">
                <InputNumber min={0} max={86400} style={{width: '100%'}} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="aggregation_threshold"
                label="Aggregate above"
                tooltip="Events of one type above this count inside the window collapse into a single summary message."
              >
                <InputNumber min={2} max={1000} style={{width: '100%'}} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="quiet_hours_start" label="Quiet hours start" tooltip="Only Critical events are sent during quiet hours.">
                <InputNumber min={0} max={23} style={{width: '100%'}} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="quiet_hours_end" label="Quiet hours end">
                <InputNumber min={0} max={23} style={{width: '100%'}} />
              </Form.Item>
            </Col>
          </Row>

          <Space>
            <Button type="primary" onClick={saveConfig} loading={saving}>Save</Button>
          </Space>
        </Form>
      </Card>

      <Card
        title="Destinations"
        style={{marginTop: 16}}
        extra={<Button type="primary" onClick={() => openModal(null)}>Add destination</Button>}
      >
        <Table
          rowKey="id"
          size="small"
          dataSource={destinations}
          pagination={false}
          columns={[
            {title: 'Name', dataIndex: 'name'},
            {title: 'Chat ID', dataIndex: 'chat_id'},
            {title: 'Topic', dataIndex: 'message_thread_id'},
            {title: 'Language', dataIndex: 'language'},
            {title: 'Events', dataIndex: 'event_types', render: (v: string[]) => (v?.length ? v.join(', ') : 'all')},
            {title: 'Enabled', dataIndex: 'enabled', render: (v: boolean) => (v ? 'Yes' : 'No')},
            {
              title: 'Actions',
              render: (_: unknown, record: Destination) => (
                <Space>
                  <Button size="small" loading={testing} onClick={() => testDestination(record)}>Test</Button>
                  <Button size="small" onClick={() => openModal(record)}>Edit</Button>
                  <Popconfirm title="Remove this destination?" onConfirm={() => deleteDestination(record)}>
                    <Button size="small" danger>Remove</Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        open={modalOpen}
        title={editing ? 'Edit destination' : 'Add destination'}
        onCancel={() => setModalOpen(false)}
        onOk={saveDestination}
        okText="Save"
        width={640}
      >
        <Form form={destinationForm} layout="vertical">
          <Form.Item name="name" label="Name" rules={[{required: true}]}>
            <Input placeholder="SOC Shift" />
          </Form.Item>
          <Form.Item name="chat_id" label="Chat ID" rules={[{required: true}]}>
            <Input placeholder="-1001234567890" />
          </Form.Item>
          <Form.Item name="message_thread_id" label="Topic ID" tooltip="Leave empty unless the group uses topics.">
            <Input />
          </Form.Item>
          <Form.Item name="language" label="Language" initialValue="vi">
            <Select options={[{label: 'Tiếng Việt', value: 'vi'}, {label: 'English', value: 'en'}]} />
          </Form.Item>
          <Form.Item name="event_types" label="Events" tooltip="Empty means every event.">
            <Select mode="multiple" allowClear options={EVENT_OPTIONS} />
          </Form.Item>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="min_severity" label="Minimum severity">
                <Select allowClear options={SEVERITY_OPTIONS} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="min_confidence" label="Minimum confidence" initialValue={0}>
                <InputNumber min={0} max={1} step={0.1} style={{width: '100%'}} />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="enabled" label="Enabled" valuePropName="checked" initialValue={true}>
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
