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
  Tag,
} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'

interface IocConfig {
  enabled: boolean
  internal_sources_only: boolean
  reputable_domains: string[]
  internal_networks: string[]
  internal_domains: string[]
  max_web_results: number
  rate_limit_per_minute: number
  ttl_ip_hours: number
  ttl_domain_hours: number
  ttl_url_hours: number
  ttl_hash_hours: number
  ttl_email_hours: number
}

interface McpServer {
  id: string
  name: string
  transport: 'http' | 'stdio'
  url_or_command: string
  auth_header: string
  token: string
  token_configured?: boolean
  timeout_seconds: number
  allowed_tools: string[]
  enabled: boolean
}

function iocInitialValues(): IocConfig {
  return {
    enabled: true,
    internal_sources_only: false,
    reputable_domains: [],
    internal_networks: [],
    internal_domains: [],
    max_web_results: 8,
    rate_limit_per_minute: 30,
    ttl_ip_hours: 24,
    ttl_domain_hours: 72,
    ttl_url_hours: 72,
    ttl_hash_hours: 720,
    ttl_email_hours: 168,
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

export default function IocVerificationSettings() {
  const [form] = Form.useForm<IocConfig>()
  const [serverForm] = Form.useForm<McpServer>()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [servers, setServers] = useState<McpServer[]>([])
  const [editing, setEditing] = useState<McpServer | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [checking, setChecking] = useState<string | null>(null)
  const internalOnly = Form.useWatch('internal_sources_only', form)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [config, list] = await Promise.all([
        client.get<IocConfig>('/settings/ioc-verification/'),
        client.get('/settings/mcp-servers/'),
      ])
      form.setFieldsValue({...iocInitialValues(), ...config.data})
      setServers((list.data?.results ?? list.data ?? []) as McpServer[])
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load IOC verification settings'))
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
      const {data} = await client.patch<IocConfig>('/settings/ioc-verification/', values)
      form.setFieldsValue({...iocInitialValues(), ...data})
      message.success('IOC verification settings saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save IOC verification settings'))
    } finally {
      setSaving(false)
    }
  }

  const openModal = (server: McpServer | null) => {
    setEditing(server)
    serverForm.resetFields()
    if (server) serverForm.setFieldsValue({...server, token: ''})
    setModalOpen(true)
  }

  const saveServer = async () => {
    try {
      const values = await serverForm.validateFields()
      if (editing) await client.patch(`/settings/mcp-servers/${editing.id}/`, values)
      else await client.post('/settings/mcp-servers/', values)
      message.success('MCP server saved')
      setModalOpen(false)
      await load()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save MCP server'))
    }
  }

  const deleteServer = async (server: McpServer) => {
    try {
      await client.delete(`/settings/mcp-servers/${server.id}/`)
      message.success('MCP server removed')
      await load()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to remove MCP server'))
    }
  }

  const checkHealth = async (server: McpServer) => {
    setChecking(server.id)
    try {
      const {data} = await client.post(`/settings/mcp-servers/${server.id}/health/`)
      if (data?.healthy) message.success(data.detail || 'MCP server healthy')
      else message.error(data?.detail || 'MCP server unreachable')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Health check failed'))
    } finally {
      setChecking(null)
    }
  }

  return (
    <div style={{height: '100%', minHeight: 0, overflow: 'auto'}}>
      <Card title="IOC Verification" loading={loading}>
        <Alert
          type="warning"
          showIcon
          style={{marginBottom: 16}}
          message="Web verification sends indicators to external services"
          description="An indicator queried against an external source can disclose that your team is investigating it. Internal indicators are never sent. Enable internal-sources-only to rely on OTX and OpenCTI alone."
        />
        <Form form={form} layout="vertical" initialValues={iocInitialValues()}>
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item name="enabled" label="Enabled" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="internal_sources_only"
                label="Internal sources only"
                valuePropName="checked"
                tooltip="Skip web MCP lookups entirely."
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="rate_limit_per_minute" label="Rate limit (per min)">
                <InputNumber min={1} max={600} style={{width: '100%'}} />
              </Form.Item>
            </Col>
          </Row>

          {internalOnly ? (
            <Alert
              type="info"
              showIcon
              style={{marginBottom: 16}}
              message="Web lookups are disabled. Verdicts rely on OTX and OpenCTI only."
            />
          ) : null}

          <Divider titlePlacement="start" plain>Scope</Divider>
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item name="internal_networks" label="Internal networks" tooltip="CIDR ranges treated as internal and never sent out.">
                <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="10.0.0.0/8" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="internal_domains" label="Internal domains">
                <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="shb.local" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="reputable_domains" label="Reputable sources" tooltip="References from these domains are weighted up.">
                <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="cisa.gov" />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>Cache TTL (hours)</Divider>
          <Row gutter={16}>
            <Col span={4}>
              <Form.Item name="ttl_ip_hours" label="IP"><InputNumber min={1} max={8760} style={{width: '100%'}} /></Form.Item>
            </Col>
            <Col span={4}>
              <Form.Item name="ttl_domain_hours" label="Domain"><InputNumber min={1} max={8760} style={{width: '100%'}} /></Form.Item>
            </Col>
            <Col span={4}>
              <Form.Item name="ttl_url_hours" label="URL"><InputNumber min={1} max={8760} style={{width: '100%'}} /></Form.Item>
            </Col>
            <Col span={4}>
              <Form.Item name="ttl_hash_hours" label="Hash"><InputNumber min={1} max={8760} style={{width: '100%'}} /></Form.Item>
            </Col>
            <Col span={4}>
              <Form.Item name="ttl_email_hours" label="Email"><InputNumber min={1} max={8760} style={{width: '100%'}} /></Form.Item>
            </Col>
            <Col span={4}>
              <Form.Item name="max_web_results" label="Max web results"><InputNumber min={1} max={50} style={{width: '100%'}} /></Form.Item>
            </Col>
          </Row>

          <Space>
            <Button type="primary" onClick={saveConfig} loading={saving}>Save</Button>
          </Space>
        </Form>
      </Card>

      <Card
        title="MCP Servers"
        style={{marginTop: 16}}
        extra={<Button type="primary" onClick={() => openModal(null)}>Add server</Button>}
      >
        <Table
          rowKey="id"
          size="small"
          dataSource={servers}
          pagination={false}
          columns={[
            {title: 'Name', dataIndex: 'name'},
            {title: 'Transport', dataIndex: 'transport'},
            {title: 'URL / Command', dataIndex: 'url_or_command', ellipsis: true},
            {
              title: 'Allowed tools',
              dataIndex: 'allowed_tools',
              render: (v: string[]) => (v?.length ? v.map((t) => <Tag key={t}>{t}</Tag>) : <Tag color="red">none</Tag>),
            },
            {title: 'Enabled', dataIndex: 'enabled', render: (v: boolean) => (v ? 'Yes' : 'No')},
            {
              title: 'Actions',
              render: (_: unknown, record: McpServer) => (
                <Space>
                  <Button size="small" loading={checking === record.id} onClick={() => checkHealth(record)}>Health</Button>
                  <Button size="small" onClick={() => openModal(record)}>Edit</Button>
                  <Popconfirm title="Remove this server?" onConfirm={() => deleteServer(record)}>
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
        title={editing ? 'Edit MCP server' : 'Add MCP server'}
        onCancel={() => setModalOpen(false)}
        onOk={saveServer}
        okText="Save"
        width={640}
      >
        <Form form={serverForm} layout="vertical">
          <Form.Item name="name" label="Name" rules={[{required: true}]}>
            <Input placeholder="brave-search" />
          </Form.Item>
          <Form.Item name="transport" label="Transport" initialValue="http">
            <Select options={[{label: 'Streamable HTTP', value: 'http'}, {label: 'stdio', value: 'stdio'}]} />
          </Form.Item>
          <Form.Item name="url_or_command" label="URL or command" rules={[{required: true}]}>
            <Input placeholder="https://mcp.example.com/mcp  or  npx -y @modelcontextprotocol/server-brave-search" />
          </Form.Item>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="auth_header" label="Auth header" tooltip="Defaults to Authorization: Bearer <token>.">
                <Input placeholder="X-API-Key" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="token" label="Token">
                <Input.Password autoComplete="new-password" placeholder="••••••••" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="allowed_tools"
            label="Allowed tools"
            tooltip="The platform refuses any tool not listed here. An empty list blocks every tool."
            rules={[{required: true, message: 'List at least one tool'}]}
          >
            <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="brave_web_search" />
          </Form.Item>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="timeout_seconds" label="Timeout (s)" initialValue={30}>
                <InputNumber min={5} max={300} style={{width: '100%'}} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="enabled" label="Enabled" valuePropName="checked" initialValue={false}>
                <Switch />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Modal>
    </div>
  )
}
