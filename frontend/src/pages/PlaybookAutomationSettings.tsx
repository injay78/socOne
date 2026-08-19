import {useCallback, useEffect, useState} from 'react'
import {Alert, Button, Card, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'

interface AutomationConfig {
  enabled: boolean
  max_auto_runs_per_case: number
  updated_at?: string
}

interface AutomationRule {
  id: string
  name: string
  enabled: boolean
  keywords: string[]
  min_severity: string
  playbook_name: string
  priority: number
  fallback: boolean
}

interface PlaybookDefinition {
  name: string
  description: string
  tags: string[]
  risk_level: string
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

export default function PlaybookAutomationSettings() {
  const [configForm] = Form.useForm<AutomationConfig>()
  const [ruleForm] = Form.useForm<AutomationRule>()
  const [rules, setRules] = useState<AutomationRule[]>([])
  const [playbooks, setPlaybooks] = useState<PlaybookDefinition[]>([])
  const [loading, setLoading] = useState(false)
  const [savingConfig, setSavingConfig] = useState(false)
  const [ruleModalOpen, setRuleModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<AutomationRule | null>(null)
  const [savingRule, setSavingRule] = useState(false)

  const loadAll = useCallback(async () => {
    setLoading(true)
    try {
      const [configResponse, rulesResponse, definitionsResponse] = await Promise.all([
        client.get<AutomationConfig>('/settings/playbook-automation/'),
        client.get<AutomationRule[] | { results: AutomationRule[] }>('/settings/playbook-automation/rules/'),
        client.get<{ definitions?: PlaybookDefinition[] } | PlaybookDefinition[]>('/playbooks/definitions/'),
      ])
      configForm.setFieldsValue(configResponse.data)
      const ruleRows = Array.isArray(rulesResponse.data) ? rulesResponse.data : rulesResponse.data.results ?? []
      setRules(ruleRows)
      const defs = Array.isArray(definitionsResponse.data)
        ? definitionsResponse.data
        : definitionsResponse.data.definitions ?? []
      setPlaybooks(defs)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load playbook automation configuration'))
    } finally {
      setLoading(false)
    }
  }, [configForm])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadAll()
  }, [loadAll])

  const saveConfig = async () => {
    setSavingConfig(true)
    try {
      const values = await configForm.validateFields()
      const { data } = await client.patch<AutomationConfig>('/settings/playbook-automation/', values)
      configForm.setFieldsValue(data)
      message.success('Automation configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save automation configuration'))
    } finally {
      setSavingConfig(false)
    }
  }

  const openRuleModal = (rule: AutomationRule | null) => {
    setEditingRule(rule)
    if (rule) ruleForm.setFieldsValue(rule)
    else ruleForm.setFieldsValue({ name: '', enabled: true, keywords: [], min_severity: '', playbook_name: '', priority: 100, fallback: false })
    setRuleModalOpen(true)
  }

  const saveRule = async () => {
    setSavingRule(true)
    try {
      const values = await ruleForm.validateFields()
      if (editingRule) {
        await client.patch(`/settings/playbook-automation/rules/${editingRule.id}/`, values)
        message.success('Rule updated')
      } else {
        await client.post('/settings/playbook-automation/rules/', values)
        message.success('Rule created')
      }
      setRuleModalOpen(false)
      await loadAll()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save rule'))
    } finally {
      setSavingRule(false)
    }
  }

  const deleteRule = async (rule: AutomationRule) => {
    try {
      await client.delete(`/settings/playbook-automation/rules/${rule.id}/`)
      message.success('Rule removed')
      await loadAll()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to remove rule'))
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0, overflow: 'auto' }}>
      <Card loading={loading} title="Automation" style={{ marginBottom: 16 }}>
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="Khi bật, mỗi case mới sẽ được so khớp với các rule bên dưới (theo priority) và playbook phù hợp được xếp hàng chạy tự động."
        />
        <Form form={configForm} layout="inline">
          <Form.Item name="enabled" label="Enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="max_auto_runs_per_case" label="Max playbooks / case">
            <InputNumber min={1} max={10} />
          </Form.Item>
          <Button type="primary" onClick={saveConfig} loading={savingConfig}>Save</Button>
        </Form>
      </Card>

      <Card
        title="Rules"
        extra={<Button type="primary" onClick={() => openRuleModal(null)}>Add rule</Button>}
      >
        <Table<AutomationRule>
          rowKey="id"
          dataSource={rules}
          loading={loading}
          pagination={false}
          size="small"
          columns={[
            { title: 'Priority', dataIndex: 'priority', width: 90, sorter: (a, b) => a.priority - b.priority, defaultSortOrder: 'ascend' },
            { title: 'Name', dataIndex: 'name' },
            {
              title: 'Keywords',
              dataIndex: 'keywords',
              render: (keywords: string[], rule) =>
                keywords.length
                  ? keywords.slice(0, 6).map((keyword) => <Tag key={keyword}>{keyword}</Tag>)
                  : <Typography.Text type="secondary">{rule.fallback ? 'fallback' : 'match all'}</Typography.Text>,
            },
            { title: 'Min severity', dataIndex: 'min_severity', width: 110, render: (value: string) => value || 'Any' },
            { title: 'Playbook', dataIndex: 'playbook_name' },
            {
              title: 'Enabled',
              dataIndex: 'enabled',
              width: 90,
              render: (enabled: boolean) => (enabled ? <Tag color="green">On</Tag> : <Tag>Off</Tag>),
            },
            {
              title: 'Actions',
              width: 140,
              render: (_, rule) => (
                <Space>
                  <Button size="small" onClick={() => openRuleModal(rule)}>Edit</Button>
                  <Popconfirm title="Remove this rule?" onConfirm={() => deleteRule(rule)}>
                    <Button size="small" danger>Remove</Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        title={editingRule ? 'Edit rule' : 'Add rule'}
        open={ruleModalOpen}
        onOk={saveRule}
        confirmLoading={savingRule}
        onCancel={() => setRuleModalOpen(false)}
        destroyOnHidden
      >
        <Form form={ruleForm} layout="vertical">
          <Form.Item name="name" label="Name" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="enabled" label="Enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item
            name="keywords"
            label="Keywords"
            tooltip="Khớp chuỗi con, không phân biệt hoa thường, trên title case + rule name của alert. Bỏ trống = khớp mọi case."
          >
            <Select mode="tags" open={false} suffixIcon={null} tokenSeparators={[',']} placeholder="phishing, 4625, sql injection..." />
          </Form.Item>
          <Form.Item name="min_severity" label="Min severity">
            <Select
              options={[
                { value: '', label: 'Any' },
                { value: 'Low', label: 'Low' },
                { value: 'Medium', label: 'Medium' },
                { value: 'High', label: 'High' },
                { value: 'Critical', label: 'Critical' },
              ]}
            />
          </Form.Item>
          <Form.Item name="playbook_name" label="Playbook" rules={[{ required: true }]}>
            <Select
              showSearch
              placeholder="Chọn playbook"
              options={playbooks.map((definition) => ({ value: definition.name, label: definition.name }))}
            />
          </Form.Item>
          <Form.Item name="priority" label="Priority" tooltip="Số nhỏ chạy trước.">
            <InputNumber min={1} max={1000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="fallback"
            label="Fallback"
            valuePropName="checked"
            tooltip="Chỉ chạy khi chưa có playbook nào khác được xếp cho case."
          >
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
