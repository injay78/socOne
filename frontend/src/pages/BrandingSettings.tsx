import {useCallback, useEffect, useState} from 'react'
import {Alert, Button, Card, Col, ColorPicker, Divider, Form, Input, Row, Space, Upload} from 'antd'
import {UploadOutlined} from '@ant-design/icons'
import type {UploadFile} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'
import {useBranding, useBrandingReload, type Branding} from '../brandingContext'

const IMAGE_FIELDS: {name: keyof Branding; label: string; hint: string}[] = [
  {name: 'logo_full', label: 'Logo full', hint: 'Ngang, kèm dòng phụ — dùng cho trang login'},
  {name: 'logo_compact', label: 'Logo compact', hint: 'Logo + tên ngắn — dùng cho header'},
  {name: 'logo_mark', label: 'Logo mark', hint: 'Chỉ ký hiệu — sidebar thu gọn'},
  {name: 'logo_dark', label: 'Logo cho nền tối', hint: 'Bản chữ sáng, dùng trên sidebar tối'},
  {name: 'favicon', label: 'Favicon', hint: 'PNG hoặc SVG, nền trong suốt'},
  {name: 'login_background', label: 'Ảnh nền login', hint: 'Tuỳ chọn'},
]

function apiErrorMessage(error: unknown, fallback: string) {
  const response = error as {response?: {data?: unknown}}
  const data = response.response?.data
  if (!data) return fallback
  if (typeof data === 'string') return data
  if (typeof data === 'object') return JSON.stringify(data)
  return fallback
}

export default function BrandingSettings() {
  const [form] = Form.useForm()
  const branding = useBranding()
  const reload = useBrandingReload()
  const [saving, setSaving] = useState(false)
  const [files, setFiles] = useState<Record<string, UploadFile[]>>({})

  const load = useCallback(() => {
    form.setFieldsValue({
      product_name: branding.product_name,
      product_short_name: branding.product_short_name,
      primary_color: branding.primary_color,
      accent_color: branding.accent_color,
    })
  }, [form, branding])

  useEffect(() => {
    load()
  }, [load])

  const save = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      const payload = new FormData()
      payload.append('product_name', values.product_name)
      payload.append('product_short_name', values.product_short_name)
      payload.append('primary_color', normaliseColour(values.primary_color))
      payload.append('accent_color', normaliseColour(values.accent_color))
      for (const field of IMAGE_FIELDS) {
        const selected = files[field.name]?.[0]
        if (selected?.originFileObj) payload.append(field.name, selected.originFileObj)
      }
      await client.patch('/settings/branding/', payload, {
        headers: {'Content-Type': 'multipart/form-data'},
      })
      message.success('Đã lưu bộ nhận diện')
      await reload()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Không lưu được bộ nhận diện'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{height: '100%', minHeight: 0, overflow: 'auto'}}>
      <Card title="Branding">
        <Alert
          type="info"
          showIcon
          style={{marginBottom: 16}}
          message="Bộ nhận diện thuộc về từng deployment"
          description="Release template giữ tên và logo trung tính. Bộ nhận diện của khách hàng nạp ở đây hoặc qua fixture triển khai, không commit vào repo."
        />
        <Form form={form} layout="vertical">
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="product_name" label="Product name" rules={[{required: true}]}>
                <Input placeholder="My SOC Platform" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="product_short_name" label="Short name" rules={[{required: true}]}>
                <Input placeholder="SOC One" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="primary_color"
                label="Primary colour"
                tooltip="Màu chủ đạo của nút và điều khiển. Không dùng màu cam ở đây: cam là màu severity."
              >
                <ColorPicker showText format="hex" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="accent_color"
                label="Accent colour"
                tooltip="Chỉ dùng cho logo và điểm nhấn thương hiệu, không áp vào nút hay trạng thái."
              >
                <ColorPicker showText format="hex" />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>Hình ảnh</Divider>
          <Row gutter={16}>
            {IMAGE_FIELDS.map((field) => (
              <Col span={8} key={field.name}>
                <Form.Item label={field.label} tooltip={field.hint}>
                  <Space direction="vertical" style={{width: '100%'}}>
                    {branding[field.name] ? (
                      <img
                        src={String(branding[field.name])}
                        alt=""
                        style={{maxHeight: 48, maxWidth: '100%', background: '#1f1f1f', padding: 4}}
                      />
                    ) : null}
                    <Upload
                      maxCount={1}
                      beforeUpload={() => false}
                      fileList={files[field.name] || []}
                      onChange={({fileList}) => setFiles((prev) => ({...prev, [field.name]: fileList}))}
                    >
                      <Button icon={<UploadOutlined />} size="small">Chọn tệp</Button>
                    </Upload>
                  </Space>
                </Form.Item>
              </Col>
            ))}
          </Row>

          <Button type="primary" onClick={save} loading={saving}>Lưu</Button>
        </Form>
      </Card>
    </div>
  )
}

function normaliseColour(value: unknown) {
  if (!value) return ''
  if (typeof value === 'string') return value
  const candidate = value as {toHexString?: () => string}
  return candidate.toHexString ? candidate.toHexString().toUpperCase() : ''
}
