import {Tabs} from 'antd'
import {Activity, Bell, Bot, DatabaseSearch, FileSearch, MonitorCheck, Network, Palette, Radar, ShieldQuestionMark, SlidersHorizontal, Tags, UsersRound, Workflow} from 'lucide-react'
import PlaybookAutomationSettings from './PlaybookAutomationSettings'
import AuditLogsSettings from './AuditLogsSettings'
import BrandingSettings from './BrandingSettings'
import EDRSettings from './EDRSettings'
import IocVerificationSettings from './IocVerificationSettings'
import NotificationSettings from './NotificationSettings'
import LDAPSettings from './LDAPSettings'
import LLMProviderSettings from './LLMProviderSettings'
import RuntimeSettings from './RuntimeSettings'
import SIEMSettings from './SIEMSettings'
import TagPreviewSettings from './TagPreviewSettings'
import ThreatIntelligenceSettings from './ThreatIntelligenceSettings'
import UserManagement from './UserManagement'
import WorkersSettings from './WorkersSettings'
import IconTabLabel from '../components/IconTabLabel'

export default function SystemSettings() {
  return (
    <div style={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      <Tabs
        defaultActiveKey="users"
        items={[
          {
            key: 'users',
            label: <IconTabLabel icon={UsersRound}>User Management</IconTabLabel>,
            children: <UserManagement />,
          },
          {
            key: 'llm-providers',
            label: <IconTabLabel icon={Bot}>LLM Providers</IconTabLabel>,
            children: <LLMProviderSettings />,
          },
          {
            key: 'threat-intelligence',
            label: <IconTabLabel icon={Radar}>Threat Intelligence</IconTabLabel>,
            children: <ThreatIntelligenceSettings />,
          },
          {
            key: 'ioc-verification',
            label: <IconTabLabel icon={ShieldQuestionMark}>IOC Verify</IconTabLabel>,
            children: <IocVerificationSettings />,
          },
          {
            key: 'playbook-automation',
            label: <IconTabLabel icon={Workflow}>Playbook Automation</IconTabLabel>,
            children: <PlaybookAutomationSettings />,
          },
          {
            key: 'siem',
            label: <IconTabLabel icon={DatabaseSearch}>SIEM</IconTabLabel>,
            children: <SIEMSettings />,
          },
          {
            key: 'edr',
            label: <IconTabLabel icon={MonitorCheck}>EDR</IconTabLabel>,
            children: <EDRSettings />,
          },
          {
            key: 'notifications',
            label: <IconTabLabel icon={Bell}>Notifications</IconTabLabel>,
            children: <NotificationSettings />,
          },
          {
            key: 'ldap',
            label: <IconTabLabel icon={Network}>LDAP</IconTabLabel>,
            children: <LDAPSettings />,
          },
          {
            key: 'runtime',
            label: <IconTabLabel icon={SlidersHorizontal}>Runtime</IconTabLabel>,
            children: <RuntimeSettings />,
          },
          {
            key: 'branding',
            label: <IconTabLabel icon={Palette}>Branding</IconTabLabel>,
            children: <BrandingSettings />,
          },
          {
            key: 'workers',
            label: <IconTabLabel icon={Activity}>Workers</IconTabLabel>,
            children: <WorkersSettings />,
          },
          {
            key: 'tag-preview',
            label: <IconTabLabel icon={Tags}>Tags</IconTabLabel>,
            children: <TagPreviewSettings />,
          },
          {
            key: 'audit-logs',
            label: <IconTabLabel icon={FileSearch}>Audit Logs</IconTabLabel>,
            children: <AuditLogsSettings />,
          },
        ]}
        style={{ flex: 1, minHeight: 0 }}
        className="system-settings-tabs"
      />
    </div>
  )
}
