import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';

type Identity = { username: string; role: string; type: string };
type Domain = { id: number; name: string; dnsMode?: string; certMode?: string; provider?: string; zoneId?: string; status?: string };
type HABackend = { name: string; url: string };
type Host = { id: number; fqdn: string; upstreamUrl: string; insecureTls?: boolean; haEnabled?: boolean; haMode?: string; haBackends?: HABackend[]; authEnabled?: boolean; authUser?: string; geoMode?: string; geoCountries?: string[]; state: string; errorReason?: string };
type HostDiagnostic = { fqdn: string; dnsRecords: string[]; httpStatus: number; httpsStatus: number; tlsOk: boolean; certSubject: string; certIssuer: string; certNotAfter: string; certDaysLeft: number; haEnabled?: boolean; haMode?: string; haOnline?: number; haTotal?: number; haOffline?: string[]; error?: string };
type HostLiveCheck = { fqdn: string; dnsOk: boolean; dnsPointsToServer: boolean; httpReachable: boolean; httpsReachable: boolean; tlsOk: boolean; certDaysLeft: number; cloudflareRecordFound: boolean; error?: string };
type DomainLiveCheck = { domain: string; dnsMode: string; provider: string; serverIpv4?: string; apexDnsOk: boolean; apexPointsToServer: boolean; cloudflareApiOk: boolean; cloudflareZoneId?: string; cloudflareError?: string; hosts: HostLiveCheck[]; warnings?: string[]; overallOk: boolean };
type Audit = { id: number; actor: string; action: string; target: string; meta?: string; sourceIp?: string; createdAt: string };
type BlockedIP = { ip: string; reason?: string; createdAt: string; updatedAt: string };
type APIToken = { id: number; name: string; tokenPrefix: string; scopes: string; role: string; expiresAt: string; lastUsedAt?: string };
type LogServerSyslogSettings = { enabled: boolean; protocol: 'udp' | 'tcp'; address: string; minLevel: 'info' | 'warn' | 'error'; appName: string };
type LogServerHTTPSettings = { enabled: boolean; url: string; timeoutSec: number; minLevel: 'info' | 'warn' | 'error'; insecure: boolean };
type LogServerTCPJSONSettings = { enabled: boolean; address: string; timeoutSec: number; minLevel: 'info' | 'warn' | 'error' };
type LogServerSettings = { syslog: LogServerSyslogSettings; http: LogServerHTTPSettings; tcpJson: LogServerTCPJSONSettings };
type RetentionPolicy = { auditDays: number; trafficDays: number; visitorsDays: number; threatDays: number; blockedDays: number; loginAttemptDays: number; passwordResetDays: number };
type RuntimeSettings = { domain: string; baseDomain?: string; adminFqdn?: string; acmeEmail: string; acmeStaging: boolean; hasCloudflareToken: boolean; publicIpv4?: string; styleProfile?: string; styleCustom?: string; timeSyncMode?: 'system_only' | 'external_public' | 'external_lan'; timeSyncLANServers?: string[]; logServers?: LogServerSettings; hasLogHTTPBearer?: boolean; retention?: RetentionPolicy };
type SetupStatus = { initialized: boolean; locked: boolean; unlocked: boolean; restoreReady?: boolean; otsExpiresAt?: string; unlockUntil?: string; cooldownUntil?: string };
type SetupBackupMeta = { fileName: string; format: string; createdAt: string; domnexVersion: string; domains: number; subdomains: number; users: number };
type BackupMeta = SetupBackupMeta & { dbSha256?: string; keySha256?: string };
type BackupFTPSettings = { enabled: boolean; host: string; port: number; username: string; remoteDir: string; tlsMode: 'off' | 'explicit' | 'implicit'; hasPassword?: boolean };
type BackupLocalSettings = { enabled: boolean; dir: string };
type BackupScheduleSettings = { enabled: boolean; intervalHours: number; retentionCount: number; hasPassphrase?: boolean; lastRunAt?: string; lastResult?: string; local: BackupLocalSettings; ftp: BackupFTPSettings };
type BackupArchive = { id: number; fileName: string; storage: 'local' | 'ftp'; location: string; sizeBytes: number; sha256: string; status: string; createdAt: string };
type BackupStats = { totalArchives: number; localArchives: number; ftpArchives: number };
type BackupTab = 'general' | 'browser' | 'settings' | 'manual';
type PostRestoreCheck = {
  checkedAt: string;
  domainsTotal: number;
  domainsOk: number;
  hostsTotal: number;
  hostsDnsOk: number;
  hostsHttpsOk: number;
  hostsTlsOk: number;
  hostsCertValid: number;
  certWarmupAttempts: number;
  certWarmupSucceeded: number;
  issues: string[];
};
type TimeSyncProbe = { name: string; target: string; ok: boolean; offsetMs: number; rttMs: number; error?: string; detail?: string };
type TimeSyncStatus = { mode: 'system_only' | 'external_public' | 'external_lan'; healthy: boolean; severity: 'ok' | 'warn' | 'critical'; summary: string; source?: string; offsetMs?: number; checkedAt: string; probes: TimeSyncProbe[] };
type SystemHealth = {
  cpuPercent: number;
  ramPercent: number;
  ramTotalBytes: number;
  ramUsedBytes: number;
  networkLoadPct: number;
  networkBaselineBps: number;
  networkBytesPerSec: number;
  load1: number;
  cpuCores: number;
};
type ManagedUser = {
  id: number;
  username: string;
  role: string;
  domainIds: number[];
  allowedCidrs?: string;
  ipCheckDisabled?: boolean;
  createdAt: string;
  updatedAt: string;
};
type DomainPreflightCheck = { name: string; ok: boolean; detail?: string };
type DomainPreflight = { domain: string; dnsMode: string; provider: string; zoneId?: string; resolvedZone?: string; publicIpv4?: string; checks: DomainPreflightCheck[]; ready: boolean };
type HostPreflightCheck = { name: string; ok: boolean; detail?: string };
type HostPreflight = { domain: string; fqdn?: string; upstream: string; insecureTls?: boolean; dnsMode?: string; provider?: string; zoneId?: string; checks: HostPreflightCheck[]; ready: boolean };
type TrafficHostSummary = { hostId: number; fqdn: string; requests: number; bytesIn: number; bytesOut: number; blocked: number; uniqueVisitors: number; status2xx: number; status3xx: number; status4xx: number; status5xx: number };
type TrafficOverview = { hours: number; generatedAt: string; totalRequests: number; totalBytesIn: number; totalBytesOut: number; totalBlocked: number; uniqueVisitors: number; hosts: TrafficHostSummary[] };
type TrafficPoint = { bucketStart: string; requests: number; bytesIn: number; bytesOut: number; blocked: number; status2xx: number; status3xx: number; status4xx: number; status5xx: number };
type HostTrafficDetails = { hours: number; hostId: number; fqdn: string; requests: number; bytesIn: number; bytesOut: number; blocked: number; uniqueVisitors: number; status2xx: number; status3xx: number; status4xx: number; status5xx: number; series: TrafficPoint[] };
type CountryTraffic = { country: string; requests: number; blocked: number; status2xx: number; status3xx: number; status4xx: number; status5xx: number; bytesOut: number };
type HostCountryTraffic = { hostId: number; fqdn: string; requests: number; blocked: number; status2xx: number; status3xx: number; status4xx: number; status5xx: number; bytesOut: number };
type TrafficCountryOverview = { hours: number; generatedAt: string; requestClass?: string; hostId?: number; hostFqdn?: string; totalRequests: number; totalBlocked: number; totalBytesOut: number; countries: CountryTraffic[]; unknownBreakdown?: HostCountryTraffic[] };
type TrafficLiveEvent = {
  ts: string;
  hostId: number;
  domainId: number;
  fqdn: string;
  country: string;
  class: 'human' | 'crawler' | 'unknown';
  scanner: boolean;
  status: number;
  path: string;
  sourceType: 'internal' | 'external';
};
type LiveTracePoint = {
  id: string;
  seenAt: number;
  country: string;
  hostId: number;
  fqdn: string;
  scanner: boolean;
  class: 'human' | 'crawler' | 'unknown';
};
type ThreatGeoPoint = {
  country: string;
  state: 'monitor' | 'soft' | 'hard';
  ips: number;
  hits: number;
};
type SSHBastionRoute = { id: number; fqdn: string; targetHost: string; targetPort: number; enabled: boolean; createdAt: string; updatedAt: string };
type SSHBastionKey = { id: number; name: string; publicKey: string; fingerprint: string; enabled: boolean; routeIds: number[]; createdAt: string; updatedAt: string };
type SSHBastionGenerate = { key: SSHBastionKey; privateKey?: string; privateKeyPpk?: string; publicKeyRfc4716?: string; ppkError?: string };
type ThreatIntelConfig = {
  enabled: boolean;
  mode: 'monitor_only' | 'auto_mode';
  syncHours: number;
  eventMinHits: number;
  offenderMinHits: number;
  monitorMaxLevel: number;
  softMinLevel: number;
  hardLevel: number;
  softBlockMinutes: number;
};
type ThreatIntelFeed = { id: number; name: string; url: string; enabled: boolean; isDefault?: boolean; entryCount?: number; lastSyncAt?: string; lastError?: string; lastHash?: string; createdAt?: string; updatedAt?: string };
type ThreatIntelMatch = { id: number; ip: string; feed: string; host: string; path: string; targetCount?: number; country: string; mode: string; decision: string; hits: number; firstSeenAt: string; lastSeenAt: string; lastTraceId?: string; sourceScope?: string; xp?: number; level?: number; tier?: string; riskState?: string };
type ThreatIntelTarget = { host: string; path: string; feed: string; decision: string; hits: number; lastSeenAt: string };
type ThreatIntelOffender = { ip: string; totalHits: number; distinctFeeds: number; distinctHosts: number; decisions: string; lastSeenAt: string; blocked: boolean; allowlisted: boolean; xp?: number; level?: number; tier?: string; riskState?: string };
type ThreatIntelBlocked = { ip: string; reason?: string; history?: string; updatedAt: string; totalHits: number; distinctFeeds: number; distinctHosts: number; lastSeenAt?: string; xp?: number; level?: number; tier?: string; riskState?: string };
type ThreatIntelMatchesPage = { items: ThreatIntelMatch[]; total: number; page: number; pageSize: number };
type ThreatIntelOffendersPage = { items: ThreatIntelOffender[]; total: number; page: number; pageSize: number };
type ThreatIntelBlockedPage = { items: ThreatIntelBlocked[]; total: number; page: number; pageSize: number };
type DashboardWidgetType =
  | 'ha_alerts'
  | 'kpi_overview'
  | 'health_gauges'
  | 'system_health'
  | 'performance_snapshot'
  | 'traffic_snapshot'
  | 'control_plane_health'
  | 'recent_events'
  | 'security_snapshot'
  | 'quick_actions'
  | 'degraded_hosts';
type DashboardWidget = { id: string; type: DashboardWidgetType; w: number; h: number };
type DashboardUserTab = { id: string; name: string; widgets: DashboardWidget[] };
type DashboardLayout = { version: number; tabs: DashboardUserTab[] };
type MeProfile = { email: string; dashboardLayout?: DashboardLayout };

type Tab = 'dashboard' | 'metricCenter' | 'threatIntel' | 'domains' | 'hosts' | 'backup' | 'users' | 'settings' | 'api' | 'ssh' | 'audit' | 'account' | 'accessControl' | 'integrations' | 'help';
type SettingsTab = 'general' | 'security' | 'logservers' | 'appearance' | 'advanced';
type DomainProvider = 'cloudflare' | 'strato' | 'manual';
type StyleProfile = 'monolith' | 'cybermonolith' | 'custom';
type PublicStyle = { styleProfile?: string; styleCustom?: string };
type ThemeVars = {
  bg: string;
  surface: string;
  panel: string;
  panelHover: string;
  border: string;
  text: string;
  textDim: string;
  accent: string;
  accentHover: string;
  accentActive: string;
  accentSoft: string;
  success: string;
  danger: string;
  inputBg: string;
  heroA: string;
  heroB: string;
};
const SSH_BASTION_DEFAULT_UPSTREAM = 'http://127.0.0.1:8443';
const SSH_BASTION_DEFAULT_TARGET_HOST = '127.0.0.1';
const SSH_BASTION_DEFAULT_TARGET_PORT = 22;
const defaultLogServers = (): LogServerSettings => ({
  syslog: { enabled: false, protocol: 'udp', address: '', minLevel: 'info', appName: 'DomNexDomain' },
  http: { enabled: false, url: '', timeoutSec: 4, minLevel: 'warn', insecure: false },
  tcpJson: { enabled: false, address: '', timeoutSec: 3, minLevel: 'info' },
});
const defaultRetentionPolicy = (): RetentionPolicy => ({
  auditDays: 90,
  trafficDays: 30,
  visitorsDays: 30,
  threatDays: 60,
  blockedDays: 60,
  loginAttemptDays: 30,
  passwordResetDays: 7,
});
const defaultBackupScheduleSettings = (): BackupScheduleSettings => ({
  enabled: false,
  intervalHours: 24,
  retentionCount: 10,
  hasPassphrase: false,
  local: {
    enabled: true,
    dir: '/var/lib/domnexdomain/backups',
  },
  ftp: {
    enabled: false,
    host: '',
    port: 21,
    username: '',
    remoteDir: '/',
    tlsMode: 'explicit',
    hasPassword: false,
  },
});

const mkID = () => `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

const DASHBOARD_WIDGET_STORE: Array<{
  type: DashboardWidgetType;
  category: 'Metrics' | 'Traffic' | 'Security' | 'Operations' | 'Quick Actions';
  title: string;
  description: string;
  defaultW: number;
  defaultH: number;
}> = [
  { type: 'kpi_overview', category: 'Metrics', title: 'KPI Overview', description: 'Domains, active hosts, host errors and monitored hosts.', defaultW: 12, defaultH: 1 },
  { type: 'health_gauges', category: 'Metrics', title: 'Health Gauges', description: 'DNS/HTTP/HTTPS/TLS and certificate window health.', defaultW: 12, defaultH: 2 },
  { type: 'system_health', category: 'Metrics', title: 'System Health', description: 'CPU, RAM and network load gauges from host telemetry.', defaultW: 12, defaultH: 2 },
  { type: 'performance_snapshot', category: 'Metrics', title: 'Performance Snapshot', description: 'Protocol status and certificate quality summary.', defaultW: 6, defaultH: 2 },
  { type: 'traffic_snapshot', category: 'Traffic', title: 'Traffic Snapshot', description: 'Requests, visitors, egress and blocked counters.', defaultW: 6, defaultH: 2 },
  { type: 'control_plane_health', category: 'Operations', title: 'Control Plane Health', description: 'Cloudflare/ACME/Time-sync state with probe highlights.', defaultW: 6, defaultH: 2 },
  { type: 'recent_events', category: 'Operations', title: 'Recent Events', description: 'Latest audit stream entries for fast situational awareness.', defaultW: 6, defaultH: 2 },
  { type: 'security_snapshot', category: 'Security', title: 'Security Snapshot', description: 'Audit severity split and blocked IP counters.', defaultW: 6, defaultH: 1 },
  { type: 'ha_alerts', category: 'Security', title: 'HA Alerts', description: 'Shows degraded HA routes and currently offline backends.', defaultW: 12, defaultH: 1 },
  { type: 'degraded_hosts', category: 'Operations', title: 'Degraded Hosts', description: 'List of subdomains currently in error state.', defaultW: 6, defaultH: 2 },
  { type: 'quick_actions', category: 'Quick Actions', title: 'Quick Actions', description: 'Common operations and direct links to operational views.', defaultW: 6, defaultH: 1 },
];

const dashboardWidgetByType = Object.fromEntries(DASHBOARD_WIDGET_STORE.map((w) => [w.type, w])) as Record<DashboardWidgetType, (typeof DASHBOARD_WIDGET_STORE)[number]>;

const defaultDashboardLayout = (): DashboardLayout => ({
  version: 1,
  tabs: [
    {
      id: 'minimal',
      name: 'Minimal',
      widgets: [
        { id: mkID(), type: 'kpi_overview', w: 12, h: 1 },
        { id: mkID(), type: 'health_gauges', w: 12, h: 2 },
        { id: mkID(), type: 'quick_actions', w: 12, h: 1 },
      ],
    },
    {
      id: 'security',
      name: 'Security',
      widgets: [
        { id: mkID(), type: 'ha_alerts', w: 12, h: 1 },
        { id: mkID(), type: 'security_snapshot', w: 6, h: 1 },
        { id: mkID(), type: 'control_plane_health', w: 6, h: 2 },
        { id: mkID(), type: 'recent_events', w: 12, h: 2 },
      ],
    },
    {
      id: 'network',
      name: 'Network',
      widgets: [
        { id: mkID(), type: 'traffic_snapshot', w: 6, h: 2 },
        { id: mkID(), type: 'performance_snapshot', w: 6, h: 2 },
        { id: mkID(), type: 'system_health', w: 12, h: 2 },
        { id: mkID(), type: 'degraded_hosts', w: 12, h: 2 },
      ],
    },
    {
      id: 'forensic',
      name: 'Forensic',
      widgets: [
        { id: mkID(), type: 'recent_events', w: 12, h: 2 },
        { id: mkID(), type: 'security_snapshot', w: 6, h: 1 },
        { id: mkID(), type: 'degraded_hosts', w: 6, h: 2 },
        { id: mkID(), type: 'control_plane_health', w: 12, h: 2 },
      ],
    },
  ],
});

function isLegacyOverviewLayout(layout: DashboardLayout): boolean {
  if (!layout || !Array.isArray(layout.tabs) || layout.tabs.length !== 1) return false;
  const t = layout.tabs[0];
  if (!t || String(t.name || '').toLowerCase() !== 'overview') return false;
  return true;
}

function normalizeDashboardLayout(raw: unknown): DashboardLayout {
  const fallback = defaultDashboardLayout();
  if (!raw || typeof raw !== 'object') return fallback;
  const anyRaw = raw as { version?: unknown; tabs?: unknown };
  const rawTabs = Array.isArray(anyRaw.tabs) ? anyRaw.tabs : [];
  const tabs: DashboardUserTab[] = rawTabs.map((t, idx) => {
    const o = t as { id?: unknown; name?: unknown; widgets?: unknown };
    const rawWidgets = Array.isArray(o.widgets) ? o.widgets : [];
    const widgets: DashboardWidget[] = rawWidgets
      .map((w) => {
        const ow = w as { id?: unknown; type?: unknown; w?: unknown; h?: unknown };
        const type = String(ow.type || '') as DashboardWidgetType;
        if (!dashboardWidgetByType[type]) return null;
        const width = Math.max(3, Math.min(12, Number(ow.w || dashboardWidgetByType[type].defaultW || 6)));
        const height = Math.max(1, Math.min(3, Number(ow.h || dashboardWidgetByType[type].defaultH || 1)));
        return {
          id: String(ow.id || mkID()),
          type,
          w: Number.isFinite(width) ? width : dashboardWidgetByType[type].defaultW,
          h: Number.isFinite(height) ? height : dashboardWidgetByType[type].defaultH,
        };
      })
      .filter(Boolean) as DashboardWidget[];
    return {
      id: String(o.id || `tab-${idx + 1}`),
      name: String(o.name || `Tab ${idx + 1}`).slice(0, 48),
      widgets,
    };
  }).filter((t) => t.widgets.length > 0);
  if (tabs.length === 0) return fallback;
  return {
    version: 1,
    tabs,
  };
}
const MONOLITH_THEME: ThemeVars = {
  bg: '#0f0f11',
  surface: '#16161a',
  panel: '#121219',
  panelHover: '#171722',
  border: '#222229',
  text: '#e0e0e5',
  textDim: '#9ca3af',
  accent: '#6366f1',
  accentHover: '#4f46e5',
  accentActive: '#4f46e5',
  accentSoft: 'rgba(99,102,241,.12)',
  success: '#10b981',
  danger: '#ef4444',
  inputBg: '#0f0f14',
  heroA: 'rgba(56,189,248,.15)',
  heroB: 'rgba(99,102,241,.2)',
};
const CYBER_MONOLITH_THEME: ThemeVars = {
  bg: '#16161a',
  surface: '#1c1c22',
  panel: '#1c1c22',
  panelHover: '#23232c',
  border: '#2a2a36',
  text: '#e6e6f0',
  textDim: '#8b8b99',
  accent: '#8b5cf6',
  accentHover: '#a78bfa',
  accentActive: '#7c3aed',
  accentSoft: 'rgba(139,92,246,.16)',
  success: '#10b981',
  danger: '#dc2626',
  inputBg: '#17171d',
  heroA: 'rgba(139,92,246,.16)',
  heroB: 'rgba(124,58,237,.12)',
};

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
    ...init,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = new Error(data.error || `${res.status} ${res.statusText}`) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }
  return data as T;
}

async function apiMultipart<T>(path: string, form: FormData, csrf?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (csrf) headers['X-CSRF-Token'] = csrf;
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers,
    body: form,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = new Error(data.error || `${res.status} ${res.statusText}`) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }
  return data as T;
}

function getCookie(name: string): string {
  const item = document.cookie.split('; ').find((v) => v.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.split('=')[1]) : '';
}

function downloadTextFile(filename: string, content: string): void {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadBinaryFile(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function parseCustomThemeJSON(raw: string): Partial<ThemeVars> {
  const txt = raw.trim();
  if (!txt) return {};
  try {
    const obj = JSON.parse(txt) as Record<string, string>;
    const out: Partial<ThemeVars> = {};
    const allowed = new Set<keyof ThemeVars>([
      'bg', 'surface', 'panel', 'panelHover', 'border', 'text', 'textDim',
      'accent', 'accentHover', 'accentActive', 'accentSoft', 'success', 'danger',
      'inputBg', 'heroA', 'heroB',
    ]);
    for (const [k, v] of Object.entries(obj)) {
      if (!allowed.has(k as keyof ThemeVars)) continue;
      const sv = String(v || '').trim();
      if (!sv || sv.length > 64) continue;
      if (!/^[#a-zA-Z0-9(),.%\-\s]+$/.test(sv)) continue;
      (out as Record<string, string>)[k] = sv;
    }
    return out;
  } catch {
    return {};
  }
}

class RootErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: string }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { error: '' };
  }
  static getDerivedStateFromError(err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: msg || 'Unknown UI runtime error' };
  }
  componentDidCatch(err: unknown) {
    // Keep a clear trace in browser console for debugging white-screen incidents.
    // eslint-disable-next-line no-console
    console.error('DomNex UI runtime error:', err);
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: '1rem', fontFamily: 'monospace' }}>
          <h2>DomNex UI Runtime Error</h2>
          <p>{this.state.error}</p>
          <p>Reload the page. If this persists, report this message in GitHub/Discord support.</p>
        </div>
      );
    }
    return this.props.children as React.ReactElement;
  }
}

function App() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [dashboardLayout, setDashboardLayout] = useState<DashboardLayout>(defaultDashboardLayout());
  const [dashboardTabID, setDashboardTabID] = useState('minimal');
  const [dashboardEditMode, setDashboardEditMode] = useState(false);
  const [dashboardDraft, setDashboardDraft] = useState<DashboardLayout>(defaultDashboardLayout());
  const [dashboardNewTabName, setDashboardNewTabName] = useState('');
  const [dashboardWidgetQuery, setDashboardWidgetQuery] = useState('');
  const [domains, setDomains] = useState<Domain[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostDiagnostics, setHostDiagnostics] = useState<Record<string, HostDiagnostic>>({});
  const [audit, setAudit] = useState<Audit[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<BlockedIP[]>([]);
  const [tiConfig, setTiConfig] = useState<ThreatIntelConfig>({
    enabled: false,
    mode: 'monitor_only',
    syncHours: 24,
    eventMinHits: 2,
    offenderMinHits: 10,
    monitorMaxLevel: 2,
    softMinLevel: 3,
    hardLevel: 6,
    softBlockMinutes: 15,
  });
  const [tiFeeds, setTiFeeds] = useState<ThreatIntelFeed[]>([]);
  const [tiMatches, setTiMatches] = useState<ThreatIntelMatch[]>([]);
  const [tiOffenders, setTiOffenders] = useState<ThreatIntelOffender[]>([]);
  const [tiAllowlist, setTiAllowlist] = useState<BlockedIP[]>([]);
  const [tiHours, setTiHours] = useState(24);
  const [tiDecision, setTiDecision] = useState('all');
  const [tiQuery, setTiQuery] = useState('');
  const [tiView, setTiView] = useState<'events' | 'offenders'>('events');
  const [tiPage, setTiPage] = useState(1);
  const [tiPageSize, setTiPageSize] = useState(100);
  const [tiTotalMatches, setTiTotalMatches] = useState(0);
  const [tiTotalOffenders, setTiTotalOffenders] = useState(0);
  const [tiTotalBlocked, setTiTotalBlocked] = useState(0);
  const [tiFeedsOpen, setTiFeedsOpen] = useState(false);
  const [tiAllowOpen, setTiAllowOpen] = useState(false);
  const [tiBlockedOpen, setTiBlockedOpen] = useState(false);
  const [tiTargetsOpen, setTiTargetsOpen] = useState(false);
  const [tiTargetsIP, setTiTargetsIP] = useState('');
  const [tiTargets, setTiTargets] = useState<ThreatIntelTarget[]>([]);
  const [tiBlocked, setTiBlocked] = useState<ThreatIntelBlocked[]>([]);
  const [tiFeedName, setTiFeedName] = useState('');
  const [tiFeedURL, setTiFeedURL] = useState('');
  const [tiFeedEnabled, setTiFeedEnabled] = useState(true);
  const [tiAllowIP, setTiAllowIP] = useState('');
  const [tiAllowReason, setTiAllowReason] = useState('');
  const [tiConfigSavedAt, setTiConfigSavedAt] = useState('');
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [domainChecks, setDomainChecks] = useState<Record<number, DomainLiveCheck>>({});
  const [trafficOverview, setTrafficOverview] = useState<TrafficOverview | null>(null);
  const [selectedHostTraffic, setSelectedHostTraffic] = useState<HostTrafficDetails | null>(null);
  const [metricCountryOverview, setMetricCountryOverview] = useState<TrafficCountryOverview | null>(null);
  const [metricHostFilter, setMetricHostFilter] = useState('all');
  const [metricHours, setMetricHours] = useState(24);
  const [metricClass, setMetricClass] = useState<'all' | 'human' | 'crawler' | 'unknown'>('all');
  const [metricCountryFocus, setMetricCountryFocus] = useState('all');
  const [metricMapOpen, setMetricMapOpen] = useState(false);
  const [metricMapMode, setMetricMapMode] = useState<'historical' | 'live' | 'threat'>('historical');
  const [metricLivePoints, setMetricLivePoints] = useState<LiveTracePoint[]>([]);
  const [metricLiveConnected, setMetricLiveConnected] = useState(false);
  const [metricThreatGeo, setMetricThreatGeo] = useState<ThreatGeoPoint[]>([]);
  const [metricThreatGeoAt, setMetricThreatGeoAt] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const [loginUser, setLoginUser] = useState('admin');
  const [loginPass, setLoginPass] = useState('');
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [setupMode, setSetupMode] = useState<'fresh' | 'restore'>('fresh');
  const [setupStep, setSetupStep] = useState(1);
  const [setupOTS, setSetupOTS] = useState('');
  const [setupAdminUser, setSetupAdminUser] = useState('admin');
  const [setupAdminPass, setSetupAdminPass] = useState('');
  const [setupAdminPass2, setSetupAdminPass2] = useState('');
  const [setupDomainName, setSetupDomainName] = useState('');
  const [setupDomainDNSMode, setSetupDomainDNSMode] = useState<'manual' | 'cloudflare'>('cloudflare');
  const [setupDomainCertMode, setSetupDomainCertMode] = useState<'letsencrypt' | 'letsencrypt-catchall'>('letsencrypt-catchall');
  const [setupDomainZoneID, setSetupDomainZoneID] = useState('');
  const [setupFirstSub, setSetupFirstSub] = useState('');
  const [setupFirstUpstream, setSetupFirstUpstream] = useState('http://127.0.0.1:3000');
  const [setupBackupPassphrase, setSetupBackupPassphrase] = useState('');
  const [setupBackupFile, setSetupBackupFile] = useState<File | null>(null);
  const [setupBackupMeta, setSetupBackupMeta] = useState<SetupBackupMeta | null>(null);
  const [domainName, setDomainName] = useState('');
  const [domainProvider, setDomainProvider] = useState<DomainProvider>('cloudflare');
  const [domainZoneID, setDomainZoneID] = useState('');
  const [domainWizardStep, setDomainWizardStep] = useState(1);
  const [domainPreflight, setDomainPreflight] = useState<DomainPreflight | null>(null);
  const [domainPreflightRunning, setDomainPreflightRunning] = useState(false);
  const [hostDomain, setHostDomain] = useState('');
  const [hostSub, setHostSub] = useState('');
  const [hostUpstream, setHostUpstream] = useState('http://127.0.0.1:3000');
  const [hostSSHBastion, setHostSSHBastion] = useState(false);
  const [hostInsecureTLS, setHostInsecureTLS] = useState(false);
  const [hostHAEnabled, setHostHAEnabled] = useState(false);
  const [hostHAMode, setHostHAMode] = useState<'failover' | 'round_robin'>('failover');
  const [hostHABackends, setHostHABackends] = useState<HABackend[]>([{ name: 'server1', url: '' }, { name: 'server2', url: '' }]);
  const [hostWizardStep, setHostWizardStep] = useState(1);
  const [hostPreflight, setHostPreflight] = useState<HostPreflight | null>(null);
  const [hostPreflightRunning, setHostPreflightRunning] = useState(false);
  const [selectedHostID, setSelectedHostID] = useState<number | null>(null);
  const [detailUpstream, setDetailUpstream] = useState('');
  const [detailInsecureTLS, setDetailInsecureTLS] = useState(false);
  const [detailHAEnabled, setDetailHAEnabled] = useState(false);
  const [detailHAMode, setDetailHAMode] = useState<'failover' | 'round_robin'>('failover');
  const [detailHABackends, setDetailHABackends] = useState<HABackend[]>([]);
  const [detailAuthEnabled, setDetailAuthEnabled] = useState(false);
  const [detailAuthUser, setDetailAuthUser] = useState('');
  const [detailAuthPass, setDetailAuthPass] = useState('');
  const [detailGeoMode, setDetailGeoMode] = useState<'off' | 'allow' | 'deny'>('off');
  const [detailGeoCountries, setDetailGeoCountries] = useState('');
  const [detailSavingGeneral, setDetailSavingGeneral] = useState(false);
  const [detailSavingAuth, setDetailSavingAuth] = useState(false);
  const [detailSavingGeo, setDetailSavingGeo] = useState(false);
  const [newTokenName, setNewTokenName] = useState('automation');
  const [newTokenRole, setNewTokenRole] = useState('operator');
  const [newTokenScopes, setNewTokenScopes] = useState('');
  const [newTokenGlobalRead, setNewTokenGlobalRead] = useState(false);
  const [newTokenGlobalWrite, setNewTokenGlobalWrite] = useState(false);
  const [newTokenDomainRead, setNewTokenDomainRead] = useState(true);
  const [newTokenDomainWrite, setNewTokenDomainWrite] = useState(true);
  const [newTokenSystemRead, setNewTokenSystemRead] = useState(false);
  const [newTokenSystemWrite, setNewTokenSystemWrite] = useState(false);
  const [newTokenDomainIDs, setNewTokenDomainIDs] = useState<number[]>([]);
  const [newTokenTTL, setNewTokenTTL] = useState('720h');
  const [createdToken, setCreatedToken] = useState('');
  const [resetUser, setResetUser] = useState('admin');
  const [resetTTL, setResetTTL] = useState('30m');
  const [resetToken, setResetToken] = useState('');
  const [resetNewPassword, setResetNewPassword] = useState('');
  const [logQuery, setLogQuery] = useState('');
  const [logWindow, setLogWindow] = useState<'15m' | '1h' | '6h' | '24h' | '7d' | 'all'>('24h');
  const [logLevelFilter, setLogLevelFilter] = useState<'all' | 'critical' | 'warn' | 'info'>('all');
  const [logNamespaceFilter, setLogNamespaceFilter] = useState('all');
  const [logActionFilter, setLogActionFilter] = useState('all');
  const [logActorFilter, setLogActorFilter] = useState('all');
  const [logIPFilter, setLogIPFilter] = useState('all');
  const [logScopeFilter, setLogScopeFilter] = useState<'all' | 'internal' | 'external'>('all');
  const [logTargetQuery, setLogTargetQuery] = useState('');
  const [settings, setSettings] = useState<RuntimeSettings | null>(null);
  const [settingsAcmeEmail, setSettingsAcmeEmail] = useState('');
  const [settingsAcmeStaging, setSettingsAcmeStaging] = useState(false);
  const [settingsCFToken, setSettingsCFToken] = useState('');
  const [settingsPublicIPv4, setSettingsPublicIPv4] = useState('');
  const [settingsBaseDomain, setSettingsBaseDomain] = useState('');
  const [settingsStyleProfile, setSettingsStyleProfile] = useState<StyleProfile>('monolith');
  const [settingsStyleCustom, setSettingsStyleCustom] = useState('');
  const [settingsTimeSyncMode, setSettingsTimeSyncMode] = useState<'system_only' | 'external_public' | 'external_lan'>('system_only');
  const [settingsTimeSyncLAN, setSettingsTimeSyncLAN] = useState('');
  const [settingsLogServers, setSettingsLogServers] = useState<LogServerSettings>(defaultLogServers());
  const [settingsLogHTTPBearer, setSettingsLogHTTPBearer] = useState('');
  const [settingsRetention, setSettingsRetention] = useState<RetentionPolicy>(defaultRetentionPolicy());
  const [backupPassphrase, setBackupPassphrase] = useState('');
  const [backupRestorePassphrase, setBackupRestorePassphrase] = useState('');
  const [backupRestoreConfirm, setBackupRestoreConfirm] = useState('');
  const [backupRestoreFile, setBackupRestoreFile] = useState<File | null>(null);
  const [backupMetaPreview, setBackupMetaPreview] = useState<BackupMeta | null>(null);
  const [postRestoreCheck, setPostRestoreCheck] = useState<PostRestoreCheck | null>(null);
  const [backupSettings, setBackupSettings] = useState<BackupScheduleSettings>(defaultBackupScheduleSettings());
  const [backupSchedulePassphrase, setBackupSchedulePassphrase] = useState('');
  const [backupFTPPass, setBackupFTPPass] = useState('');
  const [backupArchives, setBackupArchives] = useState<BackupArchive[]>([]);
  const [backupStats, setBackupStats] = useState<BackupStats>({ totalArchives: 0, localArchives: 0, ftpArchives: 0 });
  const [backupTab, setBackupTab] = useState<BackupTab>('general');
  const [timeSyncStatus, setTimeSyncStatus] = useState<TimeSyncStatus | null>(null);
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>('general');
  const [publicStyleProfile, setPublicStyleProfile] = useState<StyleProfile>('monolith');
  const [publicStyleCustom, setPublicStyleCustom] = useState('');
  const [settingsMessage, setSettingsMessage] = useState('');
  const [sshRoutes, setSshRoutes] = useState<SSHBastionRoute[]>([]);
  const [sshKeys, setSshKeys] = useState<SSHBastionKey[]>([]);
  const [sshSelectedHostFQDN, setSshSelectedHostFQDN] = useState('');
  const [sshRouteFQDN, setSshRouteFQDN] = useState('');
  const [sshRouteTargetHost, setSshRouteTargetHost] = useState('');
  const [sshRouteTargetPort, setSshRouteTargetPort] = useState('22');
  const [sshRouteEnabled, setSshRouteEnabled] = useState(true);
  const [sshKeyName, setSshKeyName] = useState('');
  const [sshKeyPublic, setSshKeyPublic] = useState('');
  const [sshKeyRouteIDs, setSshKeyRouteIDs] = useState<number[]>([]);
  const [sshGeneratedPrivateKey, setSshGeneratedPrivateKey] = useState('');
  const [sshGeneratedPublicKey, setSshGeneratedPublicKey] = useState('');
  const [sshGeneratedKeyName, setSshGeneratedKeyName] = useState('');
  const [sshGeneratedPPK, setSshGeneratedPPK] = useState('');
  const [sshGeneratedRFC4716, setSshGeneratedRFC4716] = useState('');
  const [sshGeneratedPPKError, setSshGeneratedPPKError] = useState('');
  const [newUserName, setNewUserName] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState<'admin' | 'domain-admin' | 'read-only'>('domain-admin');
  const [newUserDomainIDs, setNewUserDomainIDs] = useState<number[]>([]);
  const [newUserAllowedCIDRs, setNewUserAllowedCIDRs] = useState('');
  const [newUserIPCheckDisabled, setNewUserIPCheckDisabled] = useState(false);
  const [showCreateUserDialog, setShowCreateUserDialog] = useState(false);
  const [editUserID, setEditUserID] = useState<number | null>(null);
  const [editUserRole, setEditUserRole] = useState<'admin' | 'domain-admin' | 'read-only'>('domain-admin');
  const [editUserDomainIDs, setEditUserDomainIDs] = useState<number[]>([]);
  const [editUserPassword, setEditUserPassword] = useState('');
  const [editUserAllowedCIDRs, setEditUserAllowedCIDRs] = useState('');
  const [editUserIPCheckDisabled, setEditUserIPCheckDisabled] = useState(false);
  const [usersRoleFilter, setUsersRoleFilter] = useState<'all' | 'admin' | 'domain-admin' | 'read-only'>('all');
  const [usersQuery, setUsersQuery] = useState('');
  const [selfNotifyEmail, setSelfNotifyEmail] = useState('');
  const [selfCurrentPassword, setSelfCurrentPassword] = useState('');
  const [selfNewPassword, setSelfNewPassword] = useState('');
  const [selfConfirmPassword, setSelfConfirmPassword] = useState('');
  const [deleteHostDialogOpen, setDeleteHostDialogOpen] = useState(false);
  const [deleteHostID, setDeleteHostID] = useState<number | null>(null);
  const [deleteHostLabel, setDeleteHostLabel] = useState('');
  const [deleteHostConfirmText, setDeleteHostConfirmText] = useState('');

  const csrf = useMemo(() => getCookie('domnex_csrf'), [identity, loading]);

  const loadPublicStyle = async () => {
    try {
      const s = await api<PublicStyle>('/api/v1/style');
      setPublicStyleProfile((s.styleProfile as StyleProfile) || 'monolith');
      setPublicStyleCustom(s.styleCustom || '');
    } catch {
      setPublicStyleProfile('monolith');
      setPublicStyleCustom('');
    }
  };

  const loadSetupStatus = async (): Promise<SetupStatus | null> => {
    try {
      const st = await api<SetupStatus>('/api/v1/setup/status');
      setSetupStatus(st);
      if (st && !st.initialized) {
        setSetupStep(1);
        return st;
      }
      return st;
    } catch {
      return null;
    }
  };

  const refresh = async () => {
    setLoading(true);
    setError('');
    try {
      const st = await loadSetupStatus();
      if (st && !st.initialized) {
        setIdentity(null);
        setDomains([]);
        setHosts([]);
        setAudit([]);
        setSelfNotifyEmail('');
        return;
      }
      await api('/api/v1/csrf');
      const me = await api<{ identity: Identity }>('/api/v1/me');
      setIdentity(me.identity);
      try {
        const profile = await api<MeProfile>('/api/v1/me/profile');
        setSelfNotifyEmail((profile.email || '').trim());
        let normalizedLayout = normalizeDashboardLayout(profile.dashboardLayout);
        const needsSystemDefaults = !profile.dashboardLayout || isLegacyOverviewLayout(normalizedLayout);
        if (needsSystemDefaults) {
          normalizedLayout = defaultDashboardLayout();
          try {
            await api('/api/v1/me/profile', {
              method: 'POST',
              headers: { 'X-CSRF-Token': csrf },
              body: JSON.stringify({ dashboardLayout: normalizedLayout }),
            });
          } catch {
            // Keep runtime defaults even if persistence fails in this request.
          }
        }
        setDashboardLayout(normalizedLayout);
        setDashboardDraft(normalizedLayout);
        if (!normalizedLayout.tabs.some((t) => t.id === dashboardTabID)) {
          setDashboardTabID(normalizedLayout.tabs[0]?.id || 'minimal');
        }
      } catch {
        setSelfNotifyEmail('');
        const def = defaultDashboardLayout();
        setDashboardLayout(def);
        setDashboardDraft(def);
        setDashboardTabID(def.tabs[0]?.id || 'minimal');
      }
      setSetupStatus(st && st.initialized ? st : null);
      const [d, h, a] = await Promise.all([
        api<{ items: Domain[] }>('/api/v1/domains'),
        api<{ items: Host[] }>('/api/v1/hosts'),
        api<{ items: Audit[] }>('/api/v1/audit?limit=5000'),
      ]);
      setDomains(d.items || []);
      setHosts(h.items || []);
      setAudit(a.items || []);
      try {
        const bl = await api<{ items: BlockedIP[] }>('/api/v1/security/ip-blocks');
        setBlockedIPs(bl.items || []);
      } catch {
        setBlockedIPs([]);
      }
      try {
        const hd = await api<{ items: HostDiagnostic[] }>('/api/v1/hosts/diagnostics');
        const byFqdn: Record<string, HostDiagnostic> = {};
        (hd.items || []).forEach((it) => { byFqdn[it.fqdn] = it; });
        setHostDiagnostics(byFqdn);
      } catch {
        setHostDiagnostics({});
      }
      try {
        const t = await api<{ items: APIToken[] }>('/api/v1/tokens');
        setTokens(t.items || []);
      } catch {
        setTokens([]);
      }
      try {
        const u = await api<{ items: ManagedUser[] }>('/api/v1/users');
        setUsers(u.items || []);
      } catch {
        setUsers([]);
      }
      try {
        const sr = await api<{ items: SSHBastionRoute[] }>('/api/v1/ssh/routes');
        setSshRoutes(sr.items || []);
      } catch {
        // Keep current list on transient errors so UI does not flicker to empty.
      }
      try {
        const sk = await api<{ items: SSHBastionKey[] }>('/api/v1/ssh/keys');
        setSshKeys(sk.items || []);
      } catch {
        // Keep current list on transient errors so UI does not flicker to empty.
      }
      try {
        const s = await api<RuntimeSettings>('/api/v1/settings');
        setSettings(s);
        setSettingsAcmeEmail(s.acmeEmail || '');
        setSettingsAcmeStaging(!!s.acmeStaging);
        setSettingsPublicIPv4(s.publicIpv4 || '');
        setSettingsBaseDomain(s.baseDomain || '');
        setSettingsStyleProfile((s.styleProfile as StyleProfile) || 'monolith');
        setSettingsStyleCustom(s.styleCustom || '');
        setSettingsTimeSyncMode((s.timeSyncMode as 'system_only' | 'external_public' | 'external_lan') || 'system_only');
        setSettingsTimeSyncLAN((s.timeSyncLANServers || []).join(', '));
        setSettingsLogServers(s.logServers || defaultLogServers());
        setSettingsRetention(s.retention || defaultRetentionPolicy());
      } catch {
        setSettings(null);
        setSettingsPublicIPv4('');
        setSettingsBaseDomain('');
        setSettingsStyleProfile('monolith');
        setSettingsStyleCustom('');
        setSettingsTimeSyncMode('system_only');
        setSettingsTimeSyncLAN('');
        setSettingsLogServers(defaultLogServers());
        setSettingsRetention(defaultRetentionPolicy());
      }
      try {
        const b = await api<BackupScheduleSettings>('/api/v1/backup/settings');
        setBackupSettings(b || defaultBackupScheduleSettings());
      } catch {
        setBackupSettings(defaultBackupScheduleSettings());
      }
      try {
        const ba = await api<{ items: BackupArchive[]; stats: BackupStats }>('/api/v1/backup/archives?limit=500');
        setBackupArchives(ba.items || []);
        setBackupStats(ba.stats || { totalArchives: 0, localArchives: 0, ftpArchives: 0 });
      } catch {
        setBackupArchives([]);
        setBackupStats({ totalArchives: 0, localArchives: 0, ftpArchives: 0 });
      }
      try {
        const ts = await api<TimeSyncStatus>('/api/v1/time-sync');
        setTimeSyncStatus(ts);
      } catch {
        setTimeSyncStatus(null);
      }
      try {
        const sh = await api<SystemHealth>('/api/v1/system/health');
        setSystemHealth(sh);
      } catch {
        setSystemHealth(null);
      }
      try {
        const t = await api<TrafficOverview>('/api/v1/traffic/overview?hours=24');
        setTrafficOverview(t);
      } catch {
        setTrafficOverview(null);
      }
      try {
        const cfg = await api<ThreatIntelConfig>('/api/v1/threat-intel/config');
        setTiConfig({
          enabled: !!cfg.enabled,
          mode: (cfg.mode || 'monitor_only') as 'monitor_only' | 'auto_mode',
          syncHours: Number(cfg.syncHours || 24),
          eventMinHits: Number(cfg.eventMinHits || 2),
          offenderMinHits: Number(cfg.offenderMinHits || 10),
          monitorMaxLevel: Number(cfg.monitorMaxLevel || 2),
          softMinLevel: Number(cfg.softMinLevel || 3),
          hardLevel: Number(cfg.hardLevel || 6),
          softBlockMinutes: Number(cfg.softBlockMinutes || 15),
        });
      } catch {
        // Keep previous threat intel config on transient failures.
      }
    } catch (e) {
      const err = e as Error & { status?: number };
      if (err.status === 503 && /setup required/i.test(err.message)) {
        setIdentity(null);
        await loadSetupStatus();
        return;
      }
      if (err.status === 401 || /unauthorized/i.test(err.message)) {
        setIdentity(null);
        setDomains([]);
        setHosts([]);
        setAudit([]);
        setTrafficOverview(null);
        setSystemHealth(null);
        setSelectedHostTraffic(null);
        setSshRoutes([]);
        setSshKeys([]);
        void loadPublicStyle();
      } else {
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  const refreshAuditOnly = async () => {
    try {
      const out = await api<{ items: Audit[] }>('/api/v1/audit?limit=5000');
      setAudit(out.items || []);
    } catch {
      // Keep existing audit list on transient failures.
    }
  };

  const loadTimeSyncStatus = async () => {
    try {
      const out = await api<TimeSyncStatus>('/api/v1/time-sync');
      setTimeSyncStatus(out);
    } catch {
      setTimeSyncStatus(null);
    }
  };

  const loadSystemHealth = async () => {
    try {
      const out = await api<SystemHealth>('/api/v1/system/health');
      setSystemHealth(out);
    } catch {
      setSystemHealth(null);
    }
  };

  const loadThreatIntel = async () => {
    try {
      const [cfg, feeds, allow, blockedSummary] = await Promise.all([
        api<ThreatIntelConfig>('/api/v1/threat-intel/config'),
        api<{ items: ThreatIntelFeed[] }>('/api/v1/threat-intel/feeds'),
        api<{ items: BlockedIP[] }>('/api/v1/threat-intel/allowlist'),
        api<ThreatIntelBlockedPage>(`/api/v1/threat-intel/blocked?hours=${encodeURIComponent(String(tiHours))}&q=&page=1&pageSize=1`),
      ]);
      setTiConfig({
        enabled: !!cfg.enabled,
        mode: (cfg.mode || 'monitor_only') as 'monitor_only' | 'auto_mode',
        syncHours: Number(cfg.syncHours || 24),
        eventMinHits: Number(cfg.eventMinHits || 2),
        offenderMinHits: Number(cfg.offenderMinHits || 10),
        monitorMaxLevel: Number(cfg.monitorMaxLevel || 2),
        softMinLevel: Number(cfg.softMinLevel || 3),
        hardLevel: Number(cfg.hardLevel || 6),
        softBlockMinutes: Number(cfg.softBlockMinutes || 15),
      });
      setTiFeeds(feeds.items || []);
      setTiAllowlist(allow.items || []);
      setTiTotalBlocked(Number(blockedSummary.total || 0));
      if (tiView === 'events') {
        const matchesPage = await api<ThreatIntelMatchesPage>(`/api/v1/threat-intel/matches?hours=${encodeURIComponent(String(tiHours))}&decision=${encodeURIComponent(tiDecision)}&q=${encodeURIComponent(tiQuery)}&page=${encodeURIComponent(String(tiPage))}&pageSize=${encodeURIComponent(String(tiPageSize))}`);
        setTiMatches(matchesPage.items || []);
        setTiTotalMatches(Number(matchesPage.total || 0));
      } else {
        const offendersPage = await api<ThreatIntelOffendersPage>(`/api/v1/threat-intel/offenders?hours=${encodeURIComponent(String(tiHours))}&page=${encodeURIComponent(String(tiPage))}&pageSize=${encodeURIComponent(String(tiPageSize))}`);
        setTiOffenders(offendersPage.items || []);
        setTiTotalOffenders(Number(offendersPage.total || 0));
      }
      if (tiBlockedOpen) {
        const blockedPage = await api<ThreatIntelBlockedPage>(`/api/v1/threat-intel/blocked?hours=${encodeURIComponent(String(tiHours))}&q=${encodeURIComponent(tiQuery)}&page=1&pageSize=500`);
        setTiBlocked(blockedPage.items || []);
        setTiTotalBlocked(Number(blockedPage.total || 0));
      }
    } catch {
      // Keep previous data on transient failures.
    }
  };

  useEffect(() => {
    void loadPublicStyle();
    void refresh();
  }, []);

  useEffect(() => {
    if (domains.length === 0) {
      setHostDomain('');
      return;
    }
    if (!hostDomain || !domains.some((d) => d.name === hostDomain)) {
      setHostDomain(domains[0].name);
    }
  }, [domains, hostDomain]);

  useEffect(() => {
    if (tab !== 'domains' || domainWizardStep !== 3 || !domainName) return;
    void checkDomainPreflight();
    const t = window.setInterval(() => { void checkDomainPreflight(); }, 4000);
    return () => window.clearInterval(t);
  }, [tab, domainWizardStep, domainName, domainProvider, domainZoneID]);

  useEffect(() => {
    if (tab !== 'hosts' || hostWizardStep !== 2 || !hostDomain || !hostSub || (!hostHAEnabled && !hostSSHBastion && !hostUpstream)) return;
    void checkHostPreflight();
    const t = window.setInterval(() => { void checkHostPreflight(); }, 4000);
    return () => window.clearInterval(t);
  }, [tab, hostWizardStep, hostDomain, hostSub, hostUpstream, hostInsecureTLS, hostHAEnabled, hostHAMode, hostHABackends, hostSSHBastion]);

  useEffect(() => {
    if (!selectedHostID) {
      setSelectedHostTraffic(null);
      return;
    }
    void loadHostTraffic(selectedHostID);
  }, [selectedHostID]);

  useEffect(() => {
    if (tab !== 'metricCenter') return;
    void loadMetricCenter();
  }, [tab, metricHostFilter, metricHours, metricClass, hosts]);

  useEffect(() => {
    if (tab !== 'audit') return;
    void refreshAuditOnly();
    const t = window.setInterval(() => { void refreshAuditOnly(); }, 5000);
    return () => window.clearInterval(t);
  }, [tab]);

  useEffect(() => {
    if (tab !== 'threatIntel') return;
    void loadThreatIntel();
    const t = window.setInterval(() => { void loadThreatIntel(); }, 8000);
    return () => window.clearInterval(t);
  }, [tab, tiHours, tiDecision, tiQuery, tiPage, tiPageSize, tiView, tiBlockedOpen]);

  useEffect(() => {
    if (identity?.role !== 'admin') return;
    if (tab !== 'settings' && tab !== 'dashboard') return;
    void loadTimeSyncStatus();
    const t = window.setInterval(() => { void loadTimeSyncStatus(); }, 20000);
    return () => window.clearInterval(t);
  }, [tab, identity?.role]);

  useEffect(() => {
    if (!identity) return;
    if (tab !== 'dashboard') return;
    void loadSystemHealth();
    const t = window.setInterval(() => { void loadSystemHealth(); }, 15000);
    return () => window.clearInterval(t);
  }, [tab, identity?.role]);

  useEffect(() => {
    setTiPage(1);
  }, [tiHours, tiDecision, tiQuery, tiView, tiPageSize]);

  const login = async () => {
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/login', {
        method: 'POST',
        body: JSON.stringify({ username: loginUser, password: loginPass }),
      });
      setLoginPass('');
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const setupUnlock = async () => {
    setLoading(true);
    setError('');
    try {
      const st = await api<SetupStatus>('/api/v1/setup/unlock', {
        method: 'POST',
        body: JSON.stringify({ ots: setupOTS }),
      });
      setSetupStatus(st);
      setSetupStep(setupMode === 'restore' ? 2 : 3);
      setSetupOTS('');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const setupUploadBackup = async () => {
    if (!setupBackupFile) {
      setError('Select a backup package first.');
      return;
    }
    if (setupBackupPassphrase.trim().length < 12) {
      setError('Backup passphrase must be at least 12 characters.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const fd = new FormData();
      fd.append('backup', setupBackupFile);
      fd.append('passphrase', setupBackupPassphrase.trim());
      const meta = await apiMultipart<SetupBackupMeta>('/api/v1/setup/restore/upload', fd);
      setSetupBackupMeta(meta);
      setSetupStatus((p) => p ? ({ ...p, restoreReady: true }) : p);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const createEncryptedBackup = async () => {
    if (backupPassphrase.trim().length < 12) {
      setError('Backup passphrase must be at least 12 characters.');
      return;
    }
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      const res = await fetch('/api/v1/backup/create', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf,
        },
        body: JSON.stringify({ passphrase: backupPassphrase.trim() }),
      });
      if (!res.ok) {
        const txt = await res.text();
        const data = txt ? JSON.parse(txt) : {};
        throw new Error(data.error || `${res.status} ${res.statusText}`);
      }
      const blob = await res.blob();
      const cd = res.headers.get('Content-Disposition') || '';
      const m = /filename=\"?([^\";]+)\"?/.exec(cd);
      const fileName = m?.[1] || `domnex-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.dnxbak`;
      downloadBinaryFile(fileName, blob);
      setSettingsMessage('Encrypted backup package created and downloaded.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const analyzeBackupFile = async () => {
    if (!backupRestoreFile) {
      setError('Select a backup package first.');
      return;
    }
    if (backupRestorePassphrase.trim().length < 12) {
      setError('Backup passphrase must be at least 12 characters.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const fd = new FormData();
      fd.append('backup', backupRestoreFile);
      fd.append('passphrase', backupRestorePassphrase.trim());
      const meta = await apiMultipart<BackupMeta>('/api/v1/backup/analyze', fd, csrf);
      setBackupMetaPreview(meta);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const restoreEncryptedBackup = async () => {
    if (!backupRestoreFile) {
      setError('Select a backup package first.');
      return;
    }
    if (backupRestorePassphrase.trim().length < 12) {
      setError('Backup passphrase must be at least 12 characters.');
      return;
    }
    if (backupRestoreConfirm.trim() !== 'RESTORE') {
      setError('Type RESTORE exactly to confirm restore apply.');
      return;
    }
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      const fd = new FormData();
      fd.append('backup', backupRestoreFile);
      fd.append('passphrase', backupRestorePassphrase.trim());
      fd.append('confirm', backupRestoreConfirm.trim());
      const out = await apiMultipart<{ ok: boolean; postCheck?: PostRestoreCheck; postCheckError?: string }>('/api/v1/backup/restore', fd, csrf);
      if (out.postCheck) {
        setPostRestoreCheck(out.postCheck);
      }
      if (out.postCheckError) {
        setSettingsMessage(`Backup restore applied. Post-restore check failed: ${out.postCheckError}`);
      } else {
        setSettingsMessage('Backup restore applied with post-restore check. For clean runtime transition, use Reload Service now.');
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const saveBackupSchedule = async () => {
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      await api('/api/v1/backup/settings', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          enabled: !!backupSettings.enabled,
          intervalHours: Number(backupSettings.intervalHours || 24),
          retentionCount: Number(backupSettings.retentionCount || 10),
          passphrase: backupSchedulePassphrase,
          local: {
            enabled: !!backupSettings.local.enabled,
            dir: backupSettings.local.dir || '/var/lib/domnexdomain/backups',
          },
          ftp: {
            enabled: !!backupSettings.ftp.enabled,
            host: backupSettings.ftp.host || '',
            port: Number(backupSettings.ftp.port || 21),
            username: backupSettings.ftp.username || '',
            remoteDir: backupSettings.ftp.remoteDir || '/',
            tlsMode: backupSettings.ftp.tlsMode || 'explicit',
          },
          ftpPassword: backupFTPPass,
        }),
      });
      setBackupSchedulePassphrase('');
      setBackupFTPPass('');
      const b = await api<BackupScheduleSettings>('/api/v1/backup/settings');
      setBackupSettings(b || defaultBackupScheduleSettings());
      const ba = await api<{ items: BackupArchive[]; stats: BackupStats }>('/api/v1/backup/archives?limit=500');
      setBackupArchives(ba.items || []);
      setBackupStats(ba.stats || { totalArchives: 0, localArchives: 0, ftpArchives: 0 });
      setSettingsMessage('Backup schedule saved.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const runPostRestoreCheck = async () => {
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      const out = await api<PostRestoreCheck>('/api/v1/backup/post-restore-check', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: '{}',
      });
      setPostRestoreCheck(out);
      setSettingsMessage('Post-restore check completed.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const refreshBackupArchives = async () => {
    const ba = await api<{ items: BackupArchive[]; stats: BackupStats }>('/api/v1/backup/archives?limit=500');
    setBackupArchives(ba.items || []);
    setBackupStats(ba.stats || { totalArchives: 0, localArchives: 0, ftpArchives: 0 });
  };

  const runScheduledBackupNow = async () => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      await api('/api/v1/backup/schedule/run', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: '{}',
      });
      const [cfg, ba] = await Promise.all([
        api<BackupScheduleSettings>('/api/v1/backup/settings'),
        api<{ items: BackupArchive[]; stats: BackupStats }>('/api/v1/backup/archives?limit=500'),
      ]);
      setBackupSettings(cfg || defaultBackupScheduleSettings());
      setBackupArchives(ba.items || []);
      setBackupStats(ba.stats || { totalArchives: 0, localArchives: 0, ftpArchives: 0 });
      setSettingsMessage('Scheduled backup created.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const restoreBackupArchive = async (id: number) => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      const out = await api<{ ok: boolean; postCheck?: PostRestoreCheck }>('/api/v1/backup/archives/' + id + '/restore', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ confirm: 'RESTORE' }),
      });
      if (out.postCheck) setPostRestoreCheck(out.postCheck);
      await refreshBackupArchives();
      setSettingsMessage('Archive restore applied. Run Reload Service after validation.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteBackupArchive = async (id: number) => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/backup/archives/' + id, {
        method: 'DELETE',
        headers: { 'X-CSRF-Token': csrf },
      });
      await refreshBackupArchives();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const applySetup = async () => {
    if (!setupAdminUser.trim() || setupAdminPass.length < 10 || setupAdminPass !== setupAdminPass2) {
      setError('Please provide valid admin credentials (min 10 chars, matching confirmation).');
      return;
    }
    if (setupMode === 'fresh' && !setupDomainName.trim()) {
      setError('First domain is required for fresh setup.');
      return;
    }
    if (setupMode === 'restore' && !setupBackupMeta) {
      setError('Analyze a backup package first.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/setup/apply', {
        method: 'POST',
        body: JSON.stringify({
          mode: setupMode,
          adminUsername: setupAdminUser.trim().toLowerCase(),
          adminPassword: setupAdminPass,
          acmeEmail: settingsAcmeEmail,
          acmeStaging: settingsAcmeStaging,
          cfToken: '',
          publicIpv4: settingsPublicIPv4,
          baseDomain: setupMode === 'fresh' ? setupDomainName.trim().toLowerCase() : settingsBaseDomain,
          timeSyncMode: settingsTimeSyncMode,
          timeSyncLanServers: settingsTimeSyncLAN,
          logServers: settingsLogServers,
          logHttpBearer: settingsLogHTTPBearer,
          retention: settingsRetention,
          domainName: setupMode === 'fresh' ? setupDomainName.trim().toLowerCase() : '',
          domainDnsMode: setupMode === 'fresh' ? setupDomainDNSMode : '',
          domainCertMode: setupMode === 'fresh' ? setupDomainCertMode : '',
          domainProvider: setupMode === 'fresh' ? setupDomainDNSMode : '',
          domainZoneId: setupMode === 'fresh' ? setupDomainZoneID.trim() : '',
          firstSubdomain: setupMode === 'fresh' ? setupFirstSub.trim().toLowerCase() : '',
          firstUpstream: setupMode === 'fresh' ? setupFirstUpstream.trim() : '',
          firstInsecureTls: false,
          backupMeta: setupBackupMeta || undefined,
        }),
      });
      setSetupStatus(null);
      setSetupStep(1);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/logout', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
      });
      setIdentity(null);
      setDomains([]);
      setHosts([]);
      setHostDiagnostics({});
      setAudit([]);
      setTokens([]);
      setUsers([]);
      setSshRoutes([]);
      setSshKeys([]);
      setDomainChecks({});
      setSettings(null);
      setSettingsPublicIPv4('');
      setSettingsBaseDomain('');
      setSettingsStyleProfile('monolith');
      setSettingsStyleCustom('');
      setSettingsTimeSyncMode('system_only');
      setSettingsTimeSyncLAN('');
      setSettingsRetention(defaultRetentionPolicy());
      setBackupSettings(defaultBackupScheduleSettings());
      setBackupPassphrase('');
      setBackupRestorePassphrase('');
      setSelfNotifyEmail('');
      setSelfCurrentPassword('');
      setSelfNewPassword('');
      setSelfConfirmPassword('');
      const def = defaultDashboardLayout();
      setDashboardLayout(def);
      setDashboardDraft(def);
      setDashboardTabID(def.tabs[0]?.id || 'minimal');
      setDashboardEditMode(false);
      setBackupRestoreConfirm('');
      setBackupRestoreFile(null);
      setBackupMetaPreview(null);
      setPostRestoreCheck(null);
      setBackupSchedulePassphrase('');
      setBackupFTPPass('');
      setBackupArchives([]);
      setBackupStats({ totalArchives: 0, localArchives: 0, ftpArchives: 0 });
      setBackupTab('general');
      setTimeSyncStatus(null);
      setSystemHealth(null);
      void loadPublicStyle();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const saveDomain = async () => {
    if (!domainName) return;
    setLoading(true);
    setError('');
    try {
      const provider = domainProvider === 'strato' ? 'manual' : domainProvider;
      const dnsMode = domainProvider === 'cloudflare' ? 'cloudflare' : 'manual';
      await api('/api/v1/domains', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ name: domainName, dnsMode, certMode: 'letsencrypt', provider, zoneId: domainZoneID }),
      });
      setDomainName('');
      setDomainZoneID('');
      setDomainWizardStep(1);
      setDomainPreflight(null);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const addHost = async () => {
    if (!hostDomain || !hostSub || (!hostHAEnabled && !hostSSHBastion && !hostUpstream)) return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/hosts', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          domain: hostDomain,
          subdomain: hostSub,
          upstream: hostEffectiveUpstream,
          insecureTls: hostInsecureTLS,
          haEnabled: hostHAEnabled,
          haMode: hostHAMode,
          haBackends: normalizeBackends(hostHABackends),
        }),
      });
      if (hostSSHBastion || hostEffectiveUpstream.trim().toLowerCase() === SSH_BASTION_DEFAULT_UPSTREAM) {
        try {
          await api('/api/v1/ssh/routes', {
            method: 'POST',
            headers: { 'X-CSRF-Token': csrf },
            body: JSON.stringify({
              fqdn: `${hostSub}.${hostDomain}`.toLowerCase(),
              targetHost: SSH_BASTION_DEFAULT_TARGET_HOST,
              targetPort: SSH_BASTION_DEFAULT_TARGET_PORT,
              enabled: true,
            }),
          });
        } catch (routeErr) {
          setError(`Subdomain created, but SSH bastion route setup failed: ${(routeErr as Error).message}`);
        }
      }
      setHostSub('');
      setHostHAEnabled(false);
      setHostSSHBastion(false);
      setHostHAMode('failover');
      setHostHABackends([{ name: 'server1', url: '' }, { name: 'server2', url: '' }]);
      setHostInsecureTLS(false);
      setHostWizardStep(1);
      setHostPreflight(null);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const checkDomainPreflight = async () => {
    if (!domainName) {
      setDomainPreflight(null);
      return;
    }
    try {
      setDomainPreflightRunning(true);
      const provider = domainProvider === 'strato' ? 'manual' : domainProvider;
      const dnsMode = domainProvider === 'cloudflare' ? 'cloudflare' : 'manual';
      const out = await api<DomainPreflight>('/api/v1/domains/preflight', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ name: domainName, dnsMode, provider, zoneId: domainZoneID }),
      });
      setDomainPreflight(out);
    } catch (e) {
      setDomainPreflight(null);
      setError((e as Error).message);
    } finally {
      setDomainPreflightRunning(false);
    }
  };

  const checkHostPreflight = async () => {
    if (!hostDomain || !hostSub || (!hostHAEnabled && !hostSSHBastion && !hostUpstream)) {
      setHostPreflight(null);
      return;
    }
    try {
      setHostPreflightRunning(true);
      const out = await api<HostPreflight>('/api/v1/hosts/preflight', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          domain: hostDomain,
          subdomain: hostSub,
          upstream: hostEffectiveUpstream,
          insecureTls: hostInsecureTLS,
          haEnabled: hostHAEnabled,
          haMode: hostHAMode,
          haBackends: normalizeBackends(hostHABackends),
        }),
      });
      setHostPreflight(out);
    } catch (e) {
      setHostPreflight(null);
      setError((e as Error).message);
    } finally {
      setHostPreflightRunning(false);
    }
  };

  const retryHost = async (id: number) => {
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/hosts/${id}/retry`, { method: 'POST', headers: { 'X-CSRF-Token': csrf } });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const openHostDetail = (h: Host) => {
    setSelectedHostID(h.id);
    setDetailUpstream(h.upstreamUrl || '');
    setDetailInsecureTLS(!!h.insecureTls);
    setDetailHAEnabled(!!h.haEnabled);
    setDetailHAMode((h.haMode === 'round_robin' ? 'round_robin' : 'failover'));
    setDetailHABackends((h.haBackends && h.haBackends.length > 0) ? h.haBackends : [{ name: 'server1', url: '' }, { name: 'server2', url: '' }]);
    setDetailAuthEnabled(!!h.authEnabled);
    setDetailAuthUser(h.authUser || '');
    setDetailAuthPass('');
    setDetailGeoMode((h.geoMode === 'allow' || h.geoMode === 'deny') ? h.geoMode : 'off');
    setDetailGeoCountries((h.geoCountries || []).join(', '));
    void loadHostTraffic(h.id);
  };

  const saveHostGeneral = async () => {
    if (!selectedHostID) return;
    setDetailSavingGeneral(true);
    setError('');
    try {
      await api(`/api/v1/hosts/${selectedHostID}`, {
        method: 'PUT',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          upstream: detailUpstream,
          insecureTls: detailInsecureTLS,
          haEnabled: detailHAEnabled,
          haMode: detailHAMode,
          haBackends: normalizeBackends(detailHABackends),
        }),
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDetailSavingGeneral(false);
    }
  };

  const saveHostAuth = async () => {
    if (!selectedHostID) return;
    setError('');
    setDetailSavingAuth(true);
    try {
      await api(`/api/v1/hosts/${selectedHostID}/auth`, {
        method: 'PUT',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          enabled: detailAuthEnabled,
          username: detailAuthUser.trim(),
          password: detailAuthPass,
        }),
      });
      setDetailAuthPass('');
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDetailSavingAuth(false);
    }
  };

  const saveHostGeo = async () => {
    if (!selectedHostID) return;
    setError('');
    setDetailSavingGeo(true);
    try {
      await api(`/api/v1/hosts/${selectedHostID}/geo`, {
        method: 'PUT',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          mode: detailGeoMode,
          countries: parseCountryCodes(detailGeoCountries),
        }),
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDetailSavingGeo(false);
    }
  };

  const loadHostTraffic = async (hostID: number) => {
    try {
      const out = await api<HostTrafficDetails>(`/api/v1/traffic/hosts/${hostID}?hours=24`);
      setSelectedHostTraffic(out);
    } catch {
      setSelectedHostTraffic(null);
    }
  };

  const loadMetricCenter = async () => {
    try {
      const hostIdPart = metricHostFilter !== 'all' ? `&hostId=${encodeURIComponent(metricHostFilter)}` : '';
      const classPart = `&class=${encodeURIComponent(metricClass)}`;
      const out = await api<TrafficCountryOverview>(`/api/v1/traffic/countries?hours=${metricHours}${hostIdPart}${classPart}`);
      setMetricCountryOverview(out);
    } catch {
      setMetricCountryOverview(null);
    }
  };

  const loadThreatGeoMap = async () => {
    try {
      const out = await api<{ generatedAt: string; items: ThreatGeoPoint[] }>('/api/v1/threat-intel/geo');
      setMetricThreatGeo(Array.isArray(out.items) ? out.items : []);
      setMetricThreatGeoAt(String(out.generatedAt || ''));
    } catch {
      setMetricThreatGeo([]);
      setMetricThreatGeoAt('');
    }
  };

  useEffect(() => {
    if (!identity || !metricMapOpen || metricMapMode !== 'live') {
      setMetricLiveConnected(false);
      return;
    }
    const ttlMs = 10_000;
    const maxPoints = 3000;
    const es = new EventSource('/api/v1/traffic/live');
    setMetricLiveConnected(false);
    es.onopen = () => setMetricLiveConnected(true);
    es.onerror = () => setMetricLiveConnected(false);
    es.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data || '{}') as TrafficLiveEvent;
        const cc = String(ev.country || '').trim().toUpperCase();
        if (!cc || !COUNTRY_LONLAT[cc]) return;
        if (metricHostFilter !== 'all' && Number(metricHostFilter) !== Number(ev.hostId || 0)) return;
        const cls = (ev.class === 'crawler' || ev.class === 'unknown') ? ev.class : 'human';
        if (metricClass !== 'all' && cls !== metricClass) return;
        if (metricCountryFocus !== 'all' && cc !== metricCountryFocus.toUpperCase()) return;
        if (String(ev.sourceType || '').toLowerCase() === 'internal') return;
        const seenAt = Date.now();
        const p: LiveTracePoint = {
          id: `${seenAt}-${Math.random().toString(16).slice(2, 8)}`,
          seenAt,
          country: cc,
          hostId: Number(ev.hostId || 0),
          fqdn: String(ev.fqdn || ''),
          scanner: !!ev.scanner || cls === 'crawler',
          class: cls,
        };
        setMetricLivePoints((prev) => {
          const cut = seenAt - ttlMs;
          const next = [...prev.filter((it) => it.seenAt >= cut), p];
          if (next.length <= maxPoints) return next;
          return next.slice(next.length - maxPoints);
        });
      } catch {
      }
    };
    const gc = window.setInterval(() => {
      const cut = Date.now() - ttlMs;
      setMetricLivePoints((prev) => prev.filter((it) => it.seenAt >= cut));
    }, 500);
    return () => {
      window.clearInterval(gc);
      es.close();
      setMetricLiveConnected(false);
      setMetricLivePoints([]);
    };
  }, [identity, metricMapOpen, metricMapMode, metricHostFilter, metricClass, metricCountryFocus]);

  useEffect(() => {
    if (!identity || !metricMapOpen || metricMapMode !== 'threat') return;
    void loadThreatGeoMap();
    const timer = window.setInterval(() => {
      void loadThreatGeoMap();
    }, 10000);
    return () => window.clearInterval(timer);
  }, [identity, metricMapOpen, metricMapMode]);

  const activeHosts = hosts.filter((h) => h.state === 'active').length;
  const errorHosts = hosts.filter((h) => h.state === 'error').length;
  const diagnostics = Object.values(hostDiagnostics);
  const hostStateByFQDN = useMemo(() => {
    const out: Record<string, string> = {};
    hosts.forEach((h) => { out[h.fqdn] = (h.state || '').toLowerCase(); });
    return out;
  }, [hosts]);
  const diagnosticsForHealth = diagnostics.filter((d) => {
    const st = hostStateByFQDN[d.fqdn];
    return st !== 'maintenance' && st !== 'disabled';
  });
  const monitoredHosts = diagnosticsForHealth.length;
  const safeBase = monitoredHosts > 0 ? monitoredHosts : 1;
  const dnsHealthy = diagnosticsForHealth.filter((d) => (d.dnsRecords || []).length > 0).length;
  const tlsHealthy = diagnosticsForHealth.filter((d) => d.tlsOk).length;
  const httpHealthy = diagnosticsForHealth.filter((d) => d.httpStatus >= 200 && d.httpStatus < 400).length;
  const httpsHealthy = diagnosticsForHealth.filter((d) => d.httpsStatus >= 200 && d.httpsStatus < 500).length;
  const certKnown = diagnosticsForHealth.filter((d) => d.certDaysLeft > 0);
  const certExpiringSoon = certKnown.filter((d) => d.certDaysLeft <= 14).length;
  const avgCertDays = certKnown.length > 0
    ? Math.round(certKnown.reduce((sum, d) => sum + d.certDaysLeft, 0) / certKnown.length)
    : 0;
  const avgHTTPSStatus = diagnosticsForHealth.filter((d) => d.httpsStatus > 0).length > 0
    ? Math.round(
      diagnosticsForHealth.filter((d) => d.httpsStatus > 0).reduce((sum, d) => sum + d.httpsStatus, 0)
      / diagnosticsForHealth.filter((d) => d.httpsStatus > 0).length,
    )
    : 0;
  const dnsHealthPct = Math.round((dnsHealthy / safeBase) * 100);
  const tlsHealthPct = Math.round((tlsHealthy / safeBase) * 100);
  const httpHealthPct = Math.round((httpHealthy / safeBase) * 100);
  const httpsHealthPct = Math.round((httpsHealthy / safeBase) * 100);
  const certWindowPct = certKnown.length > 0 ? Math.max(0, Math.min(100, Math.round((1 - (certExpiringSoon / certKnown.length)) * 100))) : 0;
  const logWindowCutoff = (() => {
    const now = Date.now();
    if (logWindow === '15m') return now - (15 * 60 * 1000);
    if (logWindow === '1h') return now - (60 * 60 * 1000);
    if (logWindow === '6h') return now - (6 * 60 * 60 * 1000);
    if (logWindow === '24h') return now - (24 * 60 * 60 * 1000);
    if (logWindow === '7d') return now - (7 * 24 * 60 * 60 * 1000);
    return 0;
  })();
  const logsBaseByWindow = audit.filter((e) => {
    if (logWindowCutoff <= 0) return true;
    const ts = new Date(e.createdAt).getTime();
    if (!Number.isFinite(ts) || ts <= 0) return true;
    return ts >= logWindowCutoff;
  });
  const logNamespaces = Array.from(new Set(logsBaseByWindow.map((e) => actionNamespace(e.action)))).sort();
  const logActions = Array.from(new Set(logsBaseByWindow.map((e) => e.action))).sort();
  const logActors = Array.from(new Set(logsBaseByWindow.map((e) => e.actor))).sort();
  const logIPs = Array.from(new Set(logsBaseByWindow.map((e) => extractSourceIP(e)).filter(Boolean))).sort();
  const publicIPv4Hint = (settings?.publicIpv4 || settingsPublicIPv4 || '').trim();
  const filteredAudit = logsBaseByWindow.filter((e) => {
    const level = classifyAuditLevel(e.action, e.target);
    if (logLevelFilter !== 'all' && level !== logLevelFilter) return false;
    const namespace = actionNamespace(e.action);
    if (logNamespaceFilter !== 'all' && namespace !== logNamespaceFilter) return false;
    if (logActionFilter !== 'all' && e.action !== logActionFilter) return false;
    if (logActorFilter !== 'all' && e.actor !== logActorFilter) return false;
    const src = extractSourceIP(e);
    if (logIPFilter !== 'all' && src !== logIPFilter) return false;
    if (logScopeFilter !== 'all') {
      if (!src) return false;
      const scope = classifySourceScope(src, publicIPv4Hint);
      if (scope !== logScopeFilter) return false;
    }
    if (logTargetQuery.trim()) {
      const tq = logTargetQuery.trim().toLowerCase();
      if (!(e.target || '').toLowerCase().includes(tq)) return false;
    }
    if (!logQuery.trim()) return true;
    const q = logQuery.trim().toLowerCase();
    const qCompact = q.replace(/[^a-z0-9]/g, '');
    const trace = extractTraceID(e);
    const hay = `${e.action} ${e.actor} ${e.target} ${src} ${e.meta || ''}`.toLowerCase();
    const hayCompact = hay.replace(/[^a-z0-9]/g, '');
    if (hay.includes(q)) return true;
    if (qCompact && hayCompact.includes(qCompact)) return true;
    const traceNeedles = extractTraceNeedles(q);
    if (traceNeedles.length > 0) {
      const traceCompact = trace.toLowerCase().replace(/[^a-z0-9]/g, '');
      return traceNeedles.some((n) => traceCompact.includes(n) || hayCompact.includes(n));
    }
    if (!qCompact) return false;
    const traceCompact = trace.toLowerCase().replace(/[^a-z0-9]/g, '');
    return traceCompact.includes(qCompact) || hayCompact.includes(qCompact);
  });
  const auditCriticalTotal = audit.filter((e) => classifyAuditLevel(e.action, e.target) === 'critical').length;
  const auditWarningTotal = audit.filter((e) => classifyAuditLevel(e.action, e.target) === 'warn').length;
  const auditInfoTotal = audit.filter((e) => classifyAuditLevel(e.action, e.target) === 'info').length;
  const auditActorsTotal = new Set(audit.map((e) => e.actor).filter(Boolean)).size;
  useEffect(() => {
    if (logNamespaceFilter !== 'all' && !logNamespaces.includes(logNamespaceFilter)) {
      setLogNamespaceFilter('all');
    }
    if (logActionFilter !== 'all' && !logActions.includes(logActionFilter)) {
      setLogActionFilter('all');
    }
    if (logActorFilter !== 'all' && !logActors.includes(logActorFilter)) {
      setLogActorFilter('all');
    }
    if (logIPFilter !== 'all' && !logIPs.includes(logIPFilter)) {
      setLogIPFilter('all');
    }
  }, [logNamespaceFilter, logNamespaces, logActionFilter, logActions, logActorFilter, logActors, logIPFilter, logIPs]);
  const cloudflareDomains = domains.filter((d) => (d.dnsMode || '') === 'cloudflare').length;
  const manualDomains = Math.max(0, domains.length - cloudflareDomains);
  const domainsChecked = Object.keys(domainChecks).length;
  const domainsWithIssues = Object.values(domainChecks).filter((c) => !c.overallOk).length;
  const hostsWithDiagnostics = hosts.filter((h) => !!hostDiagnostics[h.fqdn]).length;
  const hostsHealthy = hosts.filter((h) => {
    const d = hostDiagnostics[h.fqdn];
    if (!d) return false;
    return (d.dnsRecords || []).length > 0 && d.tlsOk && d.httpsStatus >= 200 && d.httpsStatus < 500;
  }).length;
  const hostsGroupedByApex = useMemo(() => {
    const normalizedDomains = [...domains]
      .map((d) => String(d.name || '').trim().toLowerCase())
      .filter(Boolean)
      .sort((a, b) => b.length - a.length);
    const byApex: Record<string, Host[]> = {};
    const resolveApex = (fqdnRaw: string): string => {
      const fqdn = String(fqdnRaw || '').trim().toLowerCase();
      for (const apex of normalizedDomains) {
        if (fqdn === apex || fqdn.endsWith(`.${apex}`)) return apex;
      }
      const parts = fqdn.split('.').filter(Boolean);
      if (parts.length >= 2) return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
      return fqdn || 'unknown';
    };
    hosts.forEach((h) => {
      const apex = resolveApex(h.fqdn);
      if (!byApex[apex]) byApex[apex] = [];
      byApex[apex].push(h);
    });
    return Object.keys(byApex).sort((a, b) => a.localeCompare(b)).map((apex) => ({
      apex,
      items: byApex[apex].sort((a, b) => a.fqdn.localeCompare(b.fqdn)),
    }));
  }, [hosts, domains]);
  const filteredUsers = useMemo(() => {
    const q = usersQuery.trim().toLowerCase();
    return users.filter((u) => {
      if (usersRoleFilter !== 'all' && u.role !== usersRoleFilter) return false;
      if (!q) return true;
      return u.username.toLowerCase().includes(q) || String(u.id).includes(q) || u.role.toLowerCase().includes(q);
    });
  }, [users, usersRoleFilter, usersQuery]);
  const editingUser = editUserID ? (users.find((u) => u.id === editUserID) || null) : null;
  const configuredAdminFQDN = settings?.adminFqdn || (settingsBaseDomain ? `admin.${settingsBaseDomain}` : '');
  const activeTheme = useMemo<ThemeVars>(() => {
    const selectedProfile = identity ? settingsStyleProfile : publicStyleProfile;
    const selectedCustom = identity ? settingsStyleCustom : publicStyleCustom;
    const profile = (selectedProfile || 'monolith') as StyleProfile;
    const base = profile === 'cybermonolith' ? CYBER_MONOLITH_THEME : MONOLITH_THEME;
    const custom = parseCustomThemeJSON(selectedCustom);
    if (profile === 'custom') {
      return { ...MONOLITH_THEME, ...custom };
    }
    return { ...base, ...custom };
  }, [identity, settingsStyleProfile, settingsStyleCustom, publicStyleProfile, publicStyleCustom]);
  const fqdnPreview = hostSub && hostDomain ? `${hostSub}.${hostDomain}` : '';
  const hostUsesDirectUpstream = !hostHAEnabled && !hostSSHBastion;
  const hostEffectiveUpstream = hostSSHBastion ? SSH_BASTION_DEFAULT_UPSTREAM : hostUpstream;
  const isReadOnlyRole = identity?.role === 'read-only';
  useEffect(() => {
    if (!isReadOnlyRole) return;
    // Ensure no sensitive key material remains visible after switching to read-only.
    setSshGeneratedPrivateKey('');
    setSshGeneratedPublicKey('');
    setSshGeneratedPPK('');
    setSshGeneratedRFC4716('');
    setSshGeneratedPPKError('');
    setSshKeyPublic('');
  }, [isReadOnlyRole]);
  const sshRouteByFQDN = useMemo(() => {
    const out: Record<string, SSHBastionRoute> = {};
    sshRoutes.forEach((r) => { out[r.fqdn.toLowerCase()] = r; });
    return out;
  }, [sshRoutes]);
  const sshCandidateHosts = useMemo(
    () => hosts.filter((h) => !h.haEnabled && (h.upstreamUrl || '').trim().toLowerCase() === SSH_BASTION_DEFAULT_UPSTREAM),
    [hosts],
  );
  const sshUnroutedCandidateHosts = useMemo(
    () => sshCandidateHosts.filter((h) => !sshRouteByFQDN[h.fqdn.toLowerCase()]),
    [sshCandidateHosts, sshRouteByFQDN],
  );
  useEffect(() => {
    if (tab !== 'ssh') return;
    if (sshSelectedHostFQDN) return;
    if (sshUnroutedCandidateHosts.length === 0) return;
    setSshSelectedHostFQDN(sshUnroutedCandidateHosts[0].fqdn);
  }, [tab, sshSelectedHostFQDN, sshUnroutedCandidateHosts]);
  const selectedHost = selectedHostID ? (hosts.find((h) => h.id === selectedHostID) || null) : null;
  const requestsByHostID = useMemo(() => {
    const out: Record<number, number> = {};
    (trafficOverview?.hosts || []).forEach((h) => { out[h.hostId] = h.requests || 0; });
    return out;
  }, [trafficOverview]);
  const haHostsMonitored = hosts.filter((h) => h.haEnabled && (hostDiagnostics[h.fqdn]?.haTotal || 0) > 0).length;
  const haHostsDegraded = hosts.filter((h) => {
    const d = hostDiagnostics[h.fqdn];
    if (!h.haEnabled || !d || !d.haTotal) return false;
    return (d.haOnline || 0) < d.haTotal;
  }).length;
  const haDegradedDetails = hosts
    .map((h) => {
      const d = hostDiagnostics[h.fqdn];
      if (!h.haEnabled || !d || !d.haTotal) return null;
      if ((d.haOnline || 0) >= d.haTotal) return null;
      const offline = (d.haOffline || []).filter(Boolean);
      return {
        fqdn: h.fqdn,
        online: d.haOnline || 0,
        total: d.haTotal || 0,
        offline,
      };
    })
    .filter((it): it is { fqdn: string; online: number; total: number; offline: string[] } => !!it);
  const domainApexPreview = domainName || 'example.com';
  const adminPreview = `admin.${domainApexPreview}`;
  const publicIPPreview = settingsPublicIPv4 || settings?.publicIpv4 || '<your-public-ip>';
  const trafficReq24h = trafficOverview?.totalRequests || 0;
  const trafficVisitors24h = trafficOverview?.uniqueVisitors || 0;
  const trafficOut24h = trafficOverview?.totalBytesOut || 0;
  const trafficBlocked24h = trafficOverview?.totalBlocked || 0;
  const sysCpuPct = Math.max(0, Math.min(100, Math.round(systemHealth?.cpuPercent || 0)));
  const sysRamPct = Math.max(0, Math.min(100, Math.round(systemHealth?.ramPercent || 0)));
  const sysNetPct = Math.max(0, Math.min(100, Math.round(systemHealth?.networkLoadPct || 0)));
  const sysNetPerSec = systemHealth?.networkBytesPerSec || 0;
  const hostTrafficReq = selectedHostTraffic?.requests || 0;
  const hostTraffic2xxRate = hostTrafficReq > 0 ? Math.round(((selectedHostTraffic?.status2xx || 0) / hostTrafficReq) * 100) : 0;
  const hostTrafficErrRate = hostTrafficReq > 0 ? Math.round((((selectedHostTraffic?.status4xx || 0) + (selectedHostTraffic?.status5xx || 0)) / hostTrafficReq) * 100) : 0;
  const hostTrafficBlockRate = hostTrafficReq > 0 ? Math.round(((selectedHostTraffic?.blocked || 0) / hostTrafficReq) * 100) : 0;
  const hostVisitorRatio = hostTrafficReq > 0 ? Math.round(((selectedHostTraffic?.uniqueVisitors || 0) / hostTrafficReq) * 100) : 0;
  const metricCountries = [...(metricCountryOverview?.countries || [])].sort((a, b) => (b.requests || 0) - (a.requests || 0));
  const metricTopReq = metricCountries.length > 0 ? metricCountries[0].requests || 1 : 1;
  const metricUnknownTotal = metricCountries.find((c) => (c.country || '').toUpperCase() === 'ZZ')?.requests || 0;
  const metricUnknownBreakdown = [...(metricCountryOverview?.unknownBreakdown || [])].sort((a, b) => (b.requests || 0) - (a.requests || 0));
  const metricFilteredCountries = metricCountryFocus === 'all'
    ? metricCountries
    : metricCountries.filter((c) => (c.country || '').toUpperCase() === metricCountryFocus.toUpperCase());
  const metricTotalRequests = metricCountryOverview?.totalRequests || 0;
  const metricTotalBlocked = metricCountryOverview?.totalBlocked || 0;
  const metricTotalBytesOut = metricCountryOverview?.totalBytesOut || 0;
  const metricError4xx = metricCountries.reduce((s, c) => s + (c.status4xx || 0), 0);
  const metricError5xx = metricCountries.reduce((s, c) => s + (c.status5xx || 0), 0);
  const metric2xx = metricCountries.reduce((s, c) => s + (c.status2xx || 0), 0);
  const metricErrRatePct = metricTotalRequests > 0 ? Math.round(((metricError4xx + metricError5xx) / metricTotalRequests) * 100) : 0;
  const metric5xxRatePct = metricTotalRequests > 0 ? Math.round((metricError5xx / metricTotalRequests) * 100) : 0;
  const metricBlockRatePct = metricTotalRequests > 0 ? Math.round((metricTotalBlocked / metricTotalRequests) * 100) : 0;
  const metricSuccessRatePct = metricTotalRequests > 0 ? Math.round((metric2xx / metricTotalRequests) * 100) : 0;
  const topCountry = metricCountries[0];
  const topBlockedCountry = [...metricCountries].sort((a, b) => (b.blocked || 0) - (a.blocked || 0))[0];
  const topUnknownSharePct = metricTotalRequests > 0 ? Math.round((metricUnknownTotal / metricTotalRequests) * 100) : 0;
  const trafficSpikeScore = (() => {
    const total = trafficOverview?.totalRequests || 0;
    const base = Math.max(1, hosts.length * 120);
    return Math.round((total / base) * 100);
  })();
  const metricProblems = [
    {
      id: 'p-5xx',
      severity: metric5xxRatePct >= 5 ? 'critical' : metric5xxRatePct >= 2 ? 'warn' : 'ok',
      issue: 'Server errors (5xx)',
      value: `${metric5xxRatePct}%`,
      detail: `${metricError5xx} responses`,
      action: () => setTab('audit'),
      actionLabel: 'Open Logs',
    },
    {
      id: 'p-err',
      severity: metricErrRatePct >= 12 ? 'critical' : metricErrRatePct >= 6 ? 'warn' : 'ok',
      issue: 'Client+server errors',
      value: `${metricErrRatePct}%`,
      detail: `${metricError4xx + metricError5xx} responses`,
      action: () => setTab('audit'),
      actionLabel: 'Investigate',
    },
    {
      id: 'p-block',
      severity: metricBlockRatePct >= 25 ? 'critical' : metricBlockRatePct >= 10 ? 'warn' : 'ok',
      issue: 'Blocked request ratio',
      value: `${metricBlockRatePct}%`,
      detail: `${metricTotalBlocked} blocked`,
      action: () => setTab('threatIntel'),
      actionLabel: 'Threat Intel',
    },
    {
      id: 'p-ha',
      severity: haHostsDegraded > 0 ? 'critical' : 'ok',
      issue: 'HA degraded routes',
      value: `${haHostsDegraded}`,
      detail: `${haHostsMonitored} monitored`,
      action: () => setTab('dashboard'),
      actionLabel: 'Open Dashboard',
    },
    {
      id: 'p-spike',
      severity: trafficSpikeScore >= 220 ? 'critical' : trafficSpikeScore >= 140 ? 'warn' : 'ok',
      issue: 'Traffic spike score',
      value: `${trafficSpikeScore}%`,
      detail: 'vs baseline model',
      action: () => setTab('metricCenter'),
      actionLabel: 'Review',
    },
    {
      id: 'p-zz',
      severity: topUnknownSharePct >= 30 ? 'warn' : 'ok',
      issue: 'Unknown geo share',
      value: `${topUnknownSharePct}%`,
      detail: `${metricUnknownTotal} requests`,
      action: () => setMetricCountryFocus('all'),
      actionLabel: 'Details',
    },
  ];
  const metricProblemsSorted = [...metricProblems].sort((a, b) => {
    const score = (s: string) => (s === 'critical' ? 2 : s === 'warn' ? 1 : 0);
    return score(b.severity) - score(a.severity);
  });
  const blockedIPCount = blockedIPs.length;
  const degradedHostNames = hosts.filter((h) => h.state === 'error').map((h) => h.fqdn);
  const dashboardStoreItems = DASHBOARD_WIDGET_STORE.filter((w) => {
    if (!dashboardWidgetQuery.trim()) return true;
    const q = dashboardWidgetQuery.trim().toLowerCase();
    return `${w.title} ${w.description} ${w.category}`.toLowerCase().includes(q);
  });
  const dashboardStoreCategories = ['Metrics', 'Traffic', 'Security', 'Operations', 'Quick Actions'] as const;

  const renderDashboardWidget = (widget: DashboardWidget) => {
    switch (widget.type) {
      case 'ha_alerts':
        return haHostsDegraded > 0 ? (
          <div className="error" style={{ marginBottom: 0 }}>
            HA Alert: {haHostsDegraded}/{haHostsMonitored || haHostsDegraded} HA subdomains have offline backends.
            <div className="muted" style={{ marginTop: '.35rem' }}>
              {haDegradedDetails.map((it) => (
                <div key={`ha-alert-${it.fqdn}`}>
                  {it.fqdn}: {it.online}/{it.total} online{it.offline.length > 0 ? ` · offline: ${it.offline.join(', ')}` : ''}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="muted">No degraded HA routes.</div>
        );
      case 'kpi_overview':
        return (
          <div className="kpi-row">
            <Card title="Domains" value={String(domains.length)} status="ok" />
            <Card title="Active Hosts" value={String(activeHosts)} status="ok" />
            <Card title="Host Errors" value={String(errorHosts)} status={errorHosts > 0 ? 'err' : 'ok'} />
            <Card title="Monitored Hosts" value={String(monitoredHosts)} status={monitoredHosts > 0 ? 'ok' : 'err'} />
          </div>
        );
      case 'health_gauges':
        return (
          <div className="gauge-grid">
            <Gauge title="DNS Health" value={dnsHealthPct} subtitle={`${dnsHealthy}/${safeBase} hosts`} strictFull />
            <Gauge title="HTTP Reachability" value={httpHealthPct} subtitle={`${httpHealthy}/${safeBase} hosts`} strictFull />
            <Gauge title="HTTPS Reachability" value={httpsHealthPct} subtitle={`${httpsHealthy}/${safeBase} hosts`} strictFull />
            <Gauge title="TLS Health" value={tlsHealthPct} subtitle={`${tlsHealthy}/${safeBase} hosts`} strictFull />
            <Gauge title="Cert Window" value={certWindowPct} subtitle={certKnown.length > 0 ? `${certExpiringSoon} expiring <=14d` : 'no cert data'} strictFull />
          </div>
        );
      case 'system_health':
        return (
          <div className="gauge-grid">
            <Gauge title="CPU Load" value={sysCpuPct} subtitle={systemHealth ? `${systemHealth.load1.toFixed(2)} / ${systemHealth.cpuCores.toFixed(0)} load/cores` : 'No sample'} />
            <Gauge title="RAM Usage" value={sysRamPct} subtitle={systemHealth ? `${formatBytes(systemHealth.ramUsedBytes || 0)} / ${formatBytes(systemHealth.ramTotalBytes || 0)}` : 'No sample'} />
            <Gauge title="Network Load" value={sysNetPct} subtitle={systemHealth ? `${formatBytes(sysNetPerSec)}/s / ${formatBytes(systemHealth.networkBaselineBps || 0)}/s` : 'No sample'} />
          </div>
        );
      case 'performance_snapshot':
        return (
          <div className="metric-grid">
            <MetricTile label="Avg HTTPS Status" value={avgHTTPSStatus > 0 ? String(avgHTTPSStatus) : '-'} hint="Target: < 400" />
            <MetricTile label="Avg Cert Days Left" value={avgCertDays > 0 ? `${avgCertDays}d` : '-'} hint="Target: > 30d" />
            <MetricTile label="TLS Failure Count" value={String(Math.max(0, monitoredHosts - tlsHealthy))} hint="Should trend to 0" />
            <MetricTile label="DNS Failure Count" value={String(Math.max(0, monitoredHosts - dnsHealthy))} hint="Should trend to 0" />
          </div>
        );
      case 'traffic_snapshot':
        return (
          <div className="metric-grid">
            <MetricTile label="Requests" value={String(trafficReq24h)} hint="Total across all subdomains" />
            <MetricTile label="Unique Visitors" value={String(trafficVisitors24h)} hint="Distinct client IP hashes" />
            <MetricTile label="Traffic Out" value={formatBytes(trafficOut24h)} hint="Response bytes" />
            <MetricTile label="Geo Blocks" value={String(trafficBlocked24h)} hint="Blocked by GeoIP policy" />
          </div>
        );
      case 'control_plane_health':
        return (
          <>
            <div className="metric-grid">
              <MetricTile label="Cloudflare Token" value={settings?.hasCloudflareToken ? 'set' : 'missing'} hint="Global API token state" />
              <MetricTile label="ACME Mode" value={settingsAcmeStaging ? 'staging' : 'production'} hint="Certificate endpoint" />
              <MetricTile label="Time Sync Mode" value={settingsTimeSyncMode} hint="Clock source policy" />
              <MetricTile label="Time Sync State" value={timeSyncStatus ? (timeSyncStatus.severity || 'unknown').toUpperCase() : '-'} hint={timeSyncStatus?.summary || 'No check yet'} />
            </div>
            {timeSyncStatus ? (
              <div className="event-list" style={{ marginTop: '.55rem' }}>
                {(timeSyncStatus.probes || []).slice(0, 3).map((p, idx) => (
                  <div className="event-item" key={`dash-ts-${idx}`}>
                    <div className="event-top">
                      <strong>{p.target || p.name}</strong>
                      <span className={`badge ${p.ok ? 'ok' : 'err'}`}>{p.ok ? 'ok' : 'fail'}</span>
                    </div>
                    <div className="muted">offset {String(p.offsetMs || 0)}ms · rtt {String(p.rttMs || 0)}ms</div>
                  </div>
                ))}
              </div>
            ) : null}
          </>
        );
      case 'recent_events':
        return (
          <div className="event-list">
            {audit.length === 0 ? (
              <div className="muted">No events yet.</div>
            ) : (
              audit.slice(0, 10).map((e) => (
                <div className="event-item" key={e.id}>
                  <div className="event-top">
                    <strong>{e.action}</strong>
                    <span className="muted">{new Date(e.createdAt).toLocaleString()}</span>
                  </div>
                  <div className="muted">{e.actor} {'->'} {e.target}</div>
                </div>
              ))
            )}
          </div>
        );
      case 'security_snapshot':
        return (
          <div className="metric-grid">
            <MetricTile label="Critical" value={String(auditCriticalTotal)} hint="Deletes, resets, revokes" />
            <MetricTile label="Warnings" value={String(auditWarningTotal)} hint="Updates, retries, proxy issues" />
            <MetricTile label="Blocked IPs" value={String(blockedIPCount)} hint="Current block table size" />
            <MetricTile label="Threat Offenders" value={String(tiTotalOffenders)} hint="Current threat offender list" />
          </div>
        );
      case 'degraded_hosts':
        return degradedHostNames.length === 0 ? (
          <div className="muted">No host errors currently reported.</div>
        ) : (
          <div className="event-list">
            {degradedHostNames.slice(0, 20).map((name) => (
              <div className="event-item" key={`deg-${name}`}>{name}</div>
            ))}
          </div>
        );
      case 'quick_actions':
        return (
          <div className="row" style={{ marginBottom: 0 }}>
            <button className="btn" onClick={refresh} disabled={loading}>Refresh Data</button>
            <button className="btn" onClick={() => setTab('audit')}>Open Log Center</button>
            <button className="btn" onClick={() => setTab('metricCenter')}>Open Metric Center</button>
            <button className="btn" onClick={runScheduledBackupNow} disabled={loading || isReadOnlyRole}>Backup now</button>
            <button className="btn" onClick={reloadService} disabled={loading || isReadOnlyRole}>Reload Service</button>
          </div>
        );
      default:
        return <div className="muted">Unsupported widget.</div>;
    }
  };

  const domainProviderGuide: Record<DomainProvider, { title: string; steps: string[]; records: string[] }> = {
    cloudflare: {
      title: 'Cloudflare (API automated)',
      steps: [
        'Create a Cloudflare API token with zone DNS permissions (least privilege).',
        'Store the Cloudflare token in the Settings tab.',
        'Enter the Zone ID per domain in the wizard.',
        'Set the domain nameservers to Cloudflare.',
        'After saving, Domnex can automatically create/update DNS records.',
      ],
      records: [
        `@  A      ${publicIPPreview}   TTL 120`,
        'admin  CNAME  @              TTL Auto',
        '*.optional CNAME @           TTL Auto',
      ],
    },
    strato: {
      title: 'Strato (manual DNS setup)',
      steps: [
        'Open DNS settings for your domain in the Strato dashboard.',
        'Create the root record (@) as an A record pointing to your WAN IP.',
        'Create admin as CNAME to root (@) or as A record to the same WAN IP.',
        'Wait for DNS propagation, then verify reachability of admin.<domain>.',
      ],
      records: [
        `@  A      ${publicIPPreview}   TTL 300`,
        'admin  CNAME  @              TTL 300',
        'app    CNAME  @              TTL 300',
      ],
    },
    manual: {
      title: 'Other provider (manual)',
      steps: [
        'Create the required DNS records in your provider panel.',
        'Root domain must point to your WAN IP (A, optional AAAA).',
        'admin subdomain must point to the same target address (CNAME or A).',
        'After DNS propagation, Domnex issues certificates via HTTP-01.',
      ],
      records: [
        `@  A      ${publicIPPreview}`,
        `admin  CNAME  ${domainApexPreview}`,
      ],
    },
  };

  const createToken = async () => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    try {
      const out = await api<{ token: string }>('/api/v1/tokens', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          name: newTokenName,
          role: newTokenRole,
          scopes: newTokenScopes.split(',').map((v) => v.trim()).filter(Boolean),
          domainIds: (newTokenGlobalRead || newTokenGlobalWrite) ? [] : newTokenDomainIDs,
          permissions: {
            globalRead: newTokenGlobalRead,
            globalWrite: newTokenGlobalWrite,
            domainRead: newTokenDomainRead,
            domainWrite: newTokenDomainWrite,
            systemRead: newTokenSystemRead,
            systemWrite: newTokenSystemWrite,
          },
          expiresIn: newTokenTTL,
        }),
      });
      setCreatedToken(out.token || '');
      setNewTokenDomainIDs([]);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const revokeToken = async (id: number) => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/tokens/${id}`, { method: 'DELETE', headers: { 'X-CSRF-Token': csrf } });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const createResetToken = async () => {
    setLoading(true);
    setError('');
    try {
      const out = await api<{ token: string }>('/api/v1/password-reset/create', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ username: resetUser, expiresIn: resetTTL }),
      });
      setResetToken(out.token || '');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const consumeResetToken = async () => {
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/password-reset/consume', {
        method: 'POST',
        body: JSON.stringify({ token: resetToken, newPassword: resetNewPassword }),
      });
      setResetNewPassword('');
      setResetToken('');
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const saveSettings = async () => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      const out = await api<{ message?: string; restartNeeded?: boolean }>('/api/v1/settings', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          acmeEmail: settingsAcmeEmail,
          acmeStaging: settingsAcmeStaging,
          cfToken: settingsCFToken,
          publicIpv4: settingsPublicIPv4,
          baseDomain: settingsBaseDomain,
          styleProfile: settingsStyleProfile,
          styleCustom: settingsStyleCustom,
          timeSyncMode: settingsTimeSyncMode,
          timeSyncLANServers: settingsTimeSyncLAN,
          logServers: settingsLogServers,
          logHttpBearer: settingsLogHTTPBearer,
          retention: settingsRetention,
        }),
      });
      setSettingsCFToken('');
      setSettingsLogHTTPBearer('');
      setSettingsMessage(out.message || 'Settings saved.');
      await refresh();
      await loadTimeSyncStatus();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const runDomainLiveCheck = async (domainId: number) => {
    setLoading(true);
    setError('');
    try {
      const out = await api<DomainLiveCheck>(`/api/v1/domains/${domainId}/live-check`);
      setDomainChecks((prev) => ({ ...prev, [domainId]: out }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteDomain = async (id: number) => {
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/domains/${id}`, { method: 'DELETE', headers: { 'X-CSRF-Token': csrf } });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deactivateDomain = async (d: Domain) => {
    if (!window.confirm(`Deactivate domain ${d.name}? This will disable all subdomains under it.`)) return;
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/domains/${d.id}/deactivate`, { method: 'POST', headers: { 'X-CSRF-Token': csrf } });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteHost = async (id: number) => {
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/hosts/${id}`, { method: 'DELETE', headers: { 'X-CSRF-Token': csrf } });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const openDeleteHostDialog = (h: Host) => {
    setDeleteHostID(h.id);
    setDeleteHostLabel(h.fqdn);
    setDeleteHostConfirmText('');
    setDeleteHostDialogOpen(true);
  };

  const closeDeleteHostDialog = () => {
    setDeleteHostDialogOpen(false);
    setDeleteHostID(null);
    setDeleteHostLabel('');
    setDeleteHostConfirmText('');
  };

  const confirmDeleteHost = async () => {
    if (!deleteHostID || deleteHostConfirmText.trim() !== 'Remove') {
      setError('Deletion confirmation failed. Type exactly "Remove".');
      return;
    }
    await deleteHost(deleteHostID);
    closeDeleteHostDialog();
  };

  const setHostDisabled = async (id: number, disabled: boolean) => {
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/hosts/${id}/disable`, {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ disabled }),
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const setHostMaintenance = async (id: number, enabled: boolean) => {
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/hosts/${id}/maintenance`, {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ enabled }),
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const reloadService = async () => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      await api('/api/v1/reload', { method: 'POST', headers: { 'X-CSRF-Token': csrf } });
      setSettingsMessage('Reload triggered. Service is restarting. Wait 3-5 seconds, then refresh.');
      setTimeout(() => { window.location.reload(); }, 5000);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const saveSSHRoute = async () => {
    if (isReadOnlyRole) return;
    const fqdn = (sshSelectedHostFQDN || sshRouteFQDN).trim().toLowerCase();
    if (!fqdn || !sshRouteTargetHost.trim() || !sshRouteTargetPort.trim()) return;
    const existing = sshRouteByFQDN[fqdn];
    setLoading(true);
    setError('');
    try {
      const out = await api<SSHBastionRoute>('/api/v1/ssh/routes', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          id: existing?.id || 0,
          fqdn,
          targetHost: sshRouteTargetHost.trim(),
          targetPort: Number(sshRouteTargetPort) || 22,
          enabled: sshRouteEnabled,
        }),
      });
      setSshRoutes((prev) => {
        const idx = prev.findIndex((r) => r.id === out.id || r.fqdn.toLowerCase() === out.fqdn.toLowerCase());
        if (idx < 0) return [out, ...prev].sort((a, b) => a.fqdn.localeCompare(b.fqdn));
        const next = [...prev];
        next[idx] = out;
        return next.sort((a, b) => a.fqdn.localeCompare(b.fqdn));
      });
      setSshSelectedHostFQDN('');
      setSshRouteFQDN('');
      setSshRouteTargetHost('');
      setSshRouteTargetPort('22');
      setSshRouteEnabled(true);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteSSHRoute = async (id: number) => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/ssh/routes/${id}`, {
        method: 'DELETE',
        headers: { 'X-CSRF-Token': csrf },
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const toggleSSHKeyRoute = (id: number) => {
    if (isReadOnlyRole) return;
    setSshKeyRouteIDs((prev) => prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]);
  };

  const editSSHRoute = (r: SSHBastionRoute) => {
    if (isReadOnlyRole) return;
    setSshSelectedHostFQDN(r.fqdn);
    setSshRouteFQDN(r.fqdn);
    setSshRouteTargetHost(r.targetHost);
    setSshRouteTargetPort(String(r.targetPort || 22));
    setSshRouteEnabled(!!r.enabled);
  };

  const generateSSHKeyForRoute = async (routeID: number, fqdn: string) => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    try {
      const safeName = fqdn.replace(/[^a-zA-Z0-9._-]/g, '-');
      const out = await api<SSHBastionGenerate>('/api/v1/ssh/keys/generate', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ name: `${safeName}-key`, routeIds: [routeID] }),
      });
      setSshGeneratedPrivateKey(out.privateKey || '');
      setSshGeneratedPublicKey(out.key?.publicKey || '');
      setSshGeneratedKeyName(out.key?.name || `${safeName}-key`);
      setSshGeneratedPPK(out.privateKeyPpk || '');
      setSshGeneratedRFC4716(out.publicKeyRfc4716 || '');
      setSshGeneratedPPKError(out.ppkError || '');
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const generateSSHKey = async () => {
    if (isReadOnlyRole) return;
    if (!sshKeyName.trim() || sshKeyRouteIDs.length === 0) return;
    setLoading(true);
    setError('');
    try {
      const out = await api<SSHBastionGenerate>('/api/v1/ssh/keys/generate', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ name: sshKeyName.trim(), routeIds: sshKeyRouteIDs }),
      });
      setSshGeneratedPrivateKey(out.privateKey || '');
      setSshGeneratedPublicKey(out.key?.publicKey || '');
      setSshGeneratedKeyName(out.key?.name || sshKeyName.trim());
      setSshGeneratedPPK(out.privateKeyPpk || '');
      setSshGeneratedRFC4716(out.publicKeyRfc4716 || '');
      setSshGeneratedPPKError(out.ppkError || '');
      setSshKeyName('');
      setSshKeyPublic('');
      setSshKeyRouteIDs([]);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const downloadGeneratedLinuxKey = () => {
    if (!sshGeneratedPrivateKey.trim()) return;
    const base = (sshGeneratedKeyName || 'domnex-bastion-key').replace(/[^a-zA-Z0-9._-]/g, '-');
    downloadTextFile(`${base}.key`, sshGeneratedPrivateKey.endsWith('\n') ? sshGeneratedPrivateKey : `${sshGeneratedPrivateKey}\n`);
  };

  const downloadGeneratedWindowsKey = () => {
    if (!sshGeneratedPrivateKey.trim()) return;
    const base = (sshGeneratedKeyName || 'domnex-bastion-key').replace(/[^a-zA-Z0-9._-]/g, '-');
    const content = (sshGeneratedPrivateKey.endsWith('\n') ? sshGeneratedPrivateKey : `${sshGeneratedPrivateKey}\n`).replace(/\n/g, '\r\n');
    downloadTextFile(`${base}.pem`, content);
  };

  const downloadGeneratedPublicKey = () => {
    if (!sshGeneratedPublicKey.trim()) return;
    const base = (sshGeneratedKeyName || 'domnex-bastion-key').replace(/[^a-zA-Z0-9._-]/g, '-');
    downloadTextFile(`${base}.pub`, sshGeneratedPublicKey.endsWith('\n') ? sshGeneratedPublicKey : `${sshGeneratedPublicKey}\n`);
  };

  const downloadGeneratedPPK = () => {
    if (!sshGeneratedPPK.trim()) return;
    const base = (sshGeneratedKeyName || 'domnex-bastion-key').replace(/[^a-zA-Z0-9._-]/g, '-');
    downloadTextFile(`${base}.ppk`, sshGeneratedPPK.endsWith('\n') ? sshGeneratedPPK : `${sshGeneratedPPK}\n`);
  };

  const downloadGeneratedRFC4716 = () => {
    if (!sshGeneratedRFC4716.trim()) return;
    const base = (sshGeneratedKeyName || 'domnex-bastion-key').replace(/[^a-zA-Z0-9._-]/g, '-');
    downloadTextFile(`${base}.ssh2`, sshGeneratedRFC4716.endsWith('\n') ? sshGeneratedRFC4716 : `${sshGeneratedRFC4716}\n`);
  };

  const importSSHKey = async () => {
    if (isReadOnlyRole) return;
    if (!sshKeyName.trim() || !sshKeyPublic.trim() || sshKeyRouteIDs.length === 0) return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/ssh/keys/import', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ name: sshKeyName.trim(), publicKey: sshKeyPublic.trim(), routeIds: sshKeyRouteIDs }),
      });
      setSshKeyName('');
      setSshKeyPublic('');
      setSshKeyRouteIDs([]);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteSSHKey = async (id: number) => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/ssh/keys/${id}`, {
        method: 'DELETE',
        headers: { 'X-CSRF-Token': csrf },
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const createUser = async () => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/users', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          username: newUserName,
          password: newUserPassword,
          role: newUserRole,
          domainIds: newUserRole === 'domain-admin' ? newUserDomainIDs : [],
          allowedCidrs: newUserAllowedCIDRs.trim(),
          ipCheckDisabled: !!newUserIPCheckDisabled,
        }),
      });
      setNewUserName('');
      setNewUserPassword('');
      setNewUserRole('domain-admin');
      setNewUserDomainIDs([]);
      setNewUserAllowedCIDRs('');
      setNewUserIPCheckDisabled(false);
      setShowCreateUserDialog(false);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteUser = async (id: number) => {
    if (isReadOnlyRole) return;
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/users/${id}`, { method: 'DELETE', headers: { 'X-CSRF-Token': csrf } });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const saveUserEdit = async () => {
    if (isReadOnlyRole) return;
    if (!editUserID) return;
    if (editUserRole === 'domain-admin' && editUserDomainIDs.length === 0) {
      setError('Domain-admin requires at least one domain assignment.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/users/${editUserID}`, {
        method: 'PUT',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          role: editUserRole,
          domainIds: editUserRole === 'domain-admin' ? editUserDomainIDs : [],
          allowedCidrs: editUserAllowedCIDRs.trim(),
          ipCheckDisabled: !!editUserIPCheckDisabled,
        }),
      });
      if (editUserPassword.trim()) {
        if (editUserPassword.length < 10) {
          throw new Error('Password must be at least 10 characters.');
        }
        await api(`/api/v1/users/${editUserID}/password`, {
          method: 'PUT',
          headers: { 'X-CSRF-Token': csrf },
          body: JSON.stringify({ password: editUserPassword }),
        });
      }
      await refresh();
      closeEditUserDialog();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const changeOwnPassword = async () => {
    if (!selfCurrentPassword || !selfNewPassword) return;
    if (selfNewPassword !== selfConfirmPassword) {
      setError('New password confirmation does not match.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/me/password', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ currentPassword: selfCurrentPassword, newPassword: selfNewPassword }),
      });
      setSelfCurrentPassword('');
      setSelfNewPassword('');
      setSelfConfirmPassword('');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const saveMyProfile = async () => {
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      await api('/api/v1/me/profile', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ email: selfNotifyEmail.trim() }),
      });
      setSettingsMessage('Account profile saved.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const currentDashboard = dashboardEditMode ? dashboardDraft : dashboardLayout;
  const currentDashboardTab = currentDashboard.tabs.find((t) => t.id === dashboardTabID) || currentDashboard.tabs[0] || null;

  const startDashboardEdit = () => {
    setDashboardDraft(normalizeDashboardLayout(dashboardLayout));
    setDashboardEditMode(true);
  };

  const cancelDashboardEdit = () => {
    setDashboardDraft(normalizeDashboardLayout(dashboardLayout));
    setDashboardEditMode(false);
    setDashboardWidgetQuery('');
  };

  const saveDashboardLayout = async () => {
    setLoading(true);
    setError('');
    setSettingsMessage('');
    try {
      const normalized = normalizeDashboardLayout(dashboardDraft);
      await api('/api/v1/me/profile', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ dashboardLayout: normalized }),
      });
      setDashboardLayout(normalized);
      setDashboardDraft(normalized);
      setDashboardEditMode(false);
      if (!normalized.tabs.some((t) => t.id === dashboardTabID)) {
        setDashboardTabID(normalized.tabs[0]?.id || 'minimal');
      }
      setSettingsMessage('Dashboard layout saved.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const updateDashboardDraftTabs = (fn: (tabs: DashboardUserTab[]) => DashboardUserTab[]) => {
    setDashboardDraft((prev) => ({ ...prev, tabs: fn(prev.tabs) }));
  };

  const addDashboardTab = () => {
    const name = dashboardNewTabName.trim() || `Tab ${dashboardDraft.tabs.length + 1}`;
    const id = `tab-${mkID()}`;
    updateDashboardDraftTabs((tabs) => [...tabs, { id, name: name.slice(0, 48), widgets: [] }]);
    setDashboardTabID(id);
    setDashboardNewTabName('');
  };

  const renameDashboardTab = (id: string, name: string) => {
    updateDashboardDraftTabs((tabs) => tabs.map((t) => (t.id === id ? { ...t, name: name.slice(0, 48) } : t)));
  };

  const deleteDashboardTab = (id: string) => {
    updateDashboardDraftTabs((tabs) => {
      if (tabs.length <= 1) return tabs;
      const next = tabs.filter((t) => t.id !== id);
      if (!next.some((t) => t.id === dashboardTabID)) setDashboardTabID(next[0]?.id || 'minimal');
      return next;
    });
  };

  const addWidgetToCurrentDashboardTab = (type: DashboardWidgetType) => {
    if (!currentDashboardTab) return;
    const meta = dashboardWidgetByType[type];
    const widget: DashboardWidget = { id: `w-${mkID()}`, type, w: meta.defaultW, h: meta.defaultH };
    updateDashboardDraftTabs((tabs) => tabs.map((t) => (t.id === currentDashboardTab.id ? { ...t, widgets: [...t.widgets, widget] } : t)));
  };

  const updateCurrentTabWidgets = (fn: (widgets: DashboardWidget[]) => DashboardWidget[]) => {
    if (!currentDashboardTab) return;
    updateDashboardDraftTabs((tabs) => tabs.map((t) => (t.id === currentDashboardTab.id ? { ...t, widgets: fn(t.widgets) } : t)));
  };

  const removeDashboardWidget = (widgetID: string) => {
    updateCurrentTabWidgets((widgets) => widgets.filter((w) => w.id !== widgetID));
  };

  const moveDashboardWidget = (widgetID: string, dir: -1 | 1) => {
    updateCurrentTabWidgets((widgets) => {
      const idx = widgets.findIndex((w) => w.id === widgetID);
      if (idx < 0) return widgets;
      const nx = idx + dir;
      if (nx < 0 || nx >= widgets.length) return widgets;
      const out = [...widgets];
      const a = out[idx];
      out[idx] = out[nx];
      out[nx] = a;
      return out;
    });
  };

  const resizeDashboardWidget = (widgetID: string, w: number, h: number) => {
    updateCurrentTabWidgets((widgets) => widgets.map((it) => (it.id === widgetID ? { ...it, w: Math.max(3, Math.min(12, w)), h: Math.max(1, Math.min(3, h)) } : it)));
  };

  const blockIP = async (ip: string, reason = 'manual block from audit') => {
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/security/ip-blocks', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ ip, reason }),
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const unblockIP = async (ip: string) => {
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/security/ip-blocks/remove', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ ip }),
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const toggleNewUserDomain = (id: number) => {
    setNewUserDomainIDs((prev) => (prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]));
  };

  const toggleEditUserDomain = (id: number) => {
    setEditUserDomainIDs((prev) => (prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]));
  };

  const openEditUserDialog = (u: ManagedUser) => {
    setEditUserID(u.id);
    setEditUserRole((u.role as 'admin' | 'domain-admin' | 'read-only') || 'read-only');
    setEditUserDomainIDs([...(u.domainIds || [])]);
    setEditUserPassword('');
    setEditUserAllowedCIDRs((u.allowedCidrs || '').trim());
    setEditUserIPCheckDisabled(!!u.ipCheckDisabled);
  };

  const closeEditUserDialog = () => {
    setEditUserID(null);
    setEditUserPassword('');
    setEditUserDomainIDs([]);
    setEditUserAllowedCIDRs('');
    setEditUserIPCheckDisabled(false);
  };

  const toggleNewTokenDomain = (id: number) => {
    setNewTokenDomainIDs((prev) => (prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]));
  };

  const updateHostBackend = (idx: number, patch: Partial<HABackend>) => {
    setHostHABackends((prev) => prev.map((b, i) => (i === idx ? { ...b, ...patch } : b)));
  };

  const addHostBackend = () => {
    setHostHABackends((prev) => [...prev, { name: `server${prev.length + 1}`, url: '' }]);
  };

  const removeHostBackend = (idx: number) => {
    setHostHABackends((prev) => prev.filter((_, i) => i !== idx));
  };

  const updateDetailBackend = (idx: number, patch: Partial<HABackend>) => {
    setDetailHABackends((prev) => prev.map((b, i) => (i === idx ? { ...b, ...patch } : b)));
  };

  const addDetailBackend = () => {
    setDetailHABackends((prev) => [...prev, { name: `server${prev.length + 1}`, url: '' }]);
  };

  const removeDetailBackend = (idx: number) => {
    setDetailHABackends((prev) => prev.filter((_, i) => i !== idx));
  };

  const saveThreatIntelConfig = async () => {
    if (isReadOnlyRole || identity?.role !== 'admin') return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/threat-intel/config', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify(tiConfig),
      });
      setTiConfigSavedAt(new Date().toISOString());
      await loadThreatIntel();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const syncThreatIntelNow = async () => {
    if (isReadOnlyRole || identity?.role !== 'admin') return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/threat-intel/sync', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
      });
      await loadThreatIntel();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const addThreatIntelFeed = async () => {
    if (isReadOnlyRole || identity?.role !== 'admin') return;
    if (!tiFeedName.trim() || !tiFeedURL.trim()) return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/threat-intel/feeds', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ name: tiFeedName.trim(), url: tiFeedURL.trim(), enabled: tiFeedEnabled }),
      });
      setTiFeedName('');
      setTiFeedURL('');
      setTiFeedEnabled(true);
      await loadThreatIntel();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const toggleThreatIntelFeed = async (f: ThreatIntelFeed) => {
    if (isReadOnlyRole || identity?.role !== 'admin') return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/threat-intel/feeds', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ ...f, enabled: !f.enabled }),
      });
      await loadThreatIntel();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteThreatIntelFeed = async (id: number) => {
    if (isReadOnlyRole || identity?.role !== 'admin') return;
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/threat-intel/feeds/${id}`, {
        method: 'DELETE',
        headers: { 'X-CSRF-Token': csrf },
      });
      await loadThreatIntel();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const threatIntelBlockIP = async (ip: string) => {
    if (isReadOnlyRole || identity?.role !== 'admin') return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/threat-intel/actions/block', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ ip, reason: 'manual from threat intel' }),
      });
      await Promise.all([loadThreatIntel(), refresh()]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const threatIntelAllowIP = async (ip: string, reason = 'manual allow') => {
    if (isReadOnlyRole || identity?.role !== 'admin') return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/threat-intel/actions/allow', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ ip, reason }),
      });
      await Promise.all([loadThreatIntel(), refresh()]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const threatIntelUnallowIP = async (ip: string) => {
    if (isReadOnlyRole || identity?.role !== 'admin') return;
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/threat-intel/actions/unallow', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ ip }),
      });
      await loadThreatIntel();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const addThreatIntelAllow = async () => {
    if (!tiAllowIP.trim()) return;
    await threatIntelAllowIP(tiAllowIP.trim(), tiAllowReason.trim() || 'manual allow');
    setTiAllowIP('');
    setTiAllowReason('');
  };

  const openThreatIntelTargets = async (ip: string) => {
    setLoading(true);
    setError('');
    try {
      const out = await api<{ items: ThreatIntelTarget[] }>(`/api/v1/threat-intel/matches/${encodeURIComponent(ip)}/targets?hours=${encodeURIComponent(String(tiHours))}&limit=500`);
      setTiTargetsIP(ip);
      setTiTargets(out.items || []);
      setTiTargetsOpen(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const openThreatIntelBlocked = async () => {
    setLoading(true);
    setError('');
    try {
      const out = await api<ThreatIntelBlockedPage>(`/api/v1/threat-intel/blocked?hours=${encodeURIComponent(String(tiHours))}&q=${encodeURIComponent(tiQuery)}&page=1&pageSize=500`);
      setTiBlocked(out.items || []);
      setTiTotalBlocked(Number(out.total || 0));
      setTiBlockedOpen(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const tiTotalCurrent = tiView === 'events' ? tiTotalMatches : tiTotalOffenders;
  const tiPageCount = Math.max(1, Math.ceil(Math.max(0, tiTotalCurrent) / Math.max(1, tiPageSize)));
  const tabTitle: Record<Tab, string> = {
    dashboard: 'Dashboard',
    metricCenter: 'Metric Center',
    audit: 'Log Center',
    domains: 'Domains',
    hosts: 'Subdomains',
    threatIntel: 'Threat Intel',
    ssh: 'SSH Bastion',
    backup: 'Backup Center',
    settings: 'Settings',
    users: 'Users',
    api: 'API Management',
    account: 'My Account',
    accessControl: 'Access Control',
    integrations: 'Integrations',
    help: 'Help & Support',
  };

  return (
    <>
      {identity ? (
      <div className="app-shell">
        <aside className="sidebar">
          <div className="logo" title="DomNexDomain">
            <img src="/logo.png" alt="DomNexDomain" />
          </div>
          <nav className="menu">
            <div className="menu-group">
              <div className="menu-title">Overview</div>
              <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}>Dashboard</button>
              <button className={tab === 'metricCenter' ? 'active' : ''} onClick={() => setTab('metricCenter')}>Metric Center</button>
              <button className={tab === 'audit' ? 'active' : ''} onClick={() => setTab('audit')}>Log Center</button>
            </div>
            <div className="menu-group">
              <div className="menu-title">Edge Routing</div>
              <button className={tab === 'domains' ? 'active' : ''} onClick={() => setTab('domains')}>Domains</button>
              <button className={tab === 'hosts' ? 'active' : ''} onClick={() => setTab('hosts')}>Subdomains</button>
              {(identity?.role === 'admin' || isReadOnlyRole) ? <button className={tab === 'ssh' ? 'active' : ''} onClick={() => setTab('ssh')}>SSH Bastion</button> : null}
            </div>
            <div className="menu-group">
              <div className="menu-title">Security</div>
              <button className={tab === 'threatIntel' ? 'active' : ''} onClick={() => setTab('threatIntel')}>Threat Intel</button>
              <button className={tab === 'accessControl' ? 'active' : ''} onClick={() => setTab('accessControl')}>Access Control</button>
              {(identity?.role === 'admin' || isReadOnlyRole) ? <button className={tab === 'api' ? 'active' : ''} onClick={() => setTab('api')}>API Management</button> : null}
            </div>
            <div className="menu-group">
              <div className="menu-title">Identity</div>
              {(identity?.role === 'admin' || isReadOnlyRole) ? <button className={tab === 'users' ? 'active' : ''} onClick={() => setTab('users')}>Users</button> : null}
              <button className={tab === 'account' ? 'active' : ''} onClick={() => setTab('account')}>My Account</button>
            </div>
            <div className="menu-group">
              <div className="menu-title">Operations</div>
              {(identity?.role === 'admin' || isReadOnlyRole) ? <button className={tab === 'backup' ? 'active' : ''} onClick={() => setTab('backup')}>Backup Center</button> : null}
              {(identity?.role === 'admin' || isReadOnlyRole) ? <button className={tab === 'settings' ? 'active' : ''} onClick={() => setTab('settings')}>Settings</button> : null}
              <button className={tab === 'integrations' ? 'active' : ''} onClick={() => setTab('integrations')}>Integrations</button>
            </div>
            <div className="menu-group">
              <button className={tab === 'help' ? 'active' : ''} onClick={() => setTab('help')}>Help &amp; Support</button>
            </div>
          </nav>
        </aside>

        <main className="main">
          <header className="top">
            <div>
              <h1>{tabTitle[tab] || 'DomNexDomain'}</h1>
              <p className="subtitle">{domains.length} Domains · {hosts.length} Subdomains</p>
            </div>
            <div className="top-actions">
              <button className="btn" onClick={refresh} disabled={loading}>Refresh</button>
              {tab === 'dashboard' ? (
                !dashboardEditMode ? (
                  <button className="btn" onClick={startDashboardEdit} disabled={loading}>Edit Dashboard</button>
                ) : (
                  <button className="btn" onClick={saveDashboardLayout} disabled={loading}>Save Dashboard</button>
                )
              ) : null}
              {identity ? <button className="btn" onClick={logout}>Logout</button> : null}
            </div>
          </header>

          {error ? <div className="error">{error}</div> : null}

          {tab === 'dashboard' ? (
            <section className="dashboard">
              <div className="card" style={{ marginBottom: '.75rem' }}>
                <div className="card-head">
                  <h3>Dashboard Tabs</h3>
                  <div className="row" style={{ marginBottom: 0 }}>
                    {dashboardEditMode ? <button className="btn danger" onClick={cancelDashboardEdit} disabled={loading}>Cancel</button> : null}
                  </div>
                </div>
                <div className="wizard-steps" style={{ marginBottom: '.45rem' }}>
                  {(dashboardEditMode ? dashboardDraft.tabs : dashboardLayout.tabs).map((t) => (
                    <button key={`dt-${t.id}`} className={dashboardTabID === t.id ? 'wiz active' : 'wiz'} onClick={() => setDashboardTabID(t.id)}>
                      {t.name}
                    </button>
                  ))}
                </div>
                {dashboardEditMode ? (
                  <div className="field-grid">
                    <div className="field">
                      <label>New Tab</label>
                      <div className="row" style={{ marginBottom: 0 }}>
                        <input value={dashboardNewTabName} onChange={(e) => setDashboardNewTabName(e.target.value)} placeholder="Operations" />
                        <button className="btn" onClick={addDashboardTab}>Add Tab</button>
                      </div>
                    </div>
                    {currentDashboardTab ? (
                      <div className="field">
                        <label>Rename Current Tab</label>
                        <div className="row" style={{ marginBottom: 0 }}>
                          <input value={currentDashboardTab.name} onChange={(e) => renameDashboardTab(currentDashboardTab.id, e.target.value)} />
                          <button className="btn danger" onClick={() => deleteDashboardTab(currentDashboardTab.id)} disabled={dashboardDraft.tabs.length <= 1}>Delete Tab</button>
                        </div>
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>

              {dashboardEditMode ? (
                <div className="dashboard-editor-layout">
                  <div className="card">
                    <div className="card-head"><h3>Widget Store</h3></div>
                    <div className="row">
                      <input value={dashboardWidgetQuery} onChange={(e) => setDashboardWidgetQuery(e.target.value)} placeholder="Search widgets" />
                    </div>
                    <div className="event-list" style={{ maxHeight: '68vh' }}>
                      {dashboardStoreCategories.map((cat) => {
                        const items = dashboardStoreItems.filter((w) => w.category === cat);
                        if (items.length === 0) return null;
                        return (
                          <div key={`store-${cat}`}>
                            <div className="menu-title" style={{ paddingLeft: 0 }}>{cat}</div>
                            {items.map((w) => (
                              <div className="event-item" key={`store-item-${w.type}`}>
                                <div className="event-top">
                                  <strong>{w.title}</strong>
                                  <button className="btn" onClick={() => addWidgetToCurrentDashboardTab(w.type)} disabled={!currentDashboardTab}>Add</button>
                                </div>
                                <div className="muted">{w.description}</div>
                              </div>
                            ))}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                  <div className="card">
                    <div className="card-head"><h3>Grid Preview</h3></div>
                    {currentDashboardTab ? (
                      <div className="dashboard-grid">
                        {currentDashboardTab.widgets.map((w, idx) => {
                          const meta = dashboardWidgetByType[w.type];
                          return (
                            <section key={w.id} className="card dashboard-widget" style={{ gridColumn: `span ${Math.max(3, Math.min(12, w.w))}`, gridRow: `span ${Math.max(1, Math.min(3, w.h))}` }}>
                              <div className="card-head">
                                <h3>{meta?.title || w.type}</h3>
                                <div className="row" style={{ marginBottom: 0 }}>
                                  <button className="btn" onClick={() => moveDashboardWidget(w.id, -1)} disabled={idx <= 0}>↑</button>
                                  <button className="btn" onClick={() => moveDashboardWidget(w.id, 1)} disabled={idx >= currentDashboardTab.widgets.length - 1}>↓</button>
                                  <select value={`${w.w}x${w.h}`} onChange={(e) => {
                                    const [nw, nh] = (e.target.value || '6x1').split('x');
                                    resizeDashboardWidget(w.id, Number(nw) || 6, Number(nh) || 1);
                                  }}>
                                    <option value="3x1">S (3x1)</option>
                                    <option value="6x1">M (6x1)</option>
                                    <option value="6x2">M Tall (6x2)</option>
                                    <option value="12x1">L (12x1)</option>
                                    <option value="12x2">XL (12x2)</option>
                                  </select>
                                  <button className="btn danger" onClick={() => removeDashboardWidget(w.id)}>Remove</button>
                                </div>
                              </div>
                              {renderDashboardWidget(w)}
                            </section>
                          );
                        })}
                        {currentDashboardTab.widgets.length === 0 ? <div className="muted">No widgets in this tab yet. Add from Widget Store.</div> : null}
                      </div>
                    ) : <div className="muted">No dashboard tab selected.</div>}
                  </div>
                </div>
              ) : (
                <>
                  {currentDashboardTab ? (
                    <div className="dashboard-grid">
                      {currentDashboardTab.widgets.map((w) => {
                        const meta = dashboardWidgetByType[w.type];
                        return (
                          <section key={w.id} className="card dashboard-widget" style={{ gridColumn: `span ${Math.max(3, Math.min(12, w.w))}`, gridRow: `span ${Math.max(1, Math.min(3, w.h))}` }}>
                            <div className="card-head"><h3>{meta?.title || w.type}</h3></div>
                            {renderDashboardWidget(w)}
                          </section>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="card"><div className="muted">No dashboard tab configured.</div></div>
                  )}
                </>
              )}
            </section>
          ) : null}

          {tab === 'metricCenter' ? (
            <section className="entity-page metric-center-page">
              <div className="entity-main">
                <section className="card">
                  <div className="card-head"><h3>MetricCenter v2</h3></div>
                  <div className="row">
                    <select value={metricHostFilter} onChange={(e) => setMetricHostFilter(e.target.value)}>
                      <option value="all">All Subdomains</option>
                      {hosts.map((h) => (
                        <option key={h.id} value={String(h.id)}>{h.fqdn}</option>
                      ))}
                    </select>
                    <select value={String(metricHours)} onChange={(e) => setMetricHours(Number(e.target.value) || 24)}>
                      <option value="1">Last 1h</option>
                      <option value="6">Last 6h</option>
                      <option value="24">Last 24h</option>
                      <option value="168">Last 7d</option>
                    </select>
                    <select value={metricClass} onChange={(e) => setMetricClass(e.target.value as 'all' | 'human' | 'crawler' | 'unknown')}>
                      <option value="all">All Traffic</option>
                      <option value="human">Human</option>
                      <option value="crawler">Crawler</option>
                      <option value="unknown">Unknown UA</option>
                    </select>
                    <select value={metricCountryFocus} onChange={(e) => setMetricCountryFocus(e.target.value)}>
                      <option value="all">All Countries</option>
                      {metricCountries.slice(0, 50).map((c) => (
                        <option key={`mcc-${c.country}`} value={(c.country || '').toUpperCase()}>{(c.country || 'ZZ').toUpperCase()}</option>
                      ))}
                    </select>
                    <button className="btn" onClick={() => setMetricMapOpen(true)}>Open Geo Map</button>
                    <button className="btn" onClick={loadMetricCenter} disabled={loading}>Refresh</button>
                  </div>
                  <div className="ops-alert-strip">
                    <AlertChip label="Error Rate" value={`${metricErrRatePct}%`} state={metricErrRatePct >= 12 ? 'critical' : metricErrRatePct >= 6 ? 'warn' : 'ok'} />
                    <AlertChip label="5xx Rate" value={`${metric5xxRatePct}%`} state={metric5xxRatePct >= 5 ? 'critical' : metric5xxRatePct >= 2 ? 'warn' : 'ok'} />
                    <AlertChip label="Block Rate" value={`${metricBlockRatePct}%`} state={metricBlockRatePct >= 25 ? 'critical' : metricBlockRatePct >= 10 ? 'warn' : 'ok'} />
                    <AlertChip label="Spike Score" value={`${trafficSpikeScore}%`} state={trafficSpikeScore >= 220 ? 'critical' : trafficSpikeScore >= 140 ? 'warn' : 'ok'} />
                    <AlertChip label="Top Country" value={(topCountry?.country || 'ZZ').toUpperCase()} state="ok" />
                    <AlertChip label="HA Degraded" value={String(haHostsDegraded)} state={haHostsDegraded > 0 ? 'critical' : 'ok'} />
                  </div>
                </section>

                <section className="metric-v2-layout">
                  <section className="card metric-v2-panel">
                    <div className="card-head"><h3>Geo Intelligence Summary</h3></div>
                    <div className="muted">Use `Open Geo Map` for full world view and country-click filtering.</div>
                    <div className="metric-grid" style={{ marginTop: '.6rem' }}>
                      <MetricTile label="Requests" value={String(metricTotalRequests)} hint="Within selected time window" />
                      <MetricTile label="Blocked" value={String(metricTotalBlocked)} hint="Geo/Auth/Policy blocked requests" />
                      <MetricTile label="Traffic Out" value={formatBytes(metricTotalBytesOut)} hint="Response bytes" />
                      <MetricTile label="Success Rate" value={`${metricSuccessRatePct}%`} hint="2xx across selected scope" />
                    </div>
                  </section>

                  <section className="card metric-v2-panel">
                    <div className="card-head"><h3>Country Focus</h3></div>
                    {metricFilteredCountries.length === 0 ? (
                      <div className="muted">No traffic data for this filter yet.</div>
                    ) : (
                      <div className="event-list metric-scroll">
                        {metricFilteredCountries.map((c) => {
                          const pct = Math.max(1, Math.round(((c.requests || 0) / metricTopReq) * 100));
                          return (
                            <div key={c.country} className="event-item">
                              <div className="event-top">
                                <strong>{(c.country || 'ZZ').toUpperCase()}</strong>
                                <span className="muted">{c.requests} req</span>
                              </div>
                              <div style={{ height: 8, borderRadius: 8, background: '#0f1117', border: '1px solid #2a2a35', overflow: 'hidden' }}>
                                <div style={{ width: `${pct}%`, height: '100%', background: 'linear-gradient(90deg,#0ea5e9,#22c55e)' }} />
                              </div>
                              <div className="muted" style={{ marginTop: '.3rem' }}>
                                2xx: {c.status2xx || 0} · 3xx: {c.status3xx || 0} · 4xx: {c.status4xx || 0} · 5xx: {c.status5xx || 0} · blocked: {c.blocked || 0}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </section>

                  <section className="card metric-v2-panel">
                    <div className="card-head"><h3>Problems Now</h3></div>
                    <div className="log-table-wrap metric-table-wrap">
                      <table className="log-table metric-problem-table">
                        <thead>
                          <tr>
                            <th>Severity</th>
                            <th>Issue</th>
                            <th>Signal</th>
                            <th>Detail</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {metricProblemsSorted.map((p) => (
                            <tr key={p.id}>
                              <td><span className={`badge ${p.severity === 'critical' ? 'err' : p.severity === 'warn' ? 'warn' : 'ok'}`}>{p.severity.toUpperCase()}</span></td>
                              <td>{p.issue}</td>
                              <td><strong>{p.value}</strong></td>
                              <td className="muted">{p.detail}</td>
                              <td><button className="btn" onClick={p.action}>{p.actionLabel}</button></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="muted" style={{ marginTop: '.45rem' }}>
                      Top blocked country: {(topBlockedCountry?.country || 'ZZ').toUpperCase()} · {topBlockedCountry?.blocked || 0} blocked
                    </div>
                </section>
                </section>
              </div>
              <aside className="entity-side">
                <section className="card">
                  <div className="card-head"><h3>Top Countries</h3></div>
                  {(metricCountries.slice(0, 8)).map((c) => (
                    <div key={`top-${c.country}`} className="host">
                      <div>
                        <strong>{(c.country || 'ZZ').toUpperCase()}</strong>
                        <div className="muted">{Math.round(((c.requests || 0) / Math.max(1, metricCountryOverview?.totalRequests || 1)) * 100)}%</div>
                      </div>
                      <div className="muted">{c.requests}</div>
                    </div>
                  ))}
                  {metricCountries.length === 0 ? <div className="muted">No country data.</div> : null}
                </section>
                <section className="card">
                  <div className="card-head"><h3>Audit Snapshot</h3></div>
                  <div className="metric-grid">
                    <MetricTile label="Critical" value={String(auditCriticalTotal)} hint="Deletes, resets, revokes" />
                    <MetricTile label="Warnings" value={String(auditWarningTotal)} hint="Updates, retries, proxy issues" />
                    <MetricTile label="Info" value={String(auditInfoTotal)} hint="Read/list/login events" />
                    <MetricTile label="Unique Actors" value={String(auditActorsTotal)} hint="Across retained audit data" />
                  </div>
                </section>
                {metricUnknownTotal > 0 ? (
                  <section className="card">
                    <div className="card-head"><h3>ZZ Breakdown</h3></div>
                    <div className="muted" style={{ marginBottom: '.45rem' }}>
                      Unknown country traffic: <strong>{metricUnknownTotal}</strong> requests
                    </div>
                    {metricUnknownBreakdown.length === 0 ? (
                      <div className="muted">No subdomain split available.</div>
                    ) : (
                      metricUnknownBreakdown.slice(0, 12).map((it) => (
                        <div key={`zz-${it.hostId}`} className="host">
                          <div>
                            <strong>{it.fqdn}</strong>
                            <div className="muted">{Math.round(((it.requests || 0) / Math.max(1, metricUnknownTotal)) * 100)}%</div>
                          </div>
                          <div className="muted">{it.requests}</div>
                        </div>
                      ))
                    )}
                  </section>
                ) : null}
                {identity?.role === 'admin' ? (
                  <section className="card">
                    <div className="card-head"><h3>Security Actions</h3></div>
                    <div className="row">
                      <input value={resetUser} onChange={(e) => setResetUser(e.target.value)} placeholder="username" />
                      <input value={resetTTL} onChange={(e) => setResetTTL(e.target.value)} placeholder="30m" />
                      <button className="btn" onClick={createResetToken} disabled={loading}>Create Reset Token</button>
                    </div>
                    {resetToken ? (
                      <div className="card" style={{ marginBottom: 0 }}>
                        <div className="muted">Password reset token (time-limited):</div>
                        <pre>{resetToken}</pre>
                        <div className="row" style={{ marginTop: '.55rem', marginBottom: 0 }}>
                          <input value={resetNewPassword} onChange={(e) => setResetNewPassword(e.target.value)} placeholder="new password" />
                          <button className="btn" onClick={consumeResetToken} disabled={!resetNewPassword || loading}>Consume Token</button>
                        </div>
                      </div>
                    ) : null}
                  </section>
                ) : null}
              </aside>
            </section>
          ) : null}

          {tab === 'threatIntel' ? (
            <section className="entity-page threatintel-page">
              <div className="entity-main">
                <section className="card">
                  <div className="card-head">
                    <h3>Threat Data</h3>
                    <div className="row" style={{ marginBottom: 0 }}>
                      <button className="btn" onClick={() => setTiAllowOpen(true)}>Allowlist</button>
                      <button className="btn danger" onClick={openThreatIntelBlocked}>Blocked ({tiTotalBlocked})</button>
                    </div>
                  </div>
                  <div className="row">
                    <div className="wizard-steps" style={{ marginBottom: 0 }}>
                      <button className={tiView === 'events' ? 'wiz active' : 'wiz'} onClick={() => setTiView('events')}>Events</button>
                      <button className={tiView === 'offenders' ? 'wiz active' : 'wiz'} onClick={() => setTiView('offenders')}>Offenders</button>
                    </div>
                    <select value={String(tiHours)} onChange={(e) => setTiHours(Number(e.target.value) || 24)}>
                      <option value="1">Last 1h</option>
                      <option value="6">Last 6h</option>
                      <option value="24">Last 24h</option>
                      <option value="168">Last 7d</option>
                    </select>
                    <select value={String(tiPageSize)} onChange={(e) => setTiPageSize(Math.max(25, Number(e.target.value) || 100))}>
                      <option value="50">50 / page</option>
                      <option value="100">100 / page</option>
                      <option value="250">250 / page</option>
                      <option value="500">500 / page</option>
                    </select>
                    {tiView === 'events' ? (
                      <select value={tiDecision} onChange={(e) => setTiDecision(e.target.value)}>
                        <option value="all">All decisions</option>
                        <option value="monitor_observe">Monitor</option>
                        <option value="soft_block_set">Soft block set</option>
                        <option value="soft_block_active">Soft block active</option>
                        <option value="hard_block_set">Hard block set</option>
                        <option value="hard_block_permanent">Hard block active</option>
                      </select>
                    ) : null}
                    <input value={tiQuery} onChange={(e) => setTiQuery(e.target.value)} placeholder="Search ip/host/path/feed/country" />
                  </div>
                  <div className="muted" style={{ marginBottom: '.55rem' }}>
                    Showing page {tiPage} / {tiPageCount} · total records: {tiTotalCurrent} · Events: repeated IPs only (hits {'>='} {tiConfig.eventMinHits || 2}, {'<'} {tiConfig.offenderMinHits || 10}) · Offenders: burst offenders (hits {'>='} {tiConfig.offenderMinHits || 10}) · Tiering: XP + Level + State
                  </div>
                  <div className="log-table-wrap">
                    {tiView === 'events' ? (
                      <table className="log-table">
                        <thead>
                          <tr>
                            <th>Last Seen</th>
                            <th>IP</th>
                            <th>Decision</th>
                            <th>Hits</th>
                            <th className="ti-tier-col">Tier</th>
                            <th className="ti-feed-col">Feed</th>
                            <th>Targets</th>
                            <th>Country</th>
                            <th>Trace</th>
                            <th>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {tiMatches.length === 0 ? (
                            <tr><td colSpan={10} className="muted">No repeated threat events in current filter.</td></tr>
                          ) : tiMatches.map((m) => (
                            <tr key={`ti-match-${m.id}`}>
                              <td>{new Date(m.lastSeenAt).toLocaleString()}</td>
                              <td><code>{m.ip}</code></td>
                              <td><span className={`badge ${threatDecisionBadge(m.decision).cls}`}>{threatDecisionBadge(m.decision).label}</span></td>
                              <td>{m.hits}</td>
                              <td className="ti-tier-col"><span className={`badge ${m.riskState === 'hardblock' ? 'err' : m.riskState === 'softblock' ? 'warn' : 'ok'}`}>{(m.tier || 'tier0').toUpperCase()} · L{m.level || 0} · XP {m.xp || 0}</span></td>
                              <td className="ti-feed-col">{m.feed}</td>
                              <td>
                                <button className="btn" onClick={() => openThreatIntelTargets(m.ip)} disabled={loading}>
                                  View ({m.targetCount || 0})
                                </button>
                              </td>
                              <td>{m.country || 'ZZ'}</td>
                              <td><code>{m.lastTraceId || '-'}</code></td>
                              <td>
                                <div className="row" style={{ marginBottom: 0 }}>
                                  <button className="btn danger" onClick={() => threatIntelBlockIP(m.ip)} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Block</button>
                                  <button className="btn" onClick={() => threatIntelAllowIP(m.ip, 'allow from threat events')} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Allow</button>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <table className="log-table">
                        <thead>
                          <tr>
                            <th>IP</th>
                            <th>Hits</th>
                            <th>Feeds</th>
                            <th>Hosts</th>
                            <th>Decision</th>
                            <th className="ti-tier-col">Tier</th>
                            <th>Last Seen</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {tiOffenders.length === 0 ? (
                            <tr><td colSpan={8} className="muted">No burst offenders ({'>='}{tiConfig.offenderMinHits || 10} hits) in current filter.</td></tr>
                          ) : tiOffenders.map((o) => (
                            <tr key={`ti-off-${o.ip}`}>
                              <td><code>{o.ip}</code></td>
                              <td>{o.totalHits}</td>
                              <td>{o.distinctFeeds}</td>
                              <td>{o.distinctHosts}</td>
                              <td>
                                <div className="row" style={{ marginBottom: 0 }}>
                                  {threatDecisionList(o.decisions).map((d) => {
                                    const b = threatDecisionBadge(d);
                                    return <span key={`${o.ip}-${d}`} className={`badge ${b.cls}`}>{b.label}</span>;
                                  })}
                                </div>
                              </td>
                              <td className="ti-tier-col"><span className={`badge ${o.riskState === 'hardblock' ? 'err' : o.riskState === 'softblock' ? 'warn' : 'ok'}`}>{(o.tier || 'tier0').toUpperCase()} · L{o.level || 0} · XP {o.xp || 0}</span></td>
                              <td>{new Date(o.lastSeenAt).toLocaleString()}</td>
                              <td>
                                <div className="row" style={{ marginBottom: 0 }}>
                                  <button className="btn danger" onClick={() => threatIntelBlockIP(o.ip)} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Block</button>
                                  <button className="btn" onClick={() => threatIntelAllowIP(o.ip, 'allow from offender list')} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Allow</button>
                                  {o.allowlisted ? <span className="badge ok">allowlisted</span> : null}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                  <div className="row" style={{ marginTop: '.6rem', marginBottom: 0 }}>
                    <button className="btn" onClick={() => setTiPage((p) => Math.max(1, p - 1))} disabled={tiPage <= 1}>Prev</button>
                    <button className="btn" onClick={() => setTiPage((p) => Math.min(tiPageCount, p + 1))} disabled={tiPage >= tiPageCount}>Next</button>
                    <button className="btn" onClick={loadThreatIntel} disabled={loading}>Refresh</button>
                  </div>
                </section>
              </div>
            </section>
          ) : null}

          {tab === 'domains' ? (
            <section className="entity-page">
              <div className="entity-main">
                {isReadOnlyRole ? (
                  <section className="card">
                    <div className="muted">Read-only mode: domain create, deactivate, and delete actions are disabled.</div>
                  </section>
                ) : null}
                <section className="card">
                  <div className="card-head"><h3>Domain Wizard</h3></div>
                  <div className="wizard-steps">
                    <button className={domainWizardStep === 1 ? 'wiz active' : 'wiz'} onClick={() => setDomainWizardStep(1)} disabled={isReadOnlyRole}>1. Basics</button>
                    <button className={domainWizardStep === 2 ? 'wiz active' : 'wiz'} onClick={() => setDomainWizardStep(2)} disabled={isReadOnlyRole}>2. DNS Guide</button>
                    <button className={domainWizardStep === 3 ? 'wiz active' : 'wiz'} onClick={() => setDomainWizardStep(3)} disabled={isReadOnlyRole}>3. Auto Checks</button>
                  </div>

                  {domainWizardStep === 1 ? (
                    <div className="card" style={{ marginBottom: '.8rem' }}>
                      <div className="row">
                        <input value={domainName} onChange={(e) => setDomainName(e.target.value.toLowerCase().trim())} placeholder="example.com" />
                        <select value={domainProvider} onChange={(e) => setDomainProvider(e.target.value as DomainProvider)}>
                          <option value="cloudflare">Cloudflare (automatic)</option>
                          <option value="strato">Strato (manual)</option>
                          <option value="manual">Other provider (manual)</option>
                        </select>
                        {domainProvider === 'cloudflare' ? (
                          <input value={domainZoneID} onChange={(e) => setDomainZoneID(e.target.value.trim())} placeholder="Cloudflare Zone ID (optional, Auto-Resolve per Domain)" />
                        ) : null}
                        <button className="btn" onClick={() => setDomainWizardStep(2)} disabled={isReadOnlyRole || !domainName}>Next</button>
                      </div>
                      <div className="muted">Admin endpoint will be: <strong>{adminPreview}</strong></div>
                    </div>
                  ) : null}

                  {domainWizardStep === 2 ? (
                    <div className="card" style={{ marginBottom: '.8rem' }}>
                      <h4 style={{ marginTop: 0 }}>{domainProviderGuide[domainProvider].title}</h4>
                      <ol>
                        {domainProviderGuide[domainProvider].steps.map((step, idx) => <li key={idx}>{step}</li>)}
                      </ol>
                      <div className="muted">Recommended DNS records:</div>
                      <pre>{domainProviderGuide[domainProvider].records.join('\n')}</pre>
                      <div className="row">
                        <button className="btn" onClick={() => setDomainWizardStep(1)} disabled={isReadOnlyRole}>Back</button>
                        <button className="btn" onClick={() => { setDomainPreflight(null); setDomainWizardStep(3); }} disabled={isReadOnlyRole || !domainName}>Next</button>
                      </div>
                    </div>
                  ) : null}

                  {domainWizardStep === 3 ? (
                    <div className="card" style={{ marginBottom: '.8rem' }}>
                      <h4 style={{ marginTop: 0 }}>Automatic preflight checks</h4>
                      <div className="muted" style={{ marginBottom: '.5rem' }}>
                        Checks run automatically every 4 seconds. You can create the domain only when all required checks are green.
                      </div>
                      {domainPreflight ? (
                        <div className="diag" style={{ marginBottom: '.5rem' }}>
                          {domainPreflight.checks.map((c) => (
                            <span key={c.name} className={`badge ${c.ok ? 'ok' : 'err'}`}>
                              {c.name}: {c.ok ? 'ok' : 'fail'}{c.detail ? ` (${c.detail})` : ''}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <div className="muted">Initializing preflight...</div>
                      )}
                      <div className="row">
                        <button className="btn" onClick={() => setDomainWizardStep(2)} disabled={isReadOnlyRole}>Back</button>
                        <button className="btn" onClick={saveDomain} disabled={isReadOnlyRole || loading || !domainPreflight?.ready}>Create Domain</button>
                      </div>
                    </div>
                  ) : null}
                </section>

                <section className="card">
                  <div className="card-head"><h3>Configured Domains</h3></div>
                  {domains.map((d) => (
                    <div className="card" key={d.id} style={{ marginBottom: '.6rem' }}>
                      <div className="host" style={{ borderTop: 'none', paddingTop: 0 }}>
                        <div>
                          <strong>{d.name}</strong> <span className="muted">({d.dnsMode || '-'} / {d.provider || '-'})</span>
                          <div className="diag" style={{ marginTop: '.25rem' }}>
                            <span className={`badge ${domainStatusBadge(d.status).cls}`}>Domain {domainStatusBadge(d.status).label}</span>
                            <span className={`badge ${domainWildcardBadge(d).cls}`}>Wildcard {domainWildcardBadge(d).label}</span>
                          </div>
                          {d.zoneId ? <div className="muted">zone: {d.zoneId}</div> : null}
                        </div>
                        <div className="row" style={{ marginBottom: 0 }}>
                          <button className="btn" onClick={() => runDomainLiveCheck(d.id)} disabled={loading}>Live Check</button>
                          <button className="btn" onClick={() => deactivateDomain(d)} disabled={isReadOnlyRole || loading || (d.status || '').toLowerCase() === 'inactive'}>Deactivate</button>
                          <button className="btn danger" onClick={() => deleteDomain(d.id)} disabled={isReadOnlyRole || loading}>Delete</button>
                        </div>
                      </div>
                      {domainChecks[d.id] ? (
                        <div className="diag-block">
                          <div className="diag">
                            <span className={`badge ${domainChecks[d.id].overallOk ? 'ok' : 'warn'}`}>Overall {domainChecks[d.id].overallOk ? 'OK' : 'Issues'}</span>
                            <span className={`badge ${domainChecks[d.id].apexDnsOk ? 'ok' : 'err'}`}>Apex DNS {domainChecks[d.id].apexDnsOk ? 'ok' : 'fail'}</span>
                            <span className={`badge ${domainChecks[d.id].apexPointsToServer ? 'ok' : 'warn'}`}>Points to server {domainChecks[d.id].apexPointsToServer ? 'yes' : 'no'}</span>
                            {d.dnsMode === 'cloudflare' ? (
                              <span className={`badge ${domainChecks[d.id].cloudflareApiOk ? 'ok' : 'err'}`}>Cloudflare API {domainChecks[d.id].cloudflareApiOk ? 'ok' : 'fail'}</span>
                            ) : null}
                          </div>
                          {domainChecks[d.id].serverIpv4 ? <div className="muted">Detected Server IPv4: {domainChecks[d.id].serverIpv4}</div> : null}
                          {domainChecks[d.id].warnings?.length ? <div className="muted">{domainChecks[d.id].warnings?.join(' | ')}</div> : null}
                          {domainChecks[d.id].cloudflareError ? <div className="errtxt">{domainChecks[d.id].cloudflareError}</div> : null}
                          <pre>{JSON.stringify(domainChecks[d.id].hosts, null, 2)}</pre>
                        </div>
                      ) : null}
                    </div>
                  ))}
                </section>
              </div>
              <aside className="entity-side">
                <section className="card">
                  <div className="card-head"><h3>Domain Stats</h3></div>
                  <div className="metric-grid">
                    <MetricTile label="Total Domains" value={String(domains.length)} hint="Configured zones" />
                    <MetricTile label="Cloudflare" value={String(cloudflareDomains)} hint="API-managed DNS" />
                    <MetricTile label="Manual DNS" value={String(manualDomains)} hint="Provider-side records" />
                    <MetricTile label="Checked Domains" value={String(domainsChecked)} hint="Live-check executed" />
                    <MetricTile label="Check Issues" value={String(domainsWithIssues)} hint="From latest checks" />
                  </div>
                </section>
                <section className="card">
                  <div className="card-head"><h3>Quick Guidance</h3></div>
                  <div className="muted">Provider: <strong>{domainProviderGuide[domainProvider].title}</strong></div>
                  <div className="muted" style={{ marginTop: '.45rem' }}>Configured admin endpoint:</div>
                  <pre>{configuredAdminFQDN || '<not configured in Settings>'}</pre>
                  <div className="muted" style={{ marginTop: '.45rem' }}>Tip: run a live check after DNS changes to update health badges.</div>
                </section>
              </aside>
            </section>
          ) : null}

          {tab === 'hosts' ? (
            selectedHost ? (
              <section className="entity-page">
                <div className="entity-main">
                  {isReadOnlyRole ? (
                    <section className="card">
                      <div className="muted">Read-only mode: all subdomain modification actions are disabled.</div>
                    </section>
                  ) : null}
                  <section className="card cc-hero">
                    <div className="cc-head">
                      <div>
                        <h3>Subdomain Command Center</h3>
                        <div className="muted">Operational controls and security policy for this endpoint.</div>
                      </div>
                      <div className="top-actions">
                        <a className="btn ghost" href={`https://${selectedHost.fqdn}`} target="_blank" rel="noreferrer">Open Site</a>
                        <button className="btn" onClick={() => setSelectedHostID(null)}>Back To List</button>
                      </div>
                    </div>
                    <div className="cc-header-grid">
                      <div className="cc-title">
                        <strong>{selectedHost.fqdn}</strong>
                        <span className={`badge ${hostStateBadge(selectedHost.state).cls}`}>{hostStateBadge(selectedHost.state).label}</span>
                      </div>
                      <div className="cc-pills">
                        <span className={`cc-pill ${selectedHost.authEnabled ? 'ok' : ''}`}>Auth {selectedHost.authEnabled ? 'On' : 'Off'}</span>
                        <span className={`cc-pill ${selectedHost.haEnabled ? 'ok' : ''}`}>HA {selectedHost.haEnabled ? (selectedHost.haMode || 'failover') : 'Off'}</span>
                        <span className={`cc-pill ${selectedHost.state === 'maintenance' ? 'warn' : 'ok'}`}>Maintenance {selectedHost.state === 'maintenance' ? 'On' : 'Off'}</span>
                        <span className={`cc-pill ${selectedHost.insecureTls ? 'warn' : 'ok'}`}>TLS Verify {selectedHost.insecureTls ? 'Off' : 'On'}</span>
                        <span className={`cc-pill ${(selectedHost.geoMode || '') ? 'warn' : ''}`}>Geo {(selectedHost.geoMode || 'off').toUpperCase()}</span>
                      </div>
                    </div>
                    <div className="cc-kpi-strip">
                      <div className="cc-kpi">
                        <span>Requests (24h)</span>
                        <strong>{selectedHostTraffic ? String(selectedHostTraffic.requests || 0) : '-'}</strong>
                      </div>
                      <div className="cc-kpi">
                        <span>Unique Visitors</span>
                        <strong>{selectedHostTraffic ? String(selectedHostTraffic.uniqueVisitors || 0) : '-'}</strong>
                      </div>
                      <div className="cc-kpi">
                        <span>Traffic Out</span>
                        <strong>{selectedHostTraffic ? formatBytes(selectedHostTraffic.bytesOut || 0) : '-'}</strong>
                      </div>
                      <div className="cc-kpi">
                        <span>Blocked (24h)</span>
                        <strong>{selectedHostTraffic ? String(selectedHostTraffic.blocked || 0) : '-'}</strong>
                      </div>
                    </div>
                    <div className="cc-diag-inline">
                      {hostDiagnostics[selectedHost.fqdn] ? (
                        <div className="diag">
                          <span className={`badge ${hostDiagnostics[selectedHost.fqdn].dnsRecords?.length ? 'ok' : 'err'}`}>DNS {hostDiagnostics[selectedHost.fqdn].dnsRecords?.length ? 'ok' : 'fail'}</span>
                          {selectedHost.state === 'maintenance' ? (
                            <>
                              <span className="badge warn">HTTP MAINT</span>
                              <span className="badge warn">HTTPS MAINT</span>
                              <span className="badge warn">TLS MAINT</span>
                            </>
                          ) : (
                            <>
                              <span className={`badge ${hostDiagnostics[selectedHost.fqdn].httpStatus >= 200 && hostDiagnostics[selectedHost.fqdn].httpStatus < 400 ? 'ok' : 'warn'}`}>HTTP {hostDiagnostics[selectedHost.fqdn].httpStatus || '-'}</span>
                              <span className={`badge ${hostDiagnostics[selectedHost.fqdn].httpsStatus >= 200 && hostDiagnostics[selectedHost.fqdn].httpsStatus < 500 ? 'ok' : 'warn'}`}>HTTPS {hostDiagnostics[selectedHost.fqdn].httpsStatus || '-'}</span>
                              <span className={`badge ${hostDiagnostics[selectedHost.fqdn].tlsOk ? 'ok' : 'err'}`}>TLS {hostDiagnostics[selectedHost.fqdn].tlsOk ? 'ok' : 'fail'}</span>
                            </>
                          )}
                        </div>
                      ) : <div className="muted">Diagnostics initializing...</div>}
                    </div>
                  </section>
                  <div className="cc-section-label">Operations</div>
                  <section className="card cc-block cc-panel">
                    <div className="card-head"><h3>Routing Control</h3></div>
                    <div className="row">
                      <label className="check"><input type="checkbox" checked={detailHAEnabled} onChange={(e) => setDetailHAEnabled(e.target.checked)} /> Enable HA</label>
                    </div>
                    {detailHAEnabled ? (
                      <>
                        <div className="row">
                          <select value={detailHAMode} onChange={(e) => setDetailHAMode(e.target.value as 'failover' | 'round_robin')}>
                            <option value="failover">Failover</option>
                            <option value="round_robin">Load Balance (Round Robin)</option>
                          </select>
                      <button className="btn" type="button" onClick={addDetailBackend} disabled={isReadOnlyRole}>Add Backend</button>
                        </div>
                        {detailHABackends.map((b, idx) => (
                          <div className="row" key={`detail-ha-${idx}`}>
                            <input value={b.name} onChange={(e) => updateDetailBackend(idx, { name: e.target.value })} placeholder="Server name" />
                            <input value={b.url} onChange={(e) => updateDetailBackend(idx, { url: e.target.value })} placeholder="https://10.0.0.11:8443" />
                            <button className="btn danger" type="button" onClick={() => removeDetailBackend(idx)} disabled={isReadOnlyRole || detailHABackends.length <= 1}>Remove</button>
                          </div>
                        ))}
                        <div className="muted">Define backend name + address. Minimum 2 backends for HA.</div>
                      </>
                    ) : (
                      <div className="row">
                        <input value={detailUpstream} onChange={(e) => setDetailUpstream(e.target.value)} placeholder="https://127.0.0.1:3000" />
                      </div>
                    )}
                    <div className="row">
                      <label className="check"><input type="checkbox" checked={detailInsecureTLS} onChange={(e) => setDetailInsecureTLS(e.target.checked)} /> No TLS Verify</label>
                      <button className="btn" onClick={saveHostGeneral} disabled={isReadOnlyRole || detailSavingGeneral}>{detailSavingGeneral ? 'Saving...' : 'Save General'}</button>
                    </div>
                    <div className="muted">Use this section to adjust upstream routing for this specific subdomain.</div>
                  </section>

                  <div className="cc-section-label">Access & Security</div>
                  <div className="cc-split">
                    <section className="card cc-block cc-panel">
                      <div className="card-head"><h3>Auth Page Settings</h3></div>
                      <div className="row">
                        <label className="check"><input type="checkbox" checked={detailAuthEnabled} onChange={(e) => setDetailAuthEnabled(e.target.checked)} /> Enable Auth Page</label>
                      </div>
                      <div className="row">
                        <input value={detailAuthUser} onChange={(e) => setDetailAuthUser(e.target.value)} placeholder="Auth username (this host only)" />
                        <input type="password" value={detailAuthPass} onChange={(e) => setDetailAuthPass(e.target.value)} placeholder={selectedHost.authEnabled ? 'New password (leave empty = keep current)' : 'Auth password'} />
                        <button className="btn" onClick={saveHostAuth} disabled={isReadOnlyRole || detailSavingAuth}>{detailSavingAuth ? 'Saving...' : 'Save Auth'}</button>
                      </div>
                      <div className="muted">Credentials are dedicated to this single subdomain and are not shared with others.</div>
                    </section>

                    <section className="card cc-block cc-panel">
                      <div className="card-head"><h3>GeoIP Access Policy</h3></div>
                      <div className="row">
                        <select value={detailGeoMode} onChange={(e) => setDetailGeoMode(e.target.value as 'off' | 'allow' | 'deny')}>
                          <option value="off">Off</option>
                          <option value="allow">Allow List Countries</option>
                          <option value="deny">Deny List Countries</option>
                        </select>
                        <button className="btn" onClick={saveHostGeo} disabled={isReadOnlyRole || detailSavingGeo}>{detailSavingGeo ? 'Saving...' : 'Save Geo Policy'}</button>
                      </div>
                      {detailGeoMode !== 'off' ? (
                        <>
                          <div className="domain-pills">
                            {Object.entries(GEO_PRESETS).map(([label, codes]) => (
                              <button key={label} type="button" className="wiz" onClick={() => setDetailGeoCountries(codes.join(', '))} disabled={isReadOnlyRole}>{label}</button>
                            ))}
                            <button type="button" className="wiz" onClick={() => setDetailGeoCountries(mergeCountryCodes(detailGeoCountries, GEO_PRESETS.EU))} disabled={isReadOnlyRole}>+ EU</button>
                            <button type="button" className="wiz" onClick={() => setDetailGeoCountries('')} disabled={isReadOnlyRole}>Clear</button>
                          </div>
                          <div className="row">
                            <input
                              value={detailGeoCountries}
                              onChange={(e) => setDetailGeoCountries(e.target.value.toUpperCase())}
                              placeholder="Country codes, e.g. DE,AT,CH or US,CA"
                            />
                          </div>
                          <div className="muted">Use ISO country codes. Requests outside this policy are blocked before upstream/auth.</div>
                        </>
                      ) : (
                        <div className="muted">No country filtering. All countries are allowed.</div>
                      )}
                    </section>
                  </div>

                </div>
                <aside className="entity-side">
                  <section className="card cc-block cc-panel">
                    <div className="card-head"><h3>Subdomain Summary</h3></div>
                    <div className="metric-grid">
                      <MetricTile label="State" value={hostStateBadge(selectedHost.state).label} hint="Current lifecycle state" />
                      <MetricTile label="Auth Page" value={selectedHost.authEnabled ? 'enabled' : 'disabled'} hint="Per-host access gate" />
                      <MetricTile label="TLS Verify" value={selectedHost.insecureTls ? 'disabled' : 'enabled'} hint="Upstream certificate policy" />
                      <MetricTile label="Routing" value={selectedHost.haEnabled ? `HA (${selectedHost.haMode || 'failover'})` : 'Single Upstream'} hint="Proxy mode" />
                      <MetricTile label="Geo Policy" value={selectedHost.geoMode ? `${selectedHost.geoMode} (${(selectedHost.geoCountries || []).length})` : 'off'} hint="Country access filter" />
                    </div>
                  </section>
                  <section className="card cc-block cc-panel">
                    <div className="card-head"><h3>Traffic & Visits (24h)</h3></div>
                    {selectedHostTraffic ? (
                      <>
                        <div className="gauge-grid">
                          <Gauge title="2xx Rate" value={hostTraffic2xxRate} subtitle={`${selectedHostTraffic.status2xx || 0}/${hostTrafficReq} requests`} />
                          <Gauge title="4xx/5xx Rate" value={hostTrafficErrRate} subtitle={`${(selectedHostTraffic.status4xx || 0) + (selectedHostTraffic.status5xx || 0)} errors`} />
                          <Gauge title="Geo Block Rate" value={hostTrafficBlockRate} subtitle={`${selectedHostTraffic.blocked || 0} blocked`} />
                          <Gauge title="Visitor Ratio" value={hostVisitorRatio} subtitle={`${selectedHostTraffic.uniqueVisitors || 0} unique visitors`} />
                        </div>
                        <div className="metric-grid" style={{ marginTop: '.8rem' }}>
                          <MetricTile label="Requests" value={String(selectedHostTraffic.requests || 0)} hint="Total requests in 24h" />
                          <MetricTile label="Traffic Out" value={formatBytes(selectedHostTraffic.bytesOut || 0)} hint="Response bytes in 24h" />
                        </div>
                      </>
                    ) : (
                      <div className="muted">No traffic stats yet. Generate traffic and refresh.</div>
                    )}
                  </section>
                  <section className="card cc-danger">
                    <div className="card-head"><h3>Danger Zone</h3></div>
                    <div className="row">
                      <button className="btn" onClick={() => setHostMaintenance(selectedHost.id, selectedHost.state !== 'maintenance')} disabled={isReadOnlyRole || loading}>
                        {selectedHost.state === 'maintenance' ? 'Disable Maintenance' : 'Enable Maintenance'}
                      </button>
                      <button className="btn" onClick={() => setHostDisabled(selectedHost.id, selectedHost.state !== 'disabled')} disabled={isReadOnlyRole || loading}>
                        {selectedHost.state === 'disabled' ? 'Enable Host' : 'Disable Host'}
                      </button>
                      {selectedHost.state === 'error' ? <button className="btn" onClick={() => retryHost(selectedHost.id)} disabled={isReadOnlyRole}>Retry</button> : null}
                      <button className="btn danger" onClick={() => openDeleteHostDialog(selectedHost)} disabled={isReadOnlyRole || loading}>Delete Subdomain</button>
                    </div>
                  </section>
                </aside>
              </section>
            ) : (
              <section className="entity-page">
                <div className="entity-main">
                  {isReadOnlyRole ? (
                    <section className="card">
                      <div className="muted">Read-only mode: subdomain creation and state changes are disabled.</div>
                    </section>
                  ) : null}
                  <section className="card">
                    <div className="card-head"><h3>Subdomain Wizard</h3></div>
                    <div className="wizard-steps">
                      <button className={hostWizardStep === 1 ? 'wiz active' : 'wiz'} onClick={() => setHostWizardStep(1)} disabled={isReadOnlyRole}>1. Basics</button>
                      <button className={hostWizardStep === 2 ? 'wiz active' : 'wiz'} onClick={() => setHostWizardStep(2)} disabled={isReadOnlyRole}>2. Auto-Checks</button>
                      <button className={hostWizardStep === 3 ? 'wiz active' : 'wiz'} onClick={() => setHostWizardStep(3)} disabled={isReadOnlyRole}>3. Create</button>
                    </div>
                    {hostWizardStep === 1 ? (
                      <div className="card" style={{ marginBottom: '.8rem' }}>
                        <div className="row">
                          <select value={hostDomain} onChange={(e) => setHostDomain(e.target.value)}>
                            {domains.length === 0 ? <option value="">No domains available</option> : null}
                            {domains.map((d) => (
                              <option key={d.id} value={d.name}>{d.name}</option>
                            ))}
                          </select>
                          <input value={hostSub} onChange={(e) => setHostSub(e.target.value.toLowerCase().trim())} placeholder="app" />
                          <label className="check"><input type="checkbox" checked={hostHAEnabled} onChange={(e) => { const checked = e.target.checked; setHostHAEnabled(checked); if (checked) setHostSSHBastion(false); }} /> Enable HA</label>
                          {identity?.role === 'admin' ? <label className="check"><input type="checkbox" checked={hostSSHBastion} onChange={(e) => { const checked = e.target.checked; setHostSSHBastion(checked); if (checked) setHostHAEnabled(false); }} /> SSH Bastion</label> : null}
                          {hostUsesDirectUpstream ? <input value={hostUpstream} onChange={(e) => setHostUpstream(e.target.value)} placeholder="http://127.0.0.1:3000" /> : null}
                          {hostHAEnabled ? (
                            <select value={hostHAMode} onChange={(e) => setHostHAMode(e.target.value as 'failover' | 'round_robin')}>
                              <option value="failover">Failover</option>
                              <option value="round_robin">Load Balance (Round Robin)</option>
                            </select>
                          ) : null}
                          <label className="check"><input type="checkbox" checked={hostInsecureTLS} onChange={(e) => setHostInsecureTLS(e.target.checked)} /> No TLS Verify</label>
                          <button className="btn" onClick={() => { setHostPreflight(null); setHostWizardStep(2); }} disabled={isReadOnlyRole || !hostDomain || !hostSub || (!hostHAEnabled && !hostSSHBastion && !hostUpstream)}>Next</button>
                        </div>
                        {hostHAEnabled ? (
                          <>
                            <div className="row">
                              <button className="btn" type="button" onClick={addHostBackend} disabled={isReadOnlyRole}>Add Backend</button>
                            </div>
                            {hostHABackends.map((b, idx) => (
                              <div className="row" key={`host-ha-${idx}`}>
                                <input value={b.name} onChange={(e) => updateHostBackend(idx, { name: e.target.value })} placeholder="Server name" />
                                <input value={b.url} onChange={(e) => updateHostBackend(idx, { url: e.target.value })} placeholder="https://10.0.0.11:8443" />
                                <button className="btn danger" type="button" onClick={() => removeHostBackend(idx)} disabled={isReadOnlyRole || hostHABackends.length <= 1}>Remove</button>
                              </div>
                            ))}
                          </>
                        ) : null}
                        {hostHAEnabled ? (
                          <div className="muted">HA enabled. Configure named backend servers (minimum 2).</div>
                        ) : null}
                        {hostSSHBastion ? (
                          <div className="muted">SSH Bastion enabled. Upstream is auto-bound to this DomNex node and the FQDN is auto-added to SSH Bastion routes.</div>
                        ) : null}
                        <div className="muted">
                          {fqdnPreview ? `Will be created as: ${fqdnPreview}` : 'Enter a subdomain name, choose a domain, and set the upstream.'}
                        </div>
                      </div>
                    ) : null}
                    {hostWizardStep === 2 ? (
                      <div className="card" style={{ marginBottom: '.8rem' }}>
                        <div className="muted" style={{ marginBottom: '.5rem' }}>
                          Checks run automatically every 4 seconds. Continue only when all checks are green.
                        </div>
                        <div className="muted" style={{ marginBottom: '.5rem' }}>
                          Upstream TLS verify: <strong>{hostInsecureTLS ? 'disabled (self-signed accepted)' : 'enabled (strict verify)'}</strong> · Routing: <strong>{hostHAEnabled ? `HA (${hostHAMode})` : hostSSHBastion ? 'SSH Bastion' : 'Single Upstream'}</strong>
                        </div>
                        {hostPreflight ? (
                          <div className="diag" style={{ marginBottom: '.5rem' }}>
                            {hostPreflight.checks.map((c) => (
                              <span key={c.name} className={`badge ${c.ok ? 'ok' : 'err'}`}>
                                {c.name}: {c.ok ? 'ok' : 'fail'}{c.detail ? ` (${c.detail})` : ''}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <div className="muted">Initializing preflight...</div>
                        )}
                        <div className="row">
                          <button className="btn" onClick={() => setHostWizardStep(1)} disabled={isReadOnlyRole}>Back</button>
                          <button className="btn" onClick={() => setHostWizardStep(3)} disabled={isReadOnlyRole || hostPreflightRunning || !hostPreflight?.ready}>Next</button>
                        </div>
                      </div>
                    ) : null}
                    {hostWizardStep === 3 ? (
                      <div className="card" style={{ marginBottom: '.8rem' }}>
                        <div className="muted" style={{ marginBottom: '.5rem' }}>
                          Ready to create: <strong>{hostPreflight?.fqdn || fqdnPreview}</strong>
                        </div>
                        <div className="muted" style={{ marginBottom: '.5rem' }}>
                          Upstream TLS verify: <strong>{hostInsecureTLS ? 'disabled' : 'enabled'}</strong>
                          {hostSSHBastion ? <span> · SSH Bastion route will be created automatically.</span> : null}
                        </div>
                        <div className="row">
                          <button className="btn" onClick={() => setHostWizardStep(2)} disabled={isReadOnlyRole}>Back</button>
                          <button className="btn" onClick={addHost} disabled={isReadOnlyRole || loading || !hostPreflight?.ready}>Create Subdomain</button>
                        </div>
                      </div>
                    ) : null}
                  </section>
                  <section className="card">
                    <div className="card-head"><h3>Configured Subdomains</h3></div>
                    {hostsGroupedByApex.map((group) => (
                      <div key={`apex-${group.apex}`} className="subdomain-group">
                        <div className="subdomain-group-head">
                          <strong>{group.apex}</strong>
                          <span className="muted">{group.items.length} subdomains</span>
                        </div>
                        {group.items.map((h) => (
                          <div className="host" key={h.id}>
                            <div>
                              <strong>
                                <a className="host-fqdn-link" href={`https://${h.fqdn}`} target="_blank" rel="noopener noreferrer">{h.fqdn}</a>
                              </strong> {' -> '} {h.upstreamUrl}
                              {h.haEnabled ? <span className="badge warn" style={{ marginLeft: '.45rem' }}>HA {h.haMode || 'failover'}</span> : null}
                              {h.insecureTls ? <span className="badge warn" style={{ marginLeft: '.45rem' }}>insecure TLS</span> : null}
                              {h.authEnabled ? <span className="badge ok" style={{ marginLeft: '.45rem' }}>auth page enabled</span> : null}
                              <span className={`badge ${hostStateBadge(h.state).cls}`} style={{ marginLeft: '.45rem' }}>{hostStateBadge(h.state).label}</span>
                              {requestsByHostID[h.id] ? <span className="badge ok" style={{ marginLeft: '.45rem' }}>24h req {requestsByHostID[h.id]}</span> : null}
                              {h.haEnabled && hostDiagnostics[h.fqdn]?.haTotal ? (
                                <span className={`badge ${(hostDiagnostics[h.fqdn].haOnline || 0) === hostDiagnostics[h.fqdn].haTotal ? 'ok' : (hostDiagnostics[h.fqdn].haOnline || 0) > 0 ? 'warn' : 'err'}`} style={{ marginLeft: '.45rem' }}>
                                  Hosts Online {hostDiagnostics[h.fqdn].haOnline || 0}/{hostDiagnostics[h.fqdn].haTotal || 0}
                                </span>
                              ) : null}
                              {h.haEnabled && (hostDiagnostics[h.fqdn]?.haOffline?.length || 0) > 0 ? (
                                <span className="badge err" style={{ marginLeft: '.45rem' }}>
                                  Offline: {hostDiagnostics[h.fqdn].haOffline?.join(', ')}
                                </span>
                              ) : null}
                              {h.state === 'error' && h.errorReason ? <div className="errtxt">{h.errorReason}</div> : null}
                              {hostDiagnostics[h.fqdn] ? (
                                <div className="diag">
                                  <span className={`badge ${hostDiagnostics[h.fqdn].dnsRecords?.length ? 'ok' : 'err'}`}>DNS {hostDiagnostics[h.fqdn].dnsRecords?.length ? 'ok' : 'fail'}</span>
                                  {h.state === 'maintenance' ? (
                                    <>
                                      <span className="badge warn">HTTP MAINT</span>
                                      <span className="badge warn">HTTPS MAINT</span>
                                      <span className="badge warn">TLS MAINT</span>
                                    </>
                                  ) : (
                                    <>
                                      <span className={`badge ${hostDiagnostics[h.fqdn].httpStatus >= 200 && hostDiagnostics[h.fqdn].httpStatus < 400 ? 'ok' : 'warn'}`}>HTTP {hostDiagnostics[h.fqdn].httpStatus || '-'}</span>
                                      <span className={`badge ${hostDiagnostics[h.fqdn].httpsStatus >= 200 && hostDiagnostics[h.fqdn].httpsStatus < 500 ? 'ok' : 'warn'}`}>HTTPS {hostDiagnostics[h.fqdn].httpsStatus || '-'}</span>
                                      <span className={`badge ${hostDiagnostics[h.fqdn].tlsOk ? 'ok' : 'err'}`}>TLS {hostDiagnostics[h.fqdn].tlsOk ? 'ok' : 'fail'}</span>
                                    </>
                                  )}
                                </div>
                              ) : null}
                            </div>
                            <div className="row" style={{ marginBottom: 0 }}>
                              <button className="btn" onClick={() => openHostDetail(h)}>{isReadOnlyRole ? 'View' : 'Edit'}</button>
                              <button className="btn" onClick={() => setHostMaintenance(h.id, h.state !== 'maintenance')} disabled={isReadOnlyRole || loading}>
                                {h.state === 'maintenance' ? 'Maintenance Off' : 'Maintenance On'}
                              </button>
                              <button className="btn" onClick={() => setHostDisabled(h.id, h.state !== 'disabled')} disabled={isReadOnlyRole || loading}>
                                {h.state === 'disabled' ? 'Enable' : 'Disable'}
                              </button>
                              {h.state === 'error' ? <button className="btn" onClick={() => retryHost(h.id)} disabled={isReadOnlyRole}>Retry</button> : null}
                              <button className="btn danger" onClick={() => openDeleteHostDialog(h)} disabled={isReadOnlyRole || loading}>Delete</button>
                            </div>
                          </div>
                        ))}
                      </div>
                    ))}
                  </section>
                </div>
                <aside className="entity-side">
                  <section className="card">
                    <div className="card-head"><h3>Subdomain Stats</h3></div>
                    <div className="metric-grid">
                      <MetricTile label="Total Hosts" value={String(hosts.length)} hint="Configured subdomains" />
                      <MetricTile label="Active" value={String(activeHosts)} hint="Proxy routes online" />
                      <MetricTile label="Errors" value={String(errorHosts)} hint="Needs attention" />
                      <MetricTile label="Diagnostics" value={String(hostsWithDiagnostics)} hint="Hosts with checks" />
                      <MetricTile label="Healthy" value={String(hostsHealthy)} hint="DNS+TLS+HTTPS good" />
                    </div>
                  </section>
                  <section className="card">
                    <div className="card-head"><h3>Routing Note</h3></div>
                    <div className="muted">Use `Edit` to open a dedicated settings page for each subdomain.</div>
                    <div className="muted" style={{ marginTop: '.45rem' }}>There you can manage upstream, TLS behavior and auth page credentials.</div>
                  </section>
                </aside>
              </section>
            )
          ) : null}

          {(identity?.role === 'admin' || isReadOnlyRole) && tab === 'settings' ? (
            <section className="entity-page">
              <div className="entity-main">
                <section className="card">
                  <div className="card-head"><h3>Runtime Settings</h3></div>
                  <div className="wizard-steps" style={{ marginBottom: '.75rem' }}>
                    <button className={settingsTab === 'general' ? 'wiz active' : 'wiz'} onClick={() => setSettingsTab('general')}>General</button>
                    <button className={settingsTab === 'security' ? 'wiz active' : 'wiz'} onClick={() => setSettingsTab('security')}>Security &amp; Time</button>
                    <button className={settingsTab === 'logservers' ? 'wiz active' : 'wiz'} onClick={() => setSettingsTab('logservers')}>Logservers</button>
                    <button className={settingsTab === 'appearance' ? 'wiz active' : 'wiz'} onClick={() => setSettingsTab('appearance')}>Appearance</button>
                    <button className={settingsTab === 'advanced' ? 'wiz active' : 'wiz'} onClick={() => setSettingsTab('advanced')}>Advanced</button>
                  </div>
                  {settingsTab === 'general' ? (
                    <>
                      <div className="row">
                        <input value={settingsAcmeEmail} onChange={(e) => setSettingsAcmeEmail(e.target.value)} placeholder="ACME Email (e.g. admin@jigcinema.com)" />
                        <label className="check"><input type="checkbox" checked={settingsAcmeStaging} onChange={(e) => setSettingsAcmeStaging(e.target.checked)} /> ACME Staging</label>
                      </div>
                      <div className="row">
                        <select value={settingsBaseDomain} onChange={(e) => setSettingsBaseDomain(e.target.value)}>
                          <option value="">No base domain selected</option>
                          {domains.map((d) => (
                            <option key={d.id} value={d.name}>{d.name}</option>
                          ))}
                        </select>
                      </div>
                      <div className="muted" style={{ marginBottom: '.6rem' }}>
                        Selecting a base domain provisions `admin.&lt;domain&gt;` automatically. For Cloudflare domains, DNS records are provisioned automatically.
                      </div>
                    </>
                  ) : null}
                  {settingsTab === 'security' ? (
                    <>
                      <div className="field">
                        <label>Cloudflare API Token</label>
                        <input value={settingsCFToken} onChange={(e) => setSettingsCFToken(e.target.value)} placeholder={settings?.hasCloudflareToken ? 'Leave empty to keep current token' : 'Cloudflare API Token'} />
                      </div>
                      <div className="field">
                        <label>Preferred Public IPv4</label>
                        <input value={settingsPublicIPv4} onChange={(e) => setSettingsPublicIPv4(e.target.value)} placeholder="e.g. 203.0.113.10" />
                        <div className="muted">Auto-detected on first start. Override for multi-WAN or custom edge routing.</div>
                      </div>
                      <div className="field">
                        <label>Time Sync Mode</label>
                        <select value={settingsTimeSyncMode} onChange={(e) => setSettingsTimeSyncMode(e.target.value as 'system_only' | 'external_public' | 'external_lan')}>
                          <option value="system_only">System clock (internal NTP)</option>
                          <option value="external_public">External Public NTP (Top 3)</option>
                          <option value="external_lan">External LAN NTP server(s)</option>
                        </select>
                      </div>
                      {settingsTimeSyncMode === 'external_lan' ? (
                        <div className="field">
                          <label>LAN NTP Servers</label>
                          <textarea
                            value={settingsTimeSyncLAN}
                            onChange={(e) => setSettingsTimeSyncLAN(e.target.value)}
                            placeholder="192.168.1.1, ntp.local, 192.168.1.10:123"
                            rows={3}
                          />
                          <div className="muted">Comma or newline separated list.</div>
                        </div>
                      ) : null}
                      <div className="card" style={{ marginBottom: '.6rem' }}>
                        <div className="card-head"><h3>Threat Intel Tuning</h3></div>
                        <div className="field-grid">
                          <div className="field">
                            <label>Threat Intel Enabled</label>
                            <label className="check"><input type="checkbox" checked={!!tiConfig.enabled} onChange={(e) => setTiConfig((p) => ({ ...p, enabled: e.target.checked }))} disabled={isReadOnlyRole || identity?.role !== 'admin'} /> Opt-in enabled</label>
                          </div>
                          <div className="field">
                            <label>Mode</label>
                            <select value={tiConfig.mode} onChange={(e) => setTiConfig((p) => ({ ...p, mode: e.target.value as 'monitor_only' | 'auto_mode' }))} disabled={isReadOnlyRole || identity?.role !== 'admin'}>
                              <option value="monitor_only">Monitor only</option>
                              <option value="auto_mode">Auto mode (soft + hard)</option>
                            </select>
                          </div>
                          <div className="field">
                            <label>Feed Sync Interval (hours)</label>
                            <input type="number" min={1} max={168} value={String(tiConfig.syncHours || 24)} onChange={(e) => setTiConfig((p) => ({ ...p, syncHours: Number(e.target.value) || 24 }))} disabled={isReadOnlyRole || identity?.role !== 'admin'} />
                          </div>
                        </div>
                        <div className="field-grid">
                          <div className="field">
                            <label>Event Threshold (hits)</label>
                            <input type="number" min={1} max={100} value={String(tiConfig.eventMinHits || 2)} onChange={(e) => setTiConfig((p) => ({ ...p, eventMinHits: Number(e.target.value) || 2 }))} disabled={isReadOnlyRole || identity?.role !== 'admin'} />
                          </div>
                          <div className="field">
                            <label>Offender Threshold (hits)</label>
                            <input type="number" min={2} max={10000} value={String(tiConfig.offenderMinHits || 10)} onChange={(e) => setTiConfig((p) => ({ ...p, offenderMinHits: Number(e.target.value) || 10 }))} disabled={isReadOnlyRole || identity?.role !== 'admin'} />
                          </div>
                          <div className="field">
                            <label>Monitor Max Level</label>
                            <input type="number" min={0} max={32} value={String(tiConfig.monitorMaxLevel || 2)} onChange={(e) => setTiConfig((p) => ({ ...p, monitorMaxLevel: Number(e.target.value) || 2 }))} disabled={isReadOnlyRole || identity?.role !== 'admin'} />
                          </div>
                          <div className="field">
                            <label>Soft Block Min Level</label>
                            <input type="number" min={1} max={32} value={String(tiConfig.softMinLevel || 3)} onChange={(e) => setTiConfig((p) => ({ ...p, softMinLevel: Number(e.target.value) || 3 }))} disabled={isReadOnlyRole || identity?.role !== 'admin'} />
                          </div>
                          <div className="field">
                            <label>Hard Block Level</label>
                            <input type="number" min={2} max={64} value={String(tiConfig.hardLevel || 6)} onChange={(e) => setTiConfig((p) => ({ ...p, hardLevel: Number(e.target.value) || 6 }))} disabled={isReadOnlyRole || identity?.role !== 'admin'} />
                          </div>
                          <div className="field">
                            <label>Soft Block Duration (minutes)</label>
                            <input type="number" min={1} max={1440} value={String(tiConfig.softBlockMinutes || 15)} onChange={(e) => setTiConfig((p) => ({ ...p, softBlockMinutes: Number(e.target.value) || 15 }))} disabled={isReadOnlyRole || identity?.role !== 'admin'} />
                          </div>
                        </div>
                        <div className="row" style={{ marginBottom: 0 }}>
                          <button className="btn" onClick={syncThreatIntelNow} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Sync Now</button>
                          <button className="btn" onClick={() => setTiFeedsOpen(true)} disabled={isReadOnlyRole || identity?.role !== 'admin'}>Manage Feeds</button>
                          <button className="btn" onClick={saveThreatIntelConfig} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Save Threat Intel Policy</button>
                        </div>
                        {tiConfigSavedAt ? <div className="muted" style={{ marginTop: '.5rem' }}>Policy saved: {new Date(tiConfigSavedAt).toLocaleString()}</div> : null}
                      </div>
                    </>
                  ) : null}
                  {settingsTab === 'appearance' ? (
                    <>
                      <div className="row">
                        <select value={settingsStyleProfile} onChange={(e) => setSettingsStyleProfile(e.target.value as StyleProfile)}>
                          <option value="monolith">Monolith</option>
                          <option value="cybermonolith">CyberMonolith</option>
                          <option value="custom">Custom</option>
                        </select>
                      </div>
                      <div className="muted" style={{ marginBottom: '.35rem' }}>
                        Style profile controls the full UI palette. `Custom` uses JSON overrides (theme key to color/value).
                      </div>
                      <textarea
                        value={settingsStyleCustom}
                        onChange={(e) => setSettingsStyleCustom(e.target.value)}
                        placeholder='{"accent":"#8b5cf6","surface":"#1c1c22","text":"#e6e6f0","border":"#2a2a36"}'
                        rows={4}
                      />
                    </>
                  ) : null}
                  {settingsTab === 'logservers' ? (
                    <>
                      <div className="card" style={{ marginBottom: '.6rem' }}>
                        <div className="card-head"><h3>Syslog Delivery</h3></div>
                        <div className="field-grid">
                          <div className="field">
                            <label>Enabled</label>
                            <label className="check"><input type="checkbox" checked={!!settingsLogServers.syslog.enabled} onChange={(e) => setSettingsLogServers((p) => ({ ...p, syslog: { ...p.syslog, enabled: e.target.checked } }))} /> Forward to Syslog</label>
                          </div>
                          <div className="field">
                            <label>Protocol</label>
                            <select value={settingsLogServers.syslog.protocol} onChange={(e) => setSettingsLogServers((p) => ({ ...p, syslog: { ...p.syslog, protocol: e.target.value as 'udp' | 'tcp' } }))}>
                              <option value="udp">UDP</option>
                              <option value="tcp">TCP</option>
                            </select>
                          </div>
                          <div className="field">
                            <label>Address (host:port)</label>
                            <input value={settingsLogServers.syslog.address} onChange={(e) => setSettingsLogServers((p) => ({ ...p, syslog: { ...p.syslog, address: e.target.value } }))} placeholder="192.168.1.224:514" />
                          </div>
                          <div className="field">
                            <label>Minimum Level</label>
                            <select value={settingsLogServers.syslog.minLevel} onChange={(e) => setSettingsLogServers((p) => ({ ...p, syslog: { ...p.syslog, minLevel: e.target.value as 'info' | 'warn' | 'error' } }))}>
                              <option value="info">info</option>
                              <option value="warn">warn</option>
                              <option value="error">error</option>
                            </select>
                          </div>
                          <div className="field">
                            <label>App Name</label>
                            <input value={settingsLogServers.syslog.appName} onChange={(e) => setSettingsLogServers((p) => ({ ...p, syslog: { ...p.syslog, appName: e.target.value } }))} placeholder="DomNexDomain" />
                          </div>
                        </div>
                      </div>

                      <div className="card" style={{ marginBottom: '.6rem' }}>
                        <div className="card-head"><h3>HTTP JSON Delivery</h3></div>
                        <div className="field-grid">
                          <div className="field">
                            <label>Enabled</label>
                            <label className="check"><input type="checkbox" checked={!!settingsLogServers.http.enabled} onChange={(e) => setSettingsLogServers((p) => ({ ...p, http: { ...p.http, enabled: e.target.checked } }))} /> Forward via HTTP POST</label>
                          </div>
                          <div className="field">
                            <label>Endpoint URL</label>
                            <input value={settingsLogServers.http.url} onChange={(e) => setSettingsLogServers((p) => ({ ...p, http: { ...p.http, url: e.target.value } }))} placeholder="https://siem.local/ingest/domnex" />
                          </div>
                          <div className="field">
                            <label>Timeout (seconds)</label>
                            <input type="number" min={1} max={30} value={String(settingsLogServers.http.timeoutSec || 4)} onChange={(e) => setSettingsLogServers((p) => ({ ...p, http: { ...p.http, timeoutSec: Number(e.target.value) || 4 } }))} />
                          </div>
                          <div className="field">
                            <label>Minimum Level</label>
                            <select value={settingsLogServers.http.minLevel} onChange={(e) => setSettingsLogServers((p) => ({ ...p, http: { ...p.http, minLevel: e.target.value as 'info' | 'warn' | 'error' } }))}>
                              <option value="info">info</option>
                              <option value="warn">warn</option>
                              <option value="error">error</option>
                            </select>
                          </div>
                          <div className="field">
                            <label>TLS Verify</label>
                            <label className="check"><input type="checkbox" checked={!settingsLogServers.http.insecure} onChange={(e) => setSettingsLogServers((p) => ({ ...p, http: { ...p.http, insecure: !e.target.checked } }))} /> Verify remote TLS certificate</label>
                          </div>
                          <div className="field">
                            <label>Bearer Token (optional)</label>
                            <input value={settingsLogHTTPBearer} onChange={(e) => setSettingsLogHTTPBearer(e.target.value)} placeholder={settings?.hasLogHTTPBearer ? 'Stored. Enter only to rotate token' : 'Bearer token'} />
                          </div>
                        </div>
                      </div>

                      <div className="card" style={{ marginBottom: '.6rem' }}>
                        <div className="card-head"><h3>TCP JSON Delivery</h3></div>
                        <div className="field-grid">
                          <div className="field">
                            <label>Enabled</label>
                            <label className="check"><input type="checkbox" checked={!!settingsLogServers.tcpJson.enabled} onChange={(e) => setSettingsLogServers((p) => ({ ...p, tcpJson: { ...p.tcpJson, enabled: e.target.checked } }))} /> Forward NDJSON over TCP</label>
                          </div>
                          <div className="field">
                            <label>Address (host:port)</label>
                            <input value={settingsLogServers.tcpJson.address} onChange={(e) => setSettingsLogServers((p) => ({ ...p, tcpJson: { ...p.tcpJson, address: e.target.value } }))} placeholder="192.168.1.224:5514" />
                          </div>
                          <div className="field">
                            <label>Timeout (seconds)</label>
                            <input type="number" min={1} max={30} value={String(settingsLogServers.tcpJson.timeoutSec || 3)} onChange={(e) => setSettingsLogServers((p) => ({ ...p, tcpJson: { ...p.tcpJson, timeoutSec: Number(e.target.value) || 3 } }))} />
                          </div>
                          <div className="field">
                            <label>Minimum Level</label>
                            <select value={settingsLogServers.tcpJson.minLevel} onChange={(e) => setSettingsLogServers((p) => ({ ...p, tcpJson: { ...p.tcpJson, minLevel: e.target.value as 'info' | 'warn' | 'error' } }))}>
                              <option value="info">info</option>
                              <option value="warn">warn</option>
                              <option value="error">error</option>
                            </select>
                          </div>
                        </div>
                      </div>
                    </>
                  ) : null}
                  {settingsTab === 'advanced' ? (
                    <>
                      <div className="card" style={{ marginBottom: '.6rem' }}>
                        <div className="card-head"><h3>Data Retention Policy</h3></div>
                        <div className="field-grid">
                          <div className="field">
                            <label>Audit Events (days)</label>
                            <input type="number" min={1} max={3650} value={String(settingsRetention.auditDays || 90)} onChange={(e) => setSettingsRetention((p) => ({ ...p, auditDays: Number(e.target.value) || 90 }))} />
                          </div>
                          <div className="field">
                            <label>Traffic Buckets (days)</label>
                            <input type="number" min={1} max={3650} value={String(settingsRetention.trafficDays || 30)} onChange={(e) => setSettingsRetention((p) => ({ ...p, trafficDays: Number(e.target.value) || 30 }))} />
                          </div>
                          <div className="field">
                            <label>Visitor Hashes (days)</label>
                            <input type="number" min={1} max={3650} value={String(settingsRetention.visitorsDays || 30)} onChange={(e) => setSettingsRetention((p) => ({ ...p, visitorsDays: Number(e.target.value) || 30 }))} />
                          </div>
                          <div className="field">
                            <label>Threat Intel Events (days)</label>
                            <input type="number" min={1} max={3650} value={String(settingsRetention.threatDays || 60)} onChange={(e) => setSettingsRetention((p) => ({ ...p, threatDays: Number(e.target.value) || 60 }))} />
                          </div>
                          <div className="field">
                            <label>Blocked IP Table (days)</label>
                            <input type="number" min={1} max={3650} value={String(settingsRetention.blockedDays || 60)} onChange={(e) => setSettingsRetention((p) => ({ ...p, blockedDays: Number(e.target.value) || 60 }))} />
                          </div>
                          <div className="field">
                            <label>Login Attempts (days)</label>
                            <input type="number" min={1} max={3650} value={String(settingsRetention.loginAttemptDays || 30)} onChange={(e) => setSettingsRetention((p) => ({ ...p, loginAttemptDays: Number(e.target.value) || 30 }))} />
                          </div>
                          <div className="field">
                            <label>Password Reset Tokens (days)</label>
                            <input type="number" min={1} max={3650} value={String(settingsRetention.passwordResetDays || 7)} onChange={(e) => setSettingsRetention((p) => ({ ...p, passwordResetDays: Number(e.target.value) || 7 }))} />
                          </div>
                        </div>
                        <div className="muted">Purge runs automatically in the background (daily). Values are persisted in runtime settings.</div>
                      </div>
                    </>
                  ) : null}
                  <div className="row">
                    <button className="btn" onClick={saveSettings} disabled={loading || isReadOnlyRole}>Save Settings</button>
                    <button className="btn" onClick={reloadService} disabled={loading || isReadOnlyRole}>Reload Service</button>
                    <button className="btn" onClick={loadTimeSyncStatus} disabled={loading}>Check Time Sync</button>
                  </div>
                  {settingsMessage ? <div className="muted">{settingsMessage}</div> : null}
                </section>
              </div>
            </section>
          ) : null}

          {(identity?.role === 'admin' || isReadOnlyRole) && tab === 'backup' ? (
            <section className="entity-page">
              <div className="entity-main">
                <section className="card" style={{ marginBottom: '.6rem' }}>
                  <div className="card-head"><h3>Backup Center</h3></div>
                  <div className="wizard-steps" style={{ marginBottom: '.3rem' }}>
                    <button className={backupTab === 'general' ? 'wiz active' : 'wiz'} onClick={() => setBackupTab('general')}>General</button>
                    <button className={backupTab === 'browser' ? 'wiz active' : 'wiz'} onClick={() => setBackupTab('browser')}>Archive Browser</button>
                    <button className={backupTab === 'settings' ? 'wiz active' : 'wiz'} onClick={() => setBackupTab('settings')}>Backup Settings</button>
                    <button className={backupTab === 'manual' ? 'wiz active' : 'wiz'} onClick={() => setBackupTab('manual')}>Manual Backup</button>
                  </div>
                </section>
                {backupTab === 'general' ? (
                  <>
                    <section className="card" style={{ marginBottom: '.6rem' }}>
                      <div className="card-head"><h3>Backup Stats</h3></div>
                      <div className="metric-grid">
                        <MetricTile label="Archives Total" value={String(backupStats.totalArchives || 0)} hint="Known backup records" />
                        <MetricTile label="Local Archives" value={String(backupStats.localArchives || 0)} hint="On-server backups" />
                        <MetricTile label="FTP Archives" value={String(backupStats.ftpArchives || 0)} hint="Remote FTP backups" />
                        <MetricTile label="Retention" value={String(backupSettings.retentionCount || 10)} hint="Per target keep count" />
                      </div>
                      <div className="muted">Last run: {backupSettings.lastRunAt ? new Date(backupSettings.lastRunAt).toLocaleString() : '-'}</div>
                      <div className="muted">Last result: {backupSettings.lastResult || '-'}</div>
                    </section>
                    <section className="card" style={{ marginBottom: '.6rem' }}>
                      <div className="card-head"><h3>Scheduled Actions</h3></div>
                      <div className="row">
                        <button className="btn" onClick={runScheduledBackupNow} disabled={loading || isReadOnlyRole}>Backup now</button>
                        <button className="btn ghost" onClick={refreshBackupArchives} disabled={loading}>Refresh Stats</button>
                      </div>
                      <div className="muted">Runs one immediate scheduled backup using configured schedule targets and retention.</div>
                    </section>
                  </>
                ) : null}
                {backupTab === 'browser' ? (
                  <section className="card">
                    <div className="card-head"><h3>Archive Browser</h3></div>
                    <div className="muted" style={{ marginBottom: '.6rem' }}>Click restore to rehydrate from selected archive. Confirmation is required.</div>
                    <div className="log-table-wrap" style={{ maxHeight: '68vh' }}>
                      <table className="log-table">
                        <thead>
                          <tr>
                            <th>Created</th>
                            <th>File</th>
                            <th>Storage</th>
                            <th>Location</th>
                            <th>Size</th>
                            <th>Status</th>
                            <th>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {backupArchives.length === 0 ? (
                            <tr><td colSpan={7} className="muted" style={{ padding: '.9rem' }}>No archived backups yet.</td></tr>
                          ) : backupArchives.map((a) => (
                            <tr key={a.id}>
                              <td>{formatDateTime(a.createdAt)}</td>
                              <td>{a.fileName}</td>
                              <td><span className={`badge ${a.storage === 'local' ? 'ok' : 'warn'}`}>{a.storage}</span></td>
                              <td className="muted">{a.location}</td>
                              <td>{Math.max(1, Math.round((a.sizeBytes || 0) / 1024))} KB</td>
                              <td>{a.status || 'ready'}</td>
                              <td>
                                <div className="row" style={{ marginBottom: 0 }}>
                                  <button className="btn" disabled={loading || isReadOnlyRole} onClick={() => {
                                    const ok = window.confirm(`Restore archive ${a.fileName}? This will overwrite current state.`);
                                    if (!ok) return;
                                    void restoreBackupArchive(a.id);
                                  }}>Restore</button>
                                  <button className="btn danger" disabled={loading || isReadOnlyRole} onClick={() => {
                                    const ok = window.confirm(`Delete archive ${a.fileName}?`);
                                    if (!ok) return;
                                    void deleteBackupArchive(a.id);
                                  }}>Delete</button>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                ) : null}
                {backupTab === 'manual' ? (
                  <>
                    <section className="card" style={{ marginBottom: '.6rem' }}>
                      <div className="card-head"><h3>Create Encrypted Backup</h3></div>
                      <div className="field-grid">
                        <div className="field">
                          <label>Backup Passphrase</label>
                          <input type="password" value={backupPassphrase} onChange={(e) => setBackupPassphrase(e.target.value)} placeholder="Minimum 12 characters" />
                          <div className="muted">Creates encrypted `.dnxbak` package for download.</div>
                        </div>
                      </div>
                      <div className="row" style={{ marginBottom: 0 }}>
                        <button className="btn" onClick={createEncryptedBackup} disabled={loading || isReadOnlyRole}>Create &amp; Download Backup</button>
                      </div>
                    </section>
                    <section className="card danger-zone">
                      <div className="card-head"><h3>Direct Restore Package</h3></div>
                      <div className="field-grid">
                        <div className="field">
                          <label>Backup Package</label>
                          <input type="file" accept=".dnxbak,.bin,.dat,application/octet-stream" onChange={(e) => setBackupRestoreFile(e.target.files?.[0] || null)} />
                        </div>
                        <div className="field">
                          <label>Backup Passphrase</label>
                          <input type="password" value={backupRestorePassphrase} onChange={(e) => setBackupRestorePassphrase(e.target.value)} placeholder="Passphrase used for backup encryption" />
                        </div>
                        <div className="field">
                          <label>Confirm Restore</label>
                          <input value={backupRestoreConfirm} onChange={(e) => setBackupRestoreConfirm(e.target.value)} placeholder="Type RESTORE" />
                        </div>
                      </div>
                      <div className="row">
                        <button className="btn" onClick={analyzeBackupFile} disabled={loading || !backupRestoreFile}>Analyze Package</button>
                        <button className="btn danger" onClick={restoreEncryptedBackup} disabled={loading || isReadOnlyRole || !backupRestoreFile}>Apply Restore</button>
                        <button className="btn" onClick={runPostRestoreCheck} disabled={loading || isReadOnlyRole}>Run Post-Restore Check</button>
                      </div>
                      {backupMetaPreview ? (
                        <pre>{`File: ${backupMetaPreview.fileName}
Format: ${backupMetaPreview.format}
Created: ${backupMetaPreview.createdAt}
DomNex: ${backupMetaPreview.domnexVersion}
Domains: ${backupMetaPreview.domains}
Subdomains: ${backupMetaPreview.subdomains}
Users: ${backupMetaPreview.users}
DB SHA256: ${backupMetaPreview.dbSha256 || '-'}
Key SHA256: ${backupMetaPreview.keySha256 || '-'}`}</pre>
                      ) : null}
                      {postRestoreCheck ? (
                        <pre>{`Checked: ${new Date(postRestoreCheck.checkedAt).toLocaleString()}
Domains: ${postRestoreCheck.domainsOk}/${postRestoreCheck.domainsTotal}
Hosts DNS OK: ${postRestoreCheck.hostsDnsOk}/${postRestoreCheck.hostsTotal}
Hosts HTTPS OK: ${postRestoreCheck.hostsHttpsOk}/${postRestoreCheck.hostsTotal}
Hosts TLS OK: ${postRestoreCheck.hostsTlsOk}/${postRestoreCheck.hostsTotal}
Hosts Valid Cert: ${postRestoreCheck.hostsCertValid}/${postRestoreCheck.hostsTotal}
Cert Warmup: ${postRestoreCheck.certWarmupSucceeded}/${postRestoreCheck.certWarmupAttempts}
Issues: ${postRestoreCheck.issues.length}`}</pre>
                      ) : null}
                    </section>
                  </>
                ) : null}
                {backupTab === 'settings' ? (
                <section className="card" style={{ marginBottom: '.6rem' }}>
                  <div className="card-head"><h3>Scheduled Backup</h3></div>
                  <div className="field-grid">
                    <div className="field">
                      <label>Enable Scheduler</label>
                      <label className="check"><input type="checkbox" checked={!!backupSettings.enabled} onChange={(e) => setBackupSettings((p) => ({ ...p, enabled: e.target.checked }))} disabled={isReadOnlyRole} /> Create encrypted backups automatically</label>
                    </div>
                    <div className="field">
                      <label>Interval (hours)</label>
                      <input type="number" min={1} max={168} value={String(backupSettings.intervalHours || 24)} onChange={(e) => setBackupSettings((p) => ({ ...p, intervalHours: Number(e.target.value) || 24 }))} disabled={isReadOnlyRole} />
                    </div>
                    <div className="field">
                      <label>Retention Count</label>
                      <input type="number" min={1} max={1000} value={String(backupSettings.retentionCount || 10)} onChange={(e) => setBackupSettings((p) => ({ ...p, retentionCount: Number(e.target.value) || 10 }))} disabled={isReadOnlyRole} />
                    </div>
                    <div className="field">
                      <label>Backup Encryption Passphrase</label>
                      <input type="password" value={backupSchedulePassphrase} onChange={(e) => setBackupSchedulePassphrase(e.target.value)} placeholder={backupSettings.hasPassphrase ? 'Stored. Enter only to rotate.' : 'Minimum 12 characters'} disabled={isReadOnlyRole} />
                    </div>
                  </div>
                  <div className="muted">Last run: {backupSettings.lastRunAt ? new Date(backupSettings.lastRunAt).toLocaleString() : '-'}</div>
                  <div className="muted" style={{ marginBottom: '.5rem' }}>Last result: {backupSettings.lastResult || '-'}</div>

                  <div className="card" style={{ marginBottom: '.6rem' }}>
                    <div className="card-head"><h3>Local Backup Target</h3></div>
                    <div className="field-grid">
                      <div className="field">
                        <label>Enable Local Archive</label>
                        <label className="check"><input type="checkbox" checked={!!backupSettings.local.enabled} onChange={(e) => setBackupSettings((p) => ({ ...p, local: { ...p.local, enabled: e.target.checked } }))} disabled={isReadOnlyRole} /> Save backups on DomNex host</label>
                      </div>
                      <div className="field">
                        <label>Local Directory</label>
                        <input value={backupSettings.local.dir || '/var/lib/domnexdomain/backups'} onChange={(e) => setBackupSettings((p) => ({ ...p, local: { ...p.local, dir: e.target.value } }))} placeholder="/var/lib/domnexdomain/backups" disabled={isReadOnlyRole} />
                      </div>
                    </div>
                  </div>

                  <div className="card" style={{ marginBottom: '.6rem' }}>
                    <div className="card-head"><h3>FTP Target</h3></div>
                    <div className="field-grid">
                      <div className="field">
                        <label>Enable FTP Upload</label>
                        <label className="check"><input type="checkbox" checked={!!backupSettings.ftp.enabled} onChange={(e) => setBackupSettings((p) => ({ ...p, ftp: { ...p.ftp, enabled: e.target.checked } }))} disabled={isReadOnlyRole} /> Upload each scheduled backup to FTP</label>
                      </div>
                      <div className="field">
                        <label>Host</label>
                        <input value={backupSettings.ftp.host || ''} onChange={(e) => setBackupSettings((p) => ({ ...p, ftp: { ...p.ftp, host: e.target.value } }))} placeholder="ftp.example.net" disabled={isReadOnlyRole} />
                      </div>
                      <div className="field">
                        <label>Port</label>
                        <input type="number" min={1} max={65535} value={String(backupSettings.ftp.port || 21)} onChange={(e) => setBackupSettings((p) => ({ ...p, ftp: { ...p.ftp, port: Number(e.target.value) || 21 } }))} disabled={isReadOnlyRole} />
                      </div>
                      <div className="field">
                        <label>Username</label>
                        <input value={backupSettings.ftp.username || ''} onChange={(e) => setBackupSettings((p) => ({ ...p, ftp: { ...p.ftp, username: e.target.value } }))} placeholder="backup-user" disabled={isReadOnlyRole} />
                      </div>
                      <div className="field">
                        <label>Password</label>
                        <input type="password" value={backupFTPPass} onChange={(e) => setBackupFTPPass(e.target.value)} placeholder={backupSettings.ftp.hasPassword ? 'Stored. Enter only to rotate.' : 'FTP password'} disabled={isReadOnlyRole} />
                      </div>
                      <div className="field">
                        <label>Remote Directory</label>
                        <input value={backupSettings.ftp.remoteDir || '/'} onChange={(e) => setBackupSettings((p) => ({ ...p, ftp: { ...p.ftp, remoteDir: e.target.value } }))} placeholder="/domnex/backups" disabled={isReadOnlyRole} />
                      </div>
                      <div className="field">
                        <label>TLS Mode</label>
                        <select value={backupSettings.ftp.tlsMode || 'explicit'} onChange={(e) => setBackupSettings((p) => ({ ...p, ftp: { ...p.ftp, tlsMode: e.target.value as 'off' | 'explicit' | 'implicit' } }))} disabled={isReadOnlyRole}>
                          <option value="off">FTP (plain)</option>
                          <option value="explicit">FTP explicit TLS</option>
                          <option value="implicit">FTP implicit TLS</option>
                        </select>
                      </div>
                    </div>
                  </div>
                  <div className="row">
                    <button className="btn" onClick={saveBackupSchedule} disabled={loading || isReadOnlyRole}>Save Backup Schedule</button>
                    <button className="btn ghost" onClick={refresh} disabled={loading}>Refresh</button>
                  </div>
                </section>
                ) : null}
              </div>
            </section>
          ) : null}

          {(identity?.role === 'admin' || isReadOnlyRole) && tab === 'users' ? (
            <section className="entity-page users-page">
              <div className="entity-main">
                <section className="card">
                  <div className="card-head"><h3>User Operations</h3></div>
                  <div className="log-filter-grid user-ops-filters">
                    <select value={usersRoleFilter} onChange={(e) => setUsersRoleFilter(e.target.value as 'all' | 'admin' | 'domain-admin' | 'read-only')}>
                      <option value="all">All roles</option>
                      <option value="admin">Global Admin</option>
                      <option value="domain-admin">Domain Admin</option>
                      <option value="read-only">Read Only</option>
                    </select>
                    <input value={usersQuery} onChange={(e) => setUsersQuery(e.target.value)} placeholder="Search username, role, id..." />
                    <div className="row" style={{ marginBottom: 0 }}>
                      <button className="btn" onClick={() => {
                        setNewUserName('');
                        setNewUserPassword('');
                        setNewUserRole('domain-admin');
                        setNewUserDomainIDs([]);
                        setNewUserAllowedCIDRs('');
                        setNewUserIPCheckDisabled(false);
                        setShowCreateUserDialog(true);
                      }} disabled={loading || isReadOnlyRole}>Create User</button>
                      <button className="btn ghost" onClick={refresh} disabled={loading}>Refresh</button>
                    </div>
                  </div>
                  <div className="muted" style={{ marginBottom: '.6rem' }}>
                    Showing {filteredUsers.length} of {users.length} users.
                  </div>
                  <div className="log-table-wrap" style={{ maxHeight: '62vh' }}>
                    <table className="log-table user-table-compact">
                      <thead>
                        <tr>
                          <th>User</th>
                          <th>Role</th>
                          <th>Domain Scope</th>
                          <th>IP Policy</th>
                          <th>Updated</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredUsers.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="muted" style={{ padding: '.9rem' }}>No users match the current filter.</td>
                          </tr>
                        ) : filteredUsers.map((u) => {
                          const scopeNames = domains
                            .filter((d) => (u.domainIds || []).includes(d.id))
                            .map((d) => d.name);
                          const isCurrentUser = identity?.type === 'session' && u.id === identity.userId;
                          return (
                            <tr key={u.id}>
                              <td>
                                <div><strong>{u.username}</strong></div>
                                <div className="muted">ID {u.id}</div>
                              </td>
                              <td><span className="badge warn">{u.role}</span></td>
                              <td>
                                {u.role === 'domain-admin'
                                  ? (scopeNames.length > 0 ? scopeNames.join(', ') : 'none')
                                  : 'global'}
                              </td>
                              <td>
                                {u.ipCheckDisabled ? (
                                  <span className="badge warn">IP check disabled</span>
                                ) : (
                                  <span className="muted">{(u.allowedCidrs || '').trim() || 'default CIDR policy'}</span>
                                )}
                              </td>
                              <td>{formatDateTime(u.updatedAt)}</td>
                              <td>
                                <div className="row" style={{ marginBottom: 0 }}>
                                  <button className="btn ghost" onClick={() => openEditUserDialog(u)} disabled={loading || isCurrentUser || isReadOnlyRole}>Edit</button>
                                  <button className="btn danger" onClick={() => deleteUser(u.id)} disabled={loading || isCurrentUser || isReadOnlyRole}>Delete</button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </section>
              </div>
            </section>
          ) : null}

          {(identity?.role === 'admin' || isReadOnlyRole) && tab === 'api' ? (
            <section className="card">
              <div className="card-head"><h3>API Management</h3></div>
              <div className="row">
                <input value={newTokenName} onChange={(e) => setNewTokenName(e.target.value)} placeholder="token name" />
                <select value={newTokenRole} onChange={(e) => setNewTokenRole(e.target.value)}>
                  <option value="operator">operator</option>
                  <option value="admin">admin</option>
                  <option value="read-only">read-only</option>
                </select>
                <input value={newTokenTTL} onChange={(e) => setNewTokenTTL(e.target.value)} placeholder="720h" />
              </div>
              <div className="domain-pills">
                <label className="pill"><input type="checkbox" checked={newTokenGlobalRead} onChange={(e) => setNewTokenGlobalRead(e.target.checked)} /> global read</label>
                <label className="pill"><input type="checkbox" checked={newTokenGlobalWrite} onChange={(e) => setNewTokenGlobalWrite(e.target.checked)} /> global write</label>
                <label className="pill"><input type="checkbox" checked={newTokenDomainRead} onChange={(e) => setNewTokenDomainRead(e.target.checked)} /> domain read</label>
                <label className="pill"><input type="checkbox" checked={newTokenDomainWrite} onChange={(e) => setNewTokenDomainWrite(e.target.checked)} /> domain write</label>
                <label className="pill"><input type="checkbox" checked={newTokenSystemRead} onChange={(e) => setNewTokenSystemRead(e.target.checked)} /> system read</label>
                <label className="pill"><input type="checkbox" checked={newTokenSystemWrite} onChange={(e) => setNewTokenSystemWrite(e.target.checked)} /> system write</label>
              </div>
              <div className="muted" style={{ marginBottom: '.3rem' }}>Domain scope (only when not global):</div>
              <div className="domain-pills">
                {domains.map((d) => (
                  <label key={d.id} className="pill">
                    <input type="checkbox" checked={newTokenDomainIDs.includes(d.id)} onChange={() => toggleNewTokenDomain(d.id)} disabled={newTokenGlobalRead || newTokenGlobalWrite} />
                    {d.name}
                  </label>
                ))}
              </div>
              <div className="row">
                <input value={newTokenScopes} onChange={(e) => setNewTokenScopes(e.target.value)} placeholder="additional scopes comma-separated (optional)" />
                <button className="btn" onClick={createToken} disabled={loading || !newTokenName || isReadOnlyRole}>Create Token</button>
              </div>
              {createdToken ? (
                <div className="card" style={{ marginBottom: '.8rem' }}>
                  <div className="muted">Generated token (shown once):</div>
                  <pre>{createdToken}</pre>
                </div>
              ) : null}
              <pre>{JSON.stringify(tokens, null, 2)}</pre>
              <div className="row">
                {tokens.map((t) => (
                  <button key={t.id} className="btn" onClick={() => revokeToken(t.id)} disabled={isReadOnlyRole}>Revoke {t.name} ({t.tokenPrefix})</button>
                ))}
              </div>
            </section>
          ) : null}

          {tab === 'help' ? (
            <section className="card">
              <div className="card-head"><h3>Help &amp; Support</h3></div>
              <div className="muted" style={{ marginBottom: '.8rem' }}>
                Documentation and support have been consolidated into official external channels.
              </div>
              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>Official Documentation</h4>
                <div className="row">
                  <a className="btn ghost" href="https://github.com/AsaTyr2018/DomNexDomain/wiki" target="_blank" rel="noreferrer">Open Wiki</a>
                </div>
                <div className="muted" style={{ marginTop: '.4rem' }}>
                  The complete API usage guide has been moved to the official Wiki.
                </div>
              </div>
              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>Community Support</h4>
                <div className="row">
                  <a className="btn ghost" href="https://discord.gg/GnAUmXhfeG" target="_blank" rel="noreferrer">Join Discord</a>
                </div>
              </div>
              <div className="card">
                <h4 style={{ marginTop: 0 }}>Source Code & Issues</h4>
                <div className="row">
                  <a className="btn ghost" href="https://github.com/AsaTyr2018/DomNexDomain" target="_blank" rel="noreferrer">Open Repository</a>
                  <a className="btn ghost" href="https://github.com/AsaTyr2018/DomNexDomain/issues" target="_blank" rel="noreferrer">Open Issues</a>
                </div>
              </div>
            </section>
          ) : null}

          {tab === 'account' ? (
            <section className="entity-page">
              <div className="entity-main">
                <section className="card" style={{ marginBottom: '.6rem' }}>
                  <div className="card-head"><h3>Profile</h3></div>
                  <div className="field-grid">
                    <div className="field">
                      <label>Username</label>
                      <input value={identity?.username || ''} disabled />
                    </div>
                    <div className="field">
                      <label>Role</label>
                      <input value={identity?.role || ''} disabled />
                    </div>
                    <div className="field">
                      <label>Notification Email (future use)</label>
                      <input value={selfNotifyEmail} onChange={(e) => setSelfNotifyEmail(e.target.value)} placeholder="name@example.com" />
                    </div>
                  </div>
                  <div className="row" style={{ marginBottom: 0 }}>
                    <button className="btn" onClick={saveMyProfile} disabled={loading}>Save Profile</button>
                  </div>
                </section>
                <section className="card">
                  <div className="card-head"><h3>Change Password</h3></div>
                  <div className="field-grid">
                    <div className="field">
                      <label>Current Password</label>
                      <input type="password" value={selfCurrentPassword} onChange={(e) => setSelfCurrentPassword(e.target.value)} placeholder="Current password" />
                    </div>
                    <div className="field">
                      <label>New Password</label>
                      <input type="password" value={selfNewPassword} onChange={(e) => setSelfNewPassword(e.target.value)} placeholder="New password (min 10)" />
                    </div>
                    <div className="field">
                      <label>Confirm New Password</label>
                      <input type="password" value={selfConfirmPassword} onChange={(e) => setSelfConfirmPassword(e.target.value)} placeholder="Confirm new password" />
                    </div>
                  </div>
                  <div className="row" style={{ marginBottom: 0 }}>
                    <button className="btn" onClick={changeOwnPassword} disabled={loading || selfNewPassword.length < 10 || selfNewPassword !== selfConfirmPassword}>Save Password</button>
                  </div>
                </section>
              </div>
              <aside className="entity-side">
                <section className="card">
                  <div className="card-head"><h3>Account Notes</h3></div>
                  <div className="muted">Notification email is stored for upcoming alerting features and does not trigger outbound notifications yet.</div>
                </section>
              </aside>
            </section>
          ) : null}

          {tab === 'accessControl' ? (
            <section className="card">
              <div className="card-head"><h3>Access Control</h3></div>
              <div className="badge warn">Coming soon</div>
              <p className="muted">Centralized policy controls for admin/API access hardening, scoped by environment and integration targets.</p>
            </section>
          ) : null}

          {tab === 'integrations' ? (
            <section className="card">
              <div className="card-head"><h3>Integrations</h3></div>
              <div className="badge warn">Coming soon</div>
              <p className="muted">Integration adapters (e.g. DomRoute, DomHA, DomHost) with trusted app handshake and feature panels.</p>
            </section>
          ) : null}

          {(identity?.role === 'admin' || isReadOnlyRole) && tab === 'ssh' ? (
            <section className="entity-page">
              <div className="entity-main">
                <section className="card">
                  <div className="card-head"><h3>SSH Bastion Routes</h3></div>
                  {sshCandidateHosts.length > 0 ? (
                    <div className="muted" style={{ marginBottom: '.45rem' }}>
                      Bastion candidates from Subdomains: {sshCandidateHosts.length} total, {sshUnroutedCandidateHosts.length} without route.
                    </div>
                  ) : (
                    <div className="muted" style={{ marginBottom: '.45rem' }}>
                      No bastion candidates found in Subdomains yet. Create a Subdomain with SSH Bastion first.
                    </div>
                  )}
                  <div className="row">
                    <select value={sshSelectedHostFQDN} onChange={(e) => setSshSelectedHostFQDN(e.target.value)} disabled={isReadOnlyRole}>
                      <option value="">Select Subdomain (recommended)</option>
                      {sshCandidateHosts.map((h) => (
                        <option key={`ssh-cand-${h.id}`} value={h.fqdn}>
                          {h.fqdn}{sshRouteByFQDN[h.fqdn.toLowerCase()] ? ' (configured)' : ''}
                        </option>
                      ))}
                    </select>
                    <input value={sshRouteFQDN} onChange={(e) => setSshRouteFQDN(e.target.value)} placeholder="manual FQDN fallback" disabled={isReadOnlyRole} />
                    <input value={sshRouteTargetHost} onChange={(e) => setSshRouteTargetHost(e.target.value)} placeholder="192.168.1.14" disabled={isReadOnlyRole} />
                    <input value={sshRouteTargetPort} onChange={(e) => setSshRouteTargetPort(e.target.value)} placeholder="22" disabled={isReadOnlyRole} />
                    <label className="check"><input type="checkbox" checked={sshRouteEnabled} onChange={(e) => setSshRouteEnabled(e.target.checked)} disabled={isReadOnlyRole} /> enabled</label>
                    <button className="btn" onClick={saveSSHRoute} disabled={loading || isReadOnlyRole || (!sshSelectedHostFQDN.trim() && !sshRouteFQDN.trim())}>Save Route</button>
                  </div>
                  {sshRoutes.length === 0 ? (
                    <div className="muted">No SSH routes configured.</div>
                  ) : (
                    sshRoutes.map((r) => (
                      <div key={r.id} className="host">
                        <div>
                          <strong>{r.fqdn}</strong>
                          <div className="muted">{r.targetHost}:{r.targetPort} · {r.enabled ? 'enabled' : 'disabled'}</div>
                        </div>
                        <div className="row">
                          <button className="btn" onClick={() => editSSHRoute(r)} disabled={loading || isReadOnlyRole}>Edit</button>
                          <button className="btn" onClick={() => generateSSHKeyForRoute(r.id, r.fqdn)} disabled={loading || isReadOnlyRole}>Generate Host Key</button>
                          <button className="btn danger" onClick={() => deleteSSHRoute(r.id)} disabled={loading || isReadOnlyRole}>Delete</button>
                        </div>
                      </div>
                    ))
                  )}
                </section>
                <section className="card">
                  <div className="card-head"><h3>SSH Bastion Keys</h3></div>
                  <div className="row">
                    <input value={sshKeyName} onChange={(e) => setSshKeyName(e.target.value)} placeholder="user1-key" disabled={isReadOnlyRole} />
                    <button className="btn" onClick={generateSSHKey} disabled={loading || isReadOnlyRole || !sshKeyName || sshKeyRouteIDs.length === 0}>Generate Keypair</button>
                    <button className="btn" onClick={importSSHKey} disabled={loading || isReadOnlyRole || !sshKeyName || !sshKeyPublic || sshKeyRouteIDs.length === 0}>Import Public Key</button>
                  </div>
                  <textarea value={sshKeyPublic} onChange={(e) => setSshKeyPublic(e.target.value)} placeholder="ssh-ed25519 AAAA... user@host" rows={3} disabled={isReadOnlyRole} />
                  <div className="muted" style={{ marginBottom: '.3rem' }}>Allowed routes:</div>
                  <div className="domain-pills">
                    {sshRoutes.map((r) => (
                      <label key={`ssh-route-${r.id}`} className="pill">
                        <input type="checkbox" checked={sshKeyRouteIDs.includes(r.id)} onChange={() => toggleSSHKeyRoute(r.id)} disabled={isReadOnlyRole} />
                        {r.fqdn}
                      </label>
                    ))}
                  </div>
                  {sshGeneratedPrivateKey && !isReadOnlyRole ? (
                    <div className="card" style={{ marginBottom: '.6rem' }}>
                      <div className="muted">Generated private key (shown once):</div>
                      <div className="row" style={{ marginBottom: '.35rem' }}>
                        <button className="btn" onClick={downloadGeneratedLinuxKey} disabled={loading}>Download Linux/macOS Key (.key)</button>
                        <button className="btn" onClick={downloadGeneratedWindowsKey} disabled={loading}>Download Windows Key (.pem)</button>
                        <button className="btn" onClick={downloadGeneratedPPK} disabled={loading || !sshGeneratedPPK}>Download PuTTY Key (.ppk)</button>
                        <button className="btn" onClick={downloadGeneratedPublicKey} disabled={loading || !sshGeneratedPublicKey}>Download Public Key (.pub)</button>
                        <button className="btn" onClick={downloadGeneratedRFC4716} disabled={loading || !sshGeneratedRFC4716}>Download RFC4716 Public (.ssh2)</button>
                      </div>
                      {sshGeneratedPPKError ? <div className="muted" style={{ marginBottom: '.25rem' }}>PPK export unavailable: {sshGeneratedPPKError}</div> : null}
                      <pre>{sshGeneratedPrivateKey}</pre>
                    </div>
                  ) : null}
                  {sshKeys.length === 0 ? (
                    <div className="muted">No SSH keys configured.</div>
                  ) : (
                    sshKeys.map((k) => (
                      <div key={k.id} className="host">
                        <div>
                          <strong>{k.name}</strong>
                          <div className="muted">{isReadOnlyRole ? 'REDACTED' : k.fingerprint}</div>
                          <div className="muted">Routes: {(k.routeIds || []).map((rid) => sshRoutes.find((r) => r.id === rid)?.fqdn || `#${rid}`).join(', ') || '-'}</div>
                        </div>
                        <button className="btn danger" onClick={() => deleteSSHKey(k.id)} disabled={loading || isReadOnlyRole}>Delete</button>
                      </div>
                    ))
                  )}
                </section>
              </div>
              <aside className="entity-side">
                <section className="card">
                  <div className="card-head"><h3>How To Use</h3></div>
                  <div className="muted">Expose only one TCP port externally (e.g. 2222) and enable SSH Bastion in env config.</div>
                  <div className="muted" style={{ marginTop: '.4rem' }}>Users authenticate with assigned key at bastion, then use SSH ProxyJump to allowed targets.</div>
                  <pre>{`Host target1
  HostName 192.168.1.14
  User root
  ProxyJump user1@bastion.yourdomain:2222`}</pre>
                </section>
              </aside>
            </section>
          ) : null}

          {tab === 'audit' ? (
            <section className="logs-page">
              <div className="card">
                <div className="card-head"><h3>LogCenter</h3></div>
                <div className="log-filter-grid">
                  <select value={logWindow} onChange={(e) => setLogWindow(e.target.value as '15m' | '1h' | '6h' | '24h' | '7d' | 'all')}>
                    <option value="15m">Last 15 minutes</option>
                    <option value="1h">Last 1 hour</option>
                    <option value="6h">Last 6 hours</option>
                    <option value="24h">Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="all">All retained</option>
                  </select>
                  <select value={logLevelFilter} onChange={(e) => setLogLevelFilter(e.target.value as 'all' | 'critical' | 'warn' | 'info')}>
                    <option value="all">All levels</option>
                    <option value="critical">Critical</option>
                    <option value="warn">Warning</option>
                    <option value="info">Info</option>
                  </select>
                  <select value={logNamespaceFilter} onChange={(e) => setLogNamespaceFilter(e.target.value)}>
                    <option value="all">All namespaces</option>
                    {logNamespaces.map((n) => <option key={n} value={n}>{n}</option>)}
                  </select>
                  <select value={logActionFilter} onChange={(e) => setLogActionFilter(e.target.value)}>
                    <option value="all">All actions</option>
                    {logActions.map((a) => <option key={a} value={a}>{a}</option>)}
                  </select>
                  <select value={logActorFilter} onChange={(e) => setLogActorFilter(e.target.value)}>
                    <option value="all">All actors</option>
                    {logActors.map((a) => <option key={a} value={a}>{a}</option>)}
                  </select>
                  <select value={logIPFilter} onChange={(e) => setLogIPFilter(e.target.value)}>
                    <option value="all">All source IPs</option>
                    {logIPs.map((ip) => <option key={ip} value={ip}>{ip}</option>)}
                  </select>
                  <select value={logScopeFilter} onChange={(e) => setLogScopeFilter(e.target.value as 'all' | 'internal' | 'external')}>
                    <option value="all">All source scopes</option>
                    <option value="internal">Internal (LAN/loopback)</option>
                    <option value="external">External (internet)</option>
                  </select>
                  <input value={logTargetQuery} onChange={(e) => setLogTargetQuery(e.target.value)} placeholder="Target contains..." />
                  <input value={logQuery} onChange={(e) => setLogQuery(e.target.value)} placeholder="Search action/meta/trace/path..." />
                </div>
                <div className="muted" style={{ marginBottom: '.6rem' }}>
                  Showing {filteredAudit.length} of {logsBaseByWindow.length} events in window.
                </div>
                <div className="log-table-wrap">
                  <table className="log-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Level</th>
                        <th>Namespace</th>
                        <th>Action</th>
                        <th>Actor</th>
                        <th>Target</th>
                        <th>Source</th>
                        <th>Trace</th>
                        <th>Meta</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAudit.length === 0 ? (
                        <tr>
                          <td colSpan={9} className="muted">No events match your filter.</td>
                        </tr>
                      ) : filteredAudit.map((e) => {
                        const level = classifyAuditLevel(e.action, e.target);
                        const src = extractSourceIP(e);
                        const trace = extractTraceID(e);
                        const meta = e.meta || '';
                        const canBlock = identity?.role === 'admin' && !!src && !blockedIPs.some((b) => b.ip === src);
                        return (
                          <tr key={e.id}>
                            <td>{new Date(e.createdAt).toLocaleString()}</td>
                            <td><span className={`badge ${level === 'critical' ? 'err' : level === 'warn' ? 'warn' : 'ok'}`}>{level.toUpperCase()}</span></td>
                            <td>{actionNamespace(e.action)}</td>
                            <td><code>{e.action}</code></td>
                            <td>{e.actor || '-'}</td>
                            <td className="log-target">{e.target || '-'}</td>
                            <td>
                              <div className="log-src-cell">
                                <span>{src || '-'}</span>
                                {canBlock ? (
                                  <button className="btn danger log-mini-btn" onClick={() => blockIP(src, `from audit event ${e.id}`)} disabled={loading}>Block</button>
                                ) : null}
                              </div>
                            </td>
                            <td><code>{trace || '-'}</code></td>
                            <td className="log-meta" title={meta}>{meta || '-'}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          ) : null}
        </main>
      </div>
      ) : null}

      {!identity && setupStatus && !setupStatus.initialized ? (
        <div className="overlay auth-overlay">
          <div className="login-card auth-login-card" style={{ width: 'min(760px, 96vw)' }}>
            <div className="auth-brand">
              <img src="/logo.png" alt="DomNexDomain" />
            </div>
            <h3>Initial Setup Assistant</h3>
            <p className="muted">This instance is not initialized yet. Complete setup to enable normal admin login.</p>
            <div className="wizard-steps">
              <button className={`wiz ${setupStep === 1 ? 'active' : ''}`} onClick={() => setSetupStep(1)}>1. Unlock</button>
              {setupMode === 'restore' ? <button className={`wiz ${setupStep === 2 ? 'active' : ''}`} onClick={() => setSetupStep(2)}>2. Backup</button> : null}
              <button className={`wiz ${setupStep === 3 ? 'active' : ''}`} onClick={() => setSetupStep(3)}>{setupMode === 'restore' ? '3. Admin' : '2. Fresh Setup'}</button>
              <button className={`wiz ${setupStep === 4 ? 'active' : ''}`} onClick={() => setSetupStep(4)}>4. Review</button>
            </div>
            {setupStep === 1 ? (
              <div className="col">
                <div className="field">
                  <label>One-Time Setup Code (OTS)</label>
                  <input value={setupOTS} onChange={(e) => setSetupOTS(e.target.value)} placeholder="Enter OTS from service logs" />
                  <div className="muted">Expires: {setupStatus.otsExpiresAt ? new Date(setupStatus.otsExpiresAt).toLocaleString() : '-'}</div>
                </div>
                <div className="row" style={{ marginBottom: 0 }}>
                  <button className="btn" onClick={setupUnlock} disabled={loading || !setupOTS.trim()}>Unlock Setup</button>
                  <button className="btn" onClick={() => setSetupMode('fresh')} disabled={loading}>Fresh Install</button>
                  <button className="btn" onClick={() => setSetupMode('restore')} disabled={loading}>Restore from Backup</button>
                </div>
              </div>
            ) : null}
            {setupStep === 2 && setupMode === 'restore' ? (
              <div className="col">
                <p className="muted">Upload an encrypted DomNex backup package (`.dnxbak`) and unlock it with its backup passphrase.</p>
                <div className="row">
                  <input type="file" accept=".dnxbak,.bin,.dat,application/octet-stream" onChange={(e) => setSetupBackupFile(e.target.files?.[0] || null)} />
                </div>
                <div className="row">
                  <input type="password" value={setupBackupPassphrase} onChange={(e) => setSetupBackupPassphrase(e.target.value)} placeholder="Backup passphrase (min 12 chars)" />
                </div>
                <div className="row" style={{ marginBottom: 0 }}>
                  <button className="btn" onClick={setupUploadBackup} disabled={loading || !setupBackupFile}>Upload &amp; Analyze</button>
                  <button className="btn" onClick={() => setSetupStep(3)} disabled={!setupBackupMeta}>Continue</button>
                </div>
                {setupBackupMeta ? (
                  <pre>{`File: ${setupBackupMeta.fileName}
Format: ${setupBackupMeta.format}
Created: ${setupBackupMeta.createdAt}
DomNex: ${setupBackupMeta.domnexVersion}
Domains: ${setupBackupMeta.domains}
Subdomains: ${setupBackupMeta.subdomains}
Users: ${setupBackupMeta.users}`}</pre>
                ) : null}
              </div>
            ) : null}
            {setupStep === 3 ? (
              <div className="col">
                <div className="field-grid">
                  <div className="field">
                    <label>Admin Username</label>
                    <input value={setupAdminUser} onChange={(e) => setSetupAdminUser(e.target.value.toLowerCase())} placeholder="admin" />
                  </div>
                  <div className="field">
                    <label>Admin Password</label>
                    <input type="password" value={setupAdminPass} onChange={(e) => setSetupAdminPass(e.target.value)} placeholder="minimum 10 characters" />
                  </div>
                  <div className="field">
                    <label>Confirm Password</label>
                    <input type="password" value={setupAdminPass2} onChange={(e) => setSetupAdminPass2(e.target.value)} placeholder="repeat password" />
                  </div>
                </div>
                {setupMode === 'fresh' ? (
                  <>
                    <div className="field-grid">
                      <div className="field">
                        <label>First Domain</label>
                        <input value={setupDomainName} onChange={(e) => setSetupDomainName(e.target.value.toLowerCase().trim())} placeholder="example.com" />
                      </div>
                      <div className="field">
                        <label>DNS Mode</label>
                        <select value={setupDomainDNSMode} onChange={(e) => setSetupDomainDNSMode(e.target.value as 'manual' | 'cloudflare')}>
                          <option value="cloudflare">Cloudflare</option>
                          <option value="manual">Manual</option>
                        </select>
                      </div>
                      <div className="field">
                        <label>Cert Mode</label>
                        <select value={setupDomainCertMode} onChange={(e) => setSetupDomainCertMode(e.target.value as 'letsencrypt' | 'letsencrypt-catchall')}>
                          <option value="letsencrypt-catchall">Let's Encrypt + Catchall</option>
                          <option value="letsencrypt">Let's Encrypt</option>
                        </select>
                      </div>
                      <div className="field">
                        <label>Cloudflare Zone ID (optional)</label>
                        <input value={setupDomainZoneID} onChange={(e) => setSetupDomainZoneID(e.target.value)} placeholder="zone id" />
                      </div>
                    </div>
                    <div className="field-grid">
                      <div className="field">
                        <label>First Subdomain (optional)</label>
                        <input value={setupFirstSub} onChange={(e) => setSetupFirstSub(e.target.value.toLowerCase())} placeholder="app" />
                      </div>
                      <div className="field">
                        <label>First Upstream (optional)</label>
                        <input value={setupFirstUpstream} onChange={(e) => setSetupFirstUpstream(e.target.value)} placeholder="http://127.0.0.1:3000" />
                      </div>
                    </div>
                    <div className="muted">Cloudflare setup intent: records `@`, `*`, `admin` are auto-managed for first domain.</div>
                  </>
                ) : (
                  <div className="muted">Restore mode keeps infrastructure/runtime settings from backup snapshot. This step only bootstraps admin access.</div>
                )}
                <div className="row" style={{ marginBottom: 0 }}>
                  <button className="btn" onClick={() => setSetupStep(4)} disabled={loading}>Review</button>
                </div>
              </div>
            ) : null}
            {setupStep === 4 ? (
              <div className="col">
                <pre>{`Mode: ${setupMode}
Admin: ${setupAdminUser || '-'}
Domain: ${setupMode === 'fresh' ? (setupDomainName || '-') : '(from backup)'}
Subdomain: ${setupMode === 'fresh' ? (setupFirstSub || '(none)') : '(from backup)'}
Backup: ${setupBackupMeta ? `${setupBackupMeta.fileName} (${setupBackupMeta.format})` : '(none)'}`}</pre>
                <div className="row" style={{ marginBottom: 0 }}>
                  <button className="btn" onClick={applySetup} disabled={loading}>Apply Initial Setup</button>
                  <button className="btn danger" onClick={() => setSetupStep(1)} disabled={loading}>Back to Unlock</button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {!identity && !(setupStatus && !setupStatus.initialized) ? (
        <div className="overlay auth-overlay">
          <div className="login-card auth-login-card">
            <div className="auth-brand">
              <img src="/logo.png" alt="DomNexDomain" />
            </div>
            <h3>Control Plane Login</h3>
            <p className="muted">Sign in with your admin account to continue.</p>
            <div className="col">
              <input value={loginUser} onChange={(e) => setLoginUser(e.target.value)} placeholder="Username" />
              <input type="password" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} placeholder="Password" />
              <button className="btn" onClick={login} disabled={loading}>Login</button>
            </div>
          </div>
        </div>
      ) : null}

      {identity && deleteHostDialogOpen ? (
        <div className="overlay">
          <div className="login-card">
            <h3>Delete Subdomain</h3>
            <p className="muted">This action is permanent for <strong>{deleteHostLabel}</strong>. Type <strong>Remove</strong> to confirm.</p>
            <div className="col">
              <input value={deleteHostConfirmText} onChange={(e) => setDeleteHostConfirmText(e.target.value)} placeholder='Type "Remove"' />
              <div className="row" style={{ marginBottom: 0 }}>
                <button className="btn danger" onClick={confirmDeleteHost} disabled={loading || deleteHostConfirmText.trim() !== 'Remove'}>Delete Now</button>
                <button className="btn" onClick={closeDeleteHostDialog} disabled={loading}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {identity && showCreateUserDialog ? (
        <div className="overlay">
          <div className="login-card modal-card user-edit-modal" style={{ maxWidth: '760px', width: '94vw' }}>
            <h3>Create User</h3>
            <p className="muted">Create a new account and assign initial access.</p>
            <div className="field-grid">
              <div className="field">
                <label>Username</label>
                <input value={newUserName} onChange={(e) => setNewUserName(e.target.value.toLowerCase().trim())} placeholder="username" />
              </div>
              <div className="field">
                <label>Temporary Password</label>
                <input type="password" value={newUserPassword} onChange={(e) => setNewUserPassword(e.target.value)} placeholder="minimum 10 characters" />
              </div>
              <div className="field">
                <label>Role</label>
                <select value={newUserRole} onChange={(e) => setNewUserRole(e.target.value as 'admin' | 'domain-admin' | 'read-only')}>
                  <option value="domain-admin">Domain Admin</option>
                  <option value="read-only">Read Only</option>
                  <option value="admin">Global Admin</option>
                </select>
              </div>
              <div className="field">
                <label>IP Access CIDRs (optional)</label>
                <input value={newUserAllowedCIDRs} onChange={(e) => setNewUserAllowedCIDRs(e.target.value)} placeholder="e.g. 192.168.1.0/24, 203.0.113.8/32" disabled={newUserIPCheckDisabled} />
              </div>
              <div className="field">
                <label>IP Policy</label>
                <label className="check">
                  <input type="checkbox" checked={newUserIPCheckDisabled} onChange={(e) => setNewUserIPCheckDisabled(e.target.checked)} />
                  Disable IP check
                </label>
              </div>
            </div>
            {newUserRole === 'domain-admin' ? (
              <div className="field">
                <label>Domain Scope</label>
                <div className="domain-pills">
                  {domains.map((d) => (
                    <label key={`new-user-domain-${d.id}`} className="pill">
                      <input type="checkbox" checked={newUserDomainIDs.includes(d.id)} onChange={() => toggleNewUserDomain(d.id)} />
                      {d.name}
                    </label>
                  ))}
                </div>
              </div>
            ) : null}
            <div className="row" style={{ marginBottom: 0 }}>
              <button className="btn" onClick={createUser} disabled={loading || !newUserName || !newUserPassword || (newUserRole === 'domain-admin' && newUserDomainIDs.length === 0)}>Create User</button>
              <button className="btn danger" onClick={() => setShowCreateUserDialog(false)} disabled={loading}>Cancel</button>
            </div>
          </div>
        </div>
      ) : null}

      {identity && editingUser ? (
        <div className="overlay">
          <div className="login-card modal-card user-edit-modal" style={{ maxWidth: '860px', width: '95vw' }}>
            <h3>Edit User: {editingUser.username}</h3>
            <p className="muted">Update role, scope, and optional password reset in one operation.</p>
            <div className="field-grid">
              <div className="field">
                <label>Role</label>
                <select value={editUserRole} onChange={(e) => setEditUserRole(e.target.value as 'admin' | 'domain-admin' | 'read-only')}>
                  <option value="domain-admin">Domain Admin</option>
                  <option value="read-only">Read Only</option>
                  <option value="admin">Global Admin</option>
                </select>
              </div>
              <div className="field">
                <label>Password Reset (optional)</label>
                <input type="password" value={editUserPassword} onChange={(e) => setEditUserPassword(e.target.value)} placeholder="leave blank to keep current password" />
              </div>
              <div className="field">
                <label>IP Access CIDRs (optional)</label>
                <input value={editUserAllowedCIDRs} onChange={(e) => setEditUserAllowedCIDRs(e.target.value)} placeholder="e.g. 192.168.1.0/24, 203.0.113.8/32" disabled={editUserIPCheckDisabled} />
              </div>
              <div className="field">
                <label>IP Policy</label>
                <label className="check">
                  <input type="checkbox" checked={editUserIPCheckDisabled} onChange={(e) => setEditUserIPCheckDisabled(e.target.checked)} />
                  Disable IP check
                </label>
              </div>
            </div>
            {editUserRole === 'domain-admin' ? (
              <div className="field">
                <label>Domain Scope</label>
                <div className="domain-pills">
                  {domains.map((d) => (
                    <label key={`edit-user-domain-${d.id}`} className="pill">
                      <input type="checkbox" checked={editUserDomainIDs.includes(d.id)} onChange={() => toggleEditUserDomain(d.id)} />
                      {d.name}
                    </label>
                  ))}
                </div>
              </div>
            ) : null}
            <div className="row" style={{ marginBottom: 0 }}>
              <button className="btn" onClick={saveUserEdit} disabled={loading || (editUserRole === 'domain-admin' && editUserDomainIDs.length === 0)}>Save Changes</button>
              <button className="btn danger" onClick={closeEditUserDialog} disabled={loading}>Cancel</button>
            </div>
          </div>
        </div>
      ) : null}

      {identity && tiFeedsOpen ? (
        <div className="overlay modal-overlay">
          <div className="login-card modal-card" style={{ maxWidth: '1100px', width: '95vw' }}>
            <div className="modal-head">
              <h3>Threat Intel Feeds</h3>
            </div>
            <div className="row modal-controls">
              <input value={tiFeedName} onChange={(e) => setTiFeedName(e.target.value)} placeholder="feed name" disabled={isReadOnlyRole || identity?.role !== 'admin'} />
              <input value={tiFeedURL} onChange={(e) => setTiFeedURL(e.target.value)} placeholder="https://provider/feed.txt" disabled={isReadOnlyRole || identity?.role !== 'admin'} />
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: '.45rem' }}>
                <input type="checkbox" checked={tiFeedEnabled} onChange={(e) => setTiFeedEnabled(e.target.checked)} disabled={isReadOnlyRole || identity?.role !== 'admin'} />
                Enabled
              </label>
              <button className="btn" onClick={addThreatIntelFeed} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Add Feed</button>
              <button className="btn" onClick={() => setTiFeedsOpen(false)}>Close</button>
            </div>
            <div className="modal-body">
              <div className="log-table-wrap modal-table-wrap">
                <table className="log-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>URL</th>
                      <th>Entries</th>
                      <th>Last Sync</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tiFeeds.map((f) => (
                      <tr key={`ti-feed-modal-${f.id}`}>
                        <td>{f.name}{f.isDefault ? <span className="badge ok" style={{ marginLeft: '.35rem' }}>default</span> : null}</td>
                        <td><code>{f.url}</code></td>
                        <td>{f.entryCount || 0}</td>
                        <td>{f.lastSyncAt ? new Date(f.lastSyncAt).toLocaleString() : '-'}</td>
                        <td>{f.lastError ? <span className="badge err">error</span> : <span className={`badge ${f.enabled ? 'ok' : 'warn'}`}>{f.enabled ? 'enabled' : 'disabled'}</span>}</td>
                        <td>
                          <div className="row" style={{ marginBottom: 0 }}>
                            <button className="btn" onClick={() => toggleThreatIntelFeed(f)} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>{f.enabled ? 'Disable' : 'Enable'}</button>
                            {!f.isDefault ? <button className="btn danger" onClick={() => deleteThreatIntelFeed(f.id)} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Delete</button> : null}
                          </div>
                          {f.lastError ? <div className="muted" style={{ marginTop: '.3rem' }}>{f.lastError}</div> : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {identity && tiAllowOpen ? (
        <div className="overlay modal-overlay">
          <div className="login-card modal-card" style={{ maxWidth: '1000px', width: '94vw' }}>
            <div className="modal-head">
              <h3>Threat Intel Allowlist Overrides</h3>
            </div>
            <div className="row modal-controls">
              <input value={tiAllowIP} onChange={(e) => setTiAllowIP(e.target.value)} placeholder="IP to allowlist" disabled={isReadOnlyRole || identity?.role !== 'admin'} />
              <input value={tiAllowReason} onChange={(e) => setTiAllowReason(e.target.value)} placeholder="reason" disabled={isReadOnlyRole || identity?.role !== 'admin'} />
              <button className="btn" onClick={addThreatIntelAllow} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Add</button>
              <button className="btn" onClick={() => setTiAllowOpen(false)}>Close</button>
            </div>
            <div className="modal-body">
              <div className="log-table-wrap modal-table-wrap">
                <table className="log-table">
                  <thead>
                    <tr>
                      <th>IP</th>
                      <th>Reason</th>
                      <th>Updated</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tiAllowlist.length === 0 ? (
                      <tr><td colSpan={4} className="muted">No allowlist overrides.</td></tr>
                    ) : tiAllowlist.map((a) => (
                      <tr key={`ti-allow-modal-${a.ip}`}>
                        <td><code>{a.ip}</code></td>
                        <td>{a.reason || '-'}</td>
                        <td>{a.updatedAt ? new Date(a.updatedAt).toLocaleString() : '-'}</td>
                        <td><button className="btn danger" onClick={() => threatIntelUnallowIP(a.ip)} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Remove</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {identity && tiBlockedOpen ? (
        <div className="overlay modal-overlay">
          <div className="login-card modal-card" style={{ maxWidth: '1150px', width: '96vw' }}>
            <div className="modal-head">
              <h3>Threat Intel Blocked Entries</h3>
            </div>
            <div className="row modal-controls">
              <div className="muted">Consolidated blocked list with XP/Level/Tier state. Total blocked: {tiTotalBlocked}</div>
              <button className="btn" onClick={openThreatIntelBlocked} disabled={loading}>Refresh</button>
              <button className="btn" onClick={() => setTiBlockedOpen(false)}>Close</button>
            </div>
            <div className="modal-body">
              <div className="log-table-wrap modal-table-wrap">
                <table className="log-table">
                  <thead>
                    <tr>
                      <th>IP</th>
                      <th>Reason</th>
                      <th>History</th>
                      <th>Hits</th>
                      <th>Feeds</th>
                      <th>Hosts</th>
                      <th className="ti-tier-col">Tier</th>
                      <th>Last Seen</th>
                      <th>Blocked At</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tiBlocked.length === 0 ? (
                      <tr><td colSpan={10} className="muted">No blocked entries in current filter.</td></tr>
                    ) : tiBlocked.map((b) => (
                      <tr key={`ti-blocked-${b.ip}`}>
                        <td><code>{b.ip}</code></td>
                        <td>{b.reason || '-'}</td>
                        <td className="muted">{humanizeThreatDecisionText(b.history || '') || '-'}</td>
                        <td>{b.totalHits || 0}</td>
                        <td>{b.distinctFeeds || 0}</td>
                        <td>{b.distinctHosts || 0}</td>
                        <td className="ti-tier-col"><span className={`badge ${b.riskState === 'hardblock' ? 'err' : b.riskState === 'softblock' ? 'warn' : 'ok'}`}>{(b.tier || 'tier0').toUpperCase()} · L{b.level || 0} · XP {b.xp || 0}</span></td>
                        <td>{b.lastSeenAt ? new Date(b.lastSeenAt).toLocaleString() : '-'}</td>
                        <td>{b.updatedAt ? new Date(b.updatedAt).toLocaleString() : '-'}</td>
                        <td>
                          <div className="row" style={{ marginBottom: 0 }}>
                            <button className="btn danger" onClick={() => unblockIP(b.ip)} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Unblock</button>
                            <button className="btn" onClick={() => threatIntelAllowIP(b.ip, 'allow from blocked list')} disabled={loading || isReadOnlyRole || identity?.role !== 'admin'}>Allow</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {identity && tiTargetsOpen ? (
        <div className="overlay modal-overlay">
          <div className="login-card modal-card" style={{ maxWidth: '1100px', width: '95vw' }}>
            <div className="modal-head">
              <h3>Threat Targets for {tiTargetsIP}</h3>
            </div>
            <div className="row modal-controls">
              <div className="muted">Consolidated by IP in Threat Data. Targets are expanded here.</div>
              <button className="btn" onClick={() => setTiTargetsOpen(false)}>Close</button>
            </div>
            <div className="modal-body">
              <div className="log-table-wrap modal-table-wrap">
                <table className="log-table">
                  <thead>
                    <tr>
                      <th>Host</th>
                      <th>Path</th>
                      <th>Feed</th>
                      <th>Decision</th>
                      <th>Hits</th>
                      <th>Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tiTargets.length === 0 ? (
                      <tr><td colSpan={6} className="muted">No target details available.</td></tr>
                    ) : tiTargets.map((t, idx) => (
                      <tr key={`ti-target-${idx}`}>
                        <td>{t.host || '-'}</td>
                        <td><code>{t.path || '/'}</code></td>
                        <td>{t.feed || '-'}</td>
                        <td><span className={`badge ${threatDecisionBadge(t.decision).cls}`}>{threatDecisionBadge(t.decision).label}</span></td>
                        <td>{t.hits || 0}</td>
                        <td>{t.lastSeenAt ? new Date(t.lastSeenAt).toLocaleString() : '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {identity && metricMapOpen ? (
        <div className="overlay modal-overlay">
          <div className="login-card modal-card geo-modal-card" style={{ maxWidth: '1280px', width: '98vw' }}>
            <div className="modal-head">
              <h3>Global Geo Map</h3>
            </div>
            <div className="row modal-controls">
              <div className="muted">
                {metricMapMode === 'live'
                  ? `Live Trace ${metricLiveConnected ? 'connected' : 'disconnected'} · TTL 10s · Current filter: ${metricCountryFocus.toUpperCase()}`
                  : metricMapMode === 'threat'
                    ? `Threat Intel Map · ${metricThreatGeoAt ? `snapshot ${new Date(metricThreatGeoAt).toLocaleTimeString()}` : 'loading'} · Current filter: ${metricCountryFocus.toUpperCase()}`
                  : `Click country bubbles to focus. Current filter: ${metricCountryFocus.toUpperCase()}`}
              </div>
              <select value={metricMapMode} onChange={(e) => setMetricMapMode(e.target.value === 'live' ? 'live' : e.target.value === 'threat' ? 'threat' : 'historical')}>
                <option value="historical">Historical</option>
                <option value="live">Live Trace</option>
                <option value="threat">Threat Intel Map</option>
              </select>
              <button className="btn" onClick={() => setMetricCountryFocus('all')}>Reset Country Filter</button>
              {metricMapMode === 'threat' ? (
                <button className="btn" onClick={loadThreatGeoMap}>Refresh Threat Map</button>
              ) : null}
              <button className="btn" onClick={() => setMetricMapOpen(false)}>Close</button>
            </div>
            <div className="modal-body geo-modal-body">
              {metricMapMode === 'live' ? (
                <GeoLiveTraceMap points={metricLivePoints} onSelectCountry={(code) => setMetricCountryFocus(code)} />
              ) : metricMapMode === 'threat' ? (
                <GeoThreatIntelMap points={metricThreatGeo} countryFocus={metricCountryFocus} onSelectCountry={(code) => setMetricCountryFocus(code)} />
              ) : (
                <GeoScatterMap countries={metricFilteredCountries} onSelectCountry={(code) => setMetricCountryFocus(code)} />
              )}
            </div>
          </div>
        </div>
      ) : null}

      <style>{`
        :root { --bg:${activeTheme.bg}; --surface:${activeTheme.surface}; --panel:${activeTheme.panel}; --panel-hover:${activeTheme.panelHover}; --border:${activeTheme.border}; --text:${activeTheme.text}; --text-dim:${activeTheme.textDim}; --accent:${activeTheme.accent}; --accent-hover:${activeTheme.accentHover}; --accent-active:${activeTheme.accentActive}; --accent-soft:${activeTheme.accentSoft}; --green:${activeTheme.success}; --red:${activeTheme.danger}; --input-bg:${activeTheme.inputBg}; --hero-a:${activeTheme.heroA}; --hero-b:${activeTheme.heroB}; --radius:12px; }
        * { box-sizing: border-box; }
        body { margin:0; font-family:'Inter', system-ui, sans-serif; font-size:15px; background:var(--bg); color:var(--text); }
        .app-shell { display:grid; grid-template-columns:240px 1fr; min-height:100vh; }
        .sidebar {
          background:var(--surface);
          border-right:1px solid var(--border);
          height:100vh;
          position:sticky;
          top:0;
          display:flex;
          flex-direction:column;
          overflow:hidden;
        }
        .logo {
          padding:1.5rem .85rem 1rem;
          display:grid;
          place-items:center;
          position:sticky;
          top:0;
          z-index:3;
          background:var(--surface);
          border-bottom:1px solid var(--border);
          flex:0 0 auto;
        }
        .logo img {
          width:100%;
          max-width:220px;
          height:auto;
          display:block;
          border-radius:16px;
          filter: drop-shadow(0 3px 10px rgba(0,0,0,.28));
          -webkit-mask-image:
            radial-gradient(125% 105% at 50% 48%, rgba(0,0,0,1) 48%, rgba(0,0,0,.86) 62%, rgba(0,0,0,.52) 78%, rgba(0,0,0,0) 100%),
            linear-gradient(to bottom, rgba(0,0,0,0) 0%, rgba(0,0,0,.95) 16%, rgba(0,0,0,.95) 84%, rgba(0,0,0,0) 100%),
            linear-gradient(to right, rgba(0,0,0,0) 0%, rgba(0,0,0,.96) 12%, rgba(0,0,0,.96) 88%, rgba(0,0,0,0) 100%);
          mask-image:
            radial-gradient(125% 105% at 50% 48%, rgba(0,0,0,1) 48%, rgba(0,0,0,.86) 62%, rgba(0,0,0,.52) 78%, rgba(0,0,0,0) 100%),
            linear-gradient(to bottom, rgba(0,0,0,0) 0%, rgba(0,0,0,.95) 16%, rgba(0,0,0,.95) 84%, rgba(0,0,0,0) 100%),
            linear-gradient(to right, rgba(0,0,0,0) 0%, rgba(0,0,0,.96) 12%, rgba(0,0,0,.96) 88%, rgba(0,0,0,0) 100%);
          -webkit-mask-composite: source-in;
          mask-composite: intersect;
        }
        .menu { display:grid; gap:.25rem; padding:.8rem .5rem 1rem; overflow-y:auto; min-height:0; flex:1 1 auto; }
        .menu-group { display:grid; gap:.25rem; margin-bottom:.35rem; }
        .menu-title { color:var(--text-dim); font-size:.7rem; letter-spacing:.08em; text-transform:uppercase; padding:.35rem .9rem .15rem; }
        .menu button { text-align:left; background:transparent; border:1px solid transparent; color:var(--text-dim); padding:.85rem 1rem; border-radius:10px; cursor:pointer; font-size:.9rem; }
        .menu button:hover, .menu button.active { background:var(--accent-soft); color:var(--accent); }
        .main { padding:2.5rem 3rem; }
        .top { display:flex; justify-content:space-between; align-items:center; gap:1rem; margin-bottom:1.25rem; }
        h1 { margin:0; font-size:2.2rem; letter-spacing:-.6px; }
        .subtitle { margin:.25rem 0 0; color:var(--text-dim); }
        .top-actions { display:flex; gap:.5rem; }
        .dashboard { display:grid; gap:1rem; }
        .dashboard-grid { display:grid; gap:1rem; grid-template-columns:repeat(12, minmax(0, 1fr)); grid-auto-rows:minmax(72px, auto); align-items:start; }
        .dashboard-widget { min-height:120px; }
        .dashboard-editor-layout { display:grid; gap:1rem; grid-template-columns:minmax(320px,.85fr) minmax(0,1.15fr); align-items:start; }
        .kpi-row { display:grid; gap:1rem; grid-template-columns:repeat(4,minmax(0,1fr)); }
        .dashboard-layout { display:grid; gap:1rem; grid-template-columns:minmax(0,1.7fr) minmax(320px,1fr); align-items:start; }
        .dashboard-main { display:grid; gap:1rem; }
        .dashboard-side { display:grid; gap:1rem; min-width:0; }
        .snapshot-row { display:grid; gap:1rem; grid-template-columns:repeat(2,minmax(0,1fr)); }
        .entity-page { display:grid; gap:1rem; grid-template-columns:minmax(0,1.7fr) minmax(320px,1fr); align-items:start; }
        .entity-main { display:grid; gap:1rem; }
        .entity-side { display:grid; gap:1rem; }
        .threatintel-page { grid-template-columns:minmax(0,1fr); }
        .threatintel-page .entity-main,
        .threatintel-page .entity-side { min-width:0; }
        .threatintel-page .entity-side { grid-template-columns:minmax(0,1fr); }
        .threatintel-page .log-table { min-width:900px; }
        .threatintel-page .log-table-wrap { max-height:560px; }
        .ti-filter-grid { grid-template-columns:repeat(3,minmax(0,1fr)); }
        .cc-hero { background:
          radial-gradient(900px 300px at 88% -35%, var(--hero-a), transparent 58%),
          radial-gradient(900px 300px at 12% -45%, var(--hero-b), transparent 58%),
          var(--surface);
        }
        .cc-head { display:flex; justify-content:space-between; align-items:flex-start; gap:1rem; margin-bottom:.85rem; }
        .cc-head h3 { margin:0 0 .25rem; }
        .btn.ghost { background:var(--panel); border:1px solid var(--border); color:var(--text); text-decoration:none; display:inline-flex; align-items:center; }
        .btn.ghost:hover { background:var(--panel-hover); }
        .cc-header-grid { display:grid; gap:.65rem; margin-bottom:.75rem; }
        .cc-title { display:flex; align-items:center; gap:.6rem; font-size:1.02rem; margin-bottom:.65rem; }
        .cc-pills { display:flex; flex-wrap:wrap; gap:.45rem; }
        .cc-pill { border:1px solid var(--border); background:var(--panel); color:var(--text-dim); border-radius:999px; padding:.28rem .62rem; font-size:.76rem; }
        .cc-pill.ok { border-color:#1d5a45; color:#9df3cb; background:#103227; }
        .cc-pill.warn { border-color:#6b4d19; color:#ffd89a; background:#3a2a0f; }
        .cc-kpi-strip { display:grid; gap:.6rem; grid-template-columns:repeat(4,minmax(0,1fr)); }
        .cc-kpi { border:1px solid var(--border); border-radius:10px; padding:.55rem .65rem; background:var(--panel); display:grid; gap:.2rem; }
        .cc-kpi span { color:var(--text-dim); font-size:.73rem; }
        .cc-kpi strong { font-size:1rem; }
        .cc-diag-inline { margin-top:.7rem; padding-top:.55rem; border-top:1px solid #2a2a35; }
        .cc-section-label { color:var(--text-dim); font-size:.72rem; text-transform:uppercase; letter-spacing:.09em; margin-top:.15rem; margin-bottom:-.45rem; padding-left:.15rem; }
        .cc-block { border-color:#2a2a35; }
        .cc-panel { background:linear-gradient(180deg, rgba(18,18,24,.95), rgba(22,22,26,.95)); }
        .cc-split { display:grid; gap:1rem; grid-template-columns:repeat(2,minmax(0,1fr)); }
        .cc-danger { border-color:#7f1d1d; background:linear-gradient(180deg, rgba(127,29,29,.12), rgba(22,22,26,.85)); }
        .gauge-grid { display:grid; gap:.8rem; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); }
        .gauge-card { background:var(--panel); border:1px solid var(--border); border-radius:11px; padding:.75rem; display:grid; justify-items:center; gap:.45rem; }
        .gauge-ring { width:92px; height:92px; border-radius:999px; display:grid; place-items:center; }
        .gauge-inner { width:68px; height:68px; border-radius:999px; background:var(--panel); border:1px solid var(--border); display:grid; place-items:center; font-weight:700; }
        .gauge-title { font-size:.82rem; text-align:center; }
        .gauge-sub { font-size:.74rem; color:var(--text-dim); text-align:center; }
        .metric-grid { display:grid; gap:.8rem; grid-template-columns:repeat(2,minmax(0,1fr)); }
        .ops-alert-strip { display:grid; gap:.6rem; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); }
        .ops-alert-chip { border:1px solid var(--border); border-radius:11px; padding:.55rem .65rem; background:var(--panel); min-width:0; }
        .ops-alert-chip.ok { border-color:#1d5a45; background:#103227; }
        .ops-alert-chip.warn { border-color:#6b4d19; background:#3a2a0f; }
        .ops-alert-chip.err { border-color:#6b2222; background:#3a1717; }
        .metric-v2-layout { display:grid; gap:1rem; grid-template-columns:minmax(280px,.95fr) minmax(320px,.95fr) minmax(460px,1.3fr); align-items:start; }
        .metric-v2-panel { min-height:0; }
        .metric-scroll { max-height:58vh; }
        .metric-table-wrap { max-height:58vh; }
        .metric-problem-table { min-width:0; table-layout:fixed; }
        .metric-problem-table th, .metric-problem-table td { white-space:normal; word-break:break-word; }
        .metric-center-page { grid-template-columns:minmax(0,1fr); }
        .metric-center-page .entity-side { grid-template-columns:repeat(2,minmax(0,1fr)); }
        .metric-tile { background:var(--panel); border:1px solid var(--border); border-radius:11px; padding:.75rem; min-width:0; }
        .metric-label { color:var(--text-dim); font-size:.78rem; margin-bottom:.35rem; }
        .metric-value { font-size:1.2rem; font-weight:700; line-height:1.2; margin-bottom:.25rem; overflow-wrap:anywhere; word-break:break-word; }
        .metric-hint { color:var(--text-dim); font-size:.75rem; }
        .event-list { display:grid; gap:.55rem; max-height:360px; overflow:auto; }
        .event-item { padding:.55rem .6rem; border:1px solid var(--border); border-radius:9px; background:var(--panel); }
        .event-top { display:flex; justify-content:space-between; align-items:center; gap:.6rem; margin-bottom:.2rem; }
        .geo-map-wrap { border:1px solid #2a2a35; border-radius:12px; background:
          radial-gradient(700px 200px at 95% -45%, rgba(14,165,233,.2), transparent 55%),
          radial-gradient(700px 200px at 5% -45%, rgba(34,197,94,.16), transparent 55%),
          #0f1117;
          padding:.65rem;
        }
        .geo-map-svg { width:100%; height:auto; display:block; }
        .geo-map-vector path { fill:#24164a; stroke:#8b5cf6; stroke-width:.85; opacity:.92; }
        .geo-map-vector path:hover { fill:#2f1d5f; }
        .geo-map-grid { stroke:#2b3140; stroke-width:1; opacity:.75; }
        .geo-map-bubble { fill:#22c55e; stroke:#a7f3d0; stroke-width:1.5; }
        .geo-map-label { fill:#d1d5db; font-size:11px; font-weight:600; }
        .logs-page { display:grid; gap:1rem; grid-template-columns:minmax(0,1fr); align-items:start; }
        .logs-side { display:grid; gap:1rem; }
        .logs-list { max-height:620px; }
        .log-filter-grid { display:grid; gap:.55rem; grid-template-columns:repeat(3,minmax(0,1fr)); margin-bottom:.7rem; }
        .log-table-wrap { border:1px solid var(--border); border-radius:11px; overflow:auto; max-height:640px; background:var(--panel); }
        .log-table { width:100%; border-collapse:collapse; font-size:.86rem; min-width:1080px; }
        .log-table th, .log-table td { border-bottom:1px solid var(--border); padding:.48rem .55rem; text-align:left; vertical-align:top; }
        .log-table th { position:sticky; top:0; z-index:1; background:var(--surface); color:var(--text-dim); font-size:.73rem; text-transform:uppercase; letter-spacing:.06em; }
        .log-table tbody tr:hover { background:var(--panel-hover); }
        .log-src-cell { display:flex; align-items:center; gap:.35rem; flex-wrap:wrap; }
        .log-mini-btn { padding:.2rem .45rem; border-radius:8px; font-size:.72rem; }
        .log-meta { max-width:320px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .log-target { max-width:220px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:1rem; }
        .card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:1rem; }
        .card.wide { grid-column:span 2; }
        .card-head { display:flex; justify-content:space-between; align-items:center; margin-bottom:.8rem; }
        .card-head h3 { margin:0; }
        .value { font-size:2rem; font-weight:700; }
        .status { width:10px; height:10px; border-radius:999px; }
        .status.ok { background:var(--green); }
        .status.err { background:var(--red); }
        .btn { background:var(--accent); color:#fff; border:none; border-radius:10px; padding:.65rem 1rem; cursor:pointer; }
        .btn:hover { background:var(--accent-hover); }
        .btn.danger { background:#b91c1c; }
        .btn.danger:hover { background:#991b1b; }
        .btn:disabled { opacity:.6; cursor:not-allowed; }
        .row { display:flex; gap:.6rem; flex-wrap:wrap; margin-bottom:.8rem; }
        .field { display:grid; gap:.35rem; margin-bottom:.8rem; min-width:0; }
        .field > label { font-size:.78rem; color:var(--text-dim); letter-spacing:.02em; }
        .field-grid { display:grid; gap:.6rem; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); margin-bottom:.8rem; }
        .users-page { grid-template-columns:minmax(0,1fr); }
        .user-ops-filters { grid-template-columns:minmax(180px,.8fr) minmax(220px,1.2fr) auto; align-items:center; }
        .user-ops-filters .row { justify-content:flex-end; }
        .user-table-compact { min-width:980px; font-size:.82rem; }
        .user-table-compact th, .user-table-compact td { padding:.4rem .5rem; }
        .user-edit-modal .domain-pills { max-height:170px; overflow:auto; padding-right:.2rem; }
        input, select, textarea { background:var(--input-bg); border:1px solid var(--border); color:var(--text); border-radius:9px; padding:.6rem .75rem; }
        textarea { min-height:6rem; width:100%; }
        .wizard-steps { display:flex; gap:.5rem; margin-bottom:.8rem; flex-wrap:wrap; }
        .wiz { background:#111118; color:var(--text-dim); border:1px solid var(--border); border-radius:10px; padding:.5rem .75rem; cursor:pointer; }
        .wiz.active { color:var(--text); border-color:var(--accent); background:var(--accent-soft); }
        .check { display:flex; align-items:center; gap:.5rem; margin-bottom:.5rem; color:var(--text-dim); }
        .domain-pills { display:flex; flex-wrap:wrap; gap:.45rem; margin:.4rem 0 .8rem; }
        .pill { display:flex; align-items:center; gap:.35rem; background:#111118; border:1px solid var(--border); border-radius:999px; padding:.3rem .6rem; color:var(--text-dim); }
        ol { margin-top:.2rem; margin-bottom:.8rem; padding-left:1.2rem; }
        pre { margin:0; background:#101015; border:1px solid var(--border); border-radius:10px; padding:.75rem; overflow:auto; }
        .host { display:flex; justify-content:space-between; align-items:flex-start; gap:.6rem; border-top:1px solid var(--border); padding:.55rem 0; font-size:.9rem; }
        .subdomain-group { margin-top:.65rem; border:1px solid var(--border); border-radius:10px; background:var(--panel); padding:.5rem .7rem; }
        .subdomain-group + .subdomain-group { margin-top:.8rem; }
        .subdomain-group .host:first-of-type { border-top:1px solid var(--border); }
        .subdomain-group-head {
          display:flex;
          align-items:center;
          justify-content:space-between;
          gap:.5rem;
          padding:.15rem 0 .35rem;
          font-size:.88rem;
          border-bottom:1px solid var(--border);
          margin-bottom:.1rem;
        }
        .host-fqdn-link {
          color: var(--accent);
          text-decoration: none;
          border-bottom: 1px dotted transparent;
          transition: color .15s ease, border-color .15s ease, opacity .15s ease;
        }
        .host-fqdn-link:hover {
          color: var(--accent-hover);
          border-bottom-color: var(--accent-hover);
        }
        .host-fqdn-link:focus-visible {
          outline: 2px solid var(--accent);
          outline-offset: 2px;
          border-radius: 4px;
        }
        .diag { display:flex; gap:.35rem; flex-wrap:wrap; margin-top:.35rem; }
        .diag-block { margin-top:.4rem; }
        .badge { font-size:.74rem; padding:.15rem .45rem; border-radius:999px; border:1px solid transparent; display:inline-flex; align-items:center; white-space:nowrap; }
        .badge.ok { background:#103227; border-color:#1d5a45; color:#9df3cb; }
        .badge.warn { background:#3a2a0f; border-color:#6b4d19; color:#ffd89a; }
        .badge.err { background:#3a1717; border-color:#6b2222; color:#ffb3b3; }
        .ti-tier-col { min-width:160px; white-space:nowrap; }
        .ti-feed-col { min-width:260px; word-break:break-word; }
        .muted { color:var(--text-dim); }
        .errtxt { color:#fca5a5; }
        .error { margin-bottom:1rem; background:#3a1a1a; border:1px solid #7f1d1d; color:#fecaca; padding:.7rem .9rem; border-radius:10px; }
        .overlay { position:fixed; inset:0; z-index:10000; background:rgba(0,0,0,.5); display:grid; place-items:center; padding:1rem; }
        .modal-overlay { display:flex; align-items:center; justify-content:center; overflow:auto; }
        .auth-overlay {
          background:
            radial-gradient(800px 350px at 85% -10%, rgba(34,197,94,.16), transparent 52%),
            radial-gradient(1000px 420px at 8% -20%, rgba(14,165,233,.18), transparent 56%),
            #090b10;
        }
        .login-card { width:min(420px,100%); background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:1rem; }
        .login-card h3 { margin-top:0; }
        .modal-card { position:relative; z-index:10001; max-height:calc(100vh - 2rem); display:flex; flex-direction:column; overflow:hidden; }
        .modal-head { flex:0 0 auto; }
        .modal-controls { flex:0 0 auto; }
        .modal-body { flex:1 1 auto; min-height:0; overflow:auto; }
        .geo-modal-card { max-height:calc(100vh - 2rem); }
        .geo-modal-body { overflow:hidden; }
        .geo-modal-body .geo-map-wrap {
          height:calc(100vh - 220px);
          max-height:760px;
          min-height:320px;
          display:flex;
          flex-direction:column;
        }
        .geo-modal-body .geo-map-svg {
          flex:1 1 auto;
          min-height:0;
          width:100%;
          height:100%;
        }
        .modal-table-wrap { max-height:none; height:100%; min-height:0; }
        .modal-table-wrap .log-table th { position:static; top:auto; z-index:auto; }
        .auth-login-card { width:min(460px,100%); border-color:#2b3445; background:linear-gradient(180deg, rgba(18,22,32,.95), rgba(15,18,28,.95)); }
        .auth-brand { display:grid; place-items:center; margin-bottom:.5rem; }
        .auth-brand img {
          width:100%;
          max-width:260px;
          height:auto;
          display:block;
          border-radius:16px;
          filter: drop-shadow(0 3px 10px rgba(0,0,0,.28));
          -webkit-mask-image:
            radial-gradient(125% 105% at 50% 48%, rgba(0,0,0,1) 48%, rgba(0,0,0,.86) 62%, rgba(0,0,0,.52) 78%, rgba(0,0,0,0) 100%),
            linear-gradient(to bottom, rgba(0,0,0,0) 0%, rgba(0,0,0,.95) 16%, rgba(0,0,0,.95) 84%, rgba(0,0,0,0) 100%),
            linear-gradient(to right, rgba(0,0,0,0) 0%, rgba(0,0,0,.96) 12%, rgba(0,0,0,.96) 88%, rgba(0,0,0,0) 100%);
          mask-image:
            radial-gradient(125% 105% at 50% 48%, rgba(0,0,0,1) 48%, rgba(0,0,0,.86) 62%, rgba(0,0,0,.52) 78%, rgba(0,0,0,0) 100%),
            linear-gradient(to bottom, rgba(0,0,0,0) 0%, rgba(0,0,0,.95) 16%, rgba(0,0,0,.95) 84%, rgba(0,0,0,0) 100%),
            linear-gradient(to right, rgba(0,0,0,0) 0%, rgba(0,0,0,.96) 12%, rgba(0,0,0,.96) 88%, rgba(0,0,0,0) 100%);
          -webkit-mask-composite: source-in;
          mask-composite: intersect;
        }
        .col { display:grid; gap:.6rem; }
        @media (max-width:1150px){ .kpi-row{grid-template-columns:repeat(2,minmax(0,1fr));} .dashboard-layout{grid-template-columns:1fr;} .entity-page{grid-template-columns:1fr;} .logs-page{grid-template-columns:1fr;} .ops-alert-strip{grid-template-columns:repeat(3,minmax(0,1fr));} .metric-v2-layout{grid-template-columns:1fr;} .metric-center-page .entity-side{grid-template-columns:1fr;} .cc-kpi-strip{grid-template-columns:repeat(2,minmax(0,1fr));} .cc-split{grid-template-columns:1fr;} .log-filter-grid{grid-template-columns:repeat(2,minmax(0,1fr));} .user-ops-filters{grid-template-columns:1fr 1fr;} .user-ops-filters .row{justify-content:flex-start;} .snapshot-row{grid-template-columns:1fr;} }
        @media (max-width:900px){ .app-shell{grid-template-columns:1fr;} .sidebar{border-right:none;border-bottom:1px solid var(--border);height:auto;position:static;overflow:visible;} .logo{position:static;border-bottom:none;padding:1rem .85rem .35rem;} .menu{overflow:visible;padding:0 .5rem .8rem;} .main{padding:1rem;} .card.wide{grid-column:auto;} .dashboard-grid{grid-template-columns:1fr;} .dashboard-widget{grid-column:span 1 !important; grid-row:auto !important;} .dashboard-editor-layout{grid-template-columns:1fr;} .kpi-row{grid-template-columns:1fr;} .ops-alert-strip{grid-template-columns:1fr;} .metric-grid{grid-template-columns:1fr;} .ti-filter-grid{grid-template-columns:1fr;} .threatintel-page .log-table{min-width:760px;} .user-ops-filters{grid-template-columns:1fr;} .user-table-compact{min-width:760px;} .snapshot-row{grid-template-columns:1fr;} }
      `}</style>
    </>
  );
}

function Card({ title, value, status }: { title: string; value: string; status: 'ok' | 'err' }) {
  return (
    <div className="card">
      <div className="card-head">
        <h3>{title}</h3>
        <span className={`status ${status}`} />
      </div>
      <div className="value">{value}</div>
    </div>
  );
}

function threatDecisionBadge(decision: string): { cls: 'ok' | 'warn' | 'err'; label: string } {
  const d = (decision || '').trim().toLowerCase();
  if (d === 'monitor_observe') return { cls: 'ok', label: 'Monitor' };
  if (d === 'soft_block_set') return { cls: 'warn', label: 'Soft set' };
  if (d === 'soft_block_active') return { cls: 'warn', label: 'Soft active' };
  if (d === 'hard_block_set') return { cls: 'err', label: 'Hard set' };
  if (d === 'hard_block_permanent') return { cls: 'err', label: 'Hard active' };
  if (d === 'watch_boost') return { cls: 'warn', label: 'Watch boost' };
  if (d.includes('hard')) return { cls: 'err', label: 'Hard' };
  if (d.includes('soft')) return { cls: 'warn', label: 'Soft' };
  if (d.includes('block')) return { cls: 'err', label: 'Block' };
  if (d.includes('check')) return { cls: 'warn', label: 'Check' };
  if (d.includes('monitor') || d.includes('observe')) return { cls: 'ok', label: 'Monitor' };
  return { cls: 'ok', label: 'Other' };
}

function threatDecisionList(decisions: string): string[] {
  const inRaw = (decisions || '').trim();
  if (!inRaw) return ['monitor_observe'];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of inRaw.split(',')) {
    const d = raw.trim().toLowerCase();
    if (!d || seen.has(d)) continue;
    seen.add(d);
    out.push(d);
  }
  return out.length > 0 ? out : ['monitor_observe'];
}

function humanizeThreatDecisionText(input: string): string {
  let s = (input || '').trim();
  if (!s) return '';
  s = s.replaceAll('monitor_observe', 'Monitor');
  s = s.replaceAll('soft_block_set', 'Soft set');
  s = s.replaceAll('soft_block_active', 'Soft active');
  s = s.replaceAll('hard_block_set', 'Hard set');
  s = s.replaceAll('hard_block_permanent', 'Hard active');
  s = s.replaceAll('watch_boost', 'Watch boost');
  return s;
}

function classifyAuditLevel(action: string, target: string): 'critical' | 'warn' | 'info' {
  const s = `${action} ${target}`.toLowerCase();
  if (s.includes("auth.login.locked")) return 'critical';
  if (s.includes("auth.login.failed")) return 'warn';
  if (s.includes("proxy.error")) return 'warn';
  if (s.includes('delete') || s.includes('revoke') || s.includes('password-reset') || s.includes('reset')) return 'critical';
  if (s.includes('update') || s.includes('upsert') || s.includes('retry') || s.includes('reload')) return 'warn';
  return 'info';
}

function extractSourceIP(e: Audit): string {
  const direct = (e.sourceIp || '').trim();
  if (direct) return direct;
  const meta = (e.meta || '').trim();
  if (!meta) return '';
  const parts = meta.split(';').map((p) => p.trim());
  const src = parts.find((p) => p.startsWith('source='));
  if (!src) return '';
  return src.slice('source='.length).trim();
}

function extractTraceID(e: Audit): string {
  const meta = (e.meta || '').trim();
  if (!meta) return '';
  const parts = meta.split(';').map((p) => p.trim());
  const trace = parts.find((p) => p.startsWith('trace='));
  if (!trace) return '';
  return trace.slice('trace='.length).trim();
}

function extractTraceNeedles(query: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const re = /[a-f0-9]{8,}/gi;
  let m: RegExpExecArray | null = null;
  while ((m = re.exec(query)) !== null) {
    const v = (m[0] || '').toLowerCase();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

function formatDateTime(v?: string): string {
  if (!v) return '-';
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return '-';
  return d.toLocaleString();
}

function actionNamespace(action: string): string {
  const a = (action || '').trim().toLowerCase();
  if (!a) return 'other';
  const dot = a.indexOf('.');
  if (dot <= 0) return a;
  return a.slice(0, dot);
}

function classifySourceScope(ip: string, publicIPv4: string): 'internal' | 'external' {
  const raw = (ip || '').trim();
  if (!raw) return 'external';
  if (raw === '127.0.0.1' || raw === '::1') return 'internal';
  if (publicIPv4 && raw === publicIPv4) return 'internal';
  if (raw.startsWith('10.')) return 'internal';
  if (raw.startsWith('192.168.')) return 'internal';
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(raw)) return 'internal';
  if (raw.startsWith('fc') || raw.startsWith('fd') || raw.startsWith('fe80:')) return 'internal';
  return 'external';
}

function hostStateBadge(state: string): { cls: 'ok' | 'warn' | 'err'; label: string } {
  const s = (state || '').toLowerCase();
  if (s === 'active') return { cls: 'ok', label: 'Active' };
  if (s === 'maintenance') return { cls: 'warn', label: 'Maintenance' };
  if (s === 'disabled') return { cls: 'warn', label: 'Disabled' };
  if (s === 'error') return { cls: 'err', label: 'Error' };
  if (s === 'cert_manager_async') return { cls: 'warn', label: 'Provisioning' };
  if (s === 'cert_pending') return { cls: 'warn', label: 'Cert Pending' };
  if (s === 'dns_pending') return { cls: 'warn', label: 'DNS Pending' };
  if (s === 'created') return { cls: 'warn', label: 'Created' };
  return { cls: 'warn', label: state || 'Unknown' };
}

function domainStatusBadge(status?: string): { cls: 'ok' | 'warn' | 'err'; label: string } {
  const s = (status || '').toLowerCase().trim();
  if (s === 'active' || s === '') return { cls: 'ok', label: 'Active' };
  if (s === 'inactive') return { cls: 'warn', label: 'Inactive' };
  return { cls: 'warn', label: status || 'Unknown' };
}

function domainWildcardBadge(d: Domain): { cls: 'ok' | 'warn' | 'err'; label: string } {
  const dns = (d.dnsMode || '').toLowerCase().trim();
  const cert = (d.certMode || '').toLowerCase().trim();
  if (dns !== 'cloudflare') return { cls: 'err', label: 'Off' };
  if (cert.includes('catchall')) return { cls: 'ok', label: 'On' };
  if (cert.startsWith('letsencrypt')) return { cls: 'ok', label: 'On' };
  return { cls: 'err', label: 'Off' };
}

function normalizeBackends(items: HABackend[]): HABackend[] {
  const out: HABackend[] = [];
  const seen = new Set<string>();
  items.forEach((it, idx) => {
    const url = (it.url || '').trim();
    if (!url || seen.has(url)) return;
    seen.add(url);
    const name = (it.name || '').trim() || `backend-${idx + 1}`;
    out.push({ name, url });
  });
  return out;
}

function parseCountryCodes(raw: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  raw.split(/[,\s]+/).forEach((it) => {
    const code = it.trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(code) || seen.has(code)) return;
    seen.add(code);
    out.push(code);
  });
  return out;
}

function formatBytes(v: number): string {
  if (!Number.isFinite(v) || v <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let n = v;
  let idx = 0;
  while (n >= 1024 && idx < units.length - 1) {
    n /= 1024;
    idx++;
  }
  return `${n >= 100 || idx === 0 ? n.toFixed(0) : n.toFixed(1)} ${units[idx]}`;
}

const GEO_PRESETS: Record<string, string[]> = {
  DACH: ['DE', 'AT', 'CH'],
  EU: ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'],
  'North America': ['US', 'CA', 'MX'],
  'DACH + EU': ['DE', 'AT', 'CH', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'],
};

function mergeCountryCodes(baseRaw: string, add: string[]): string {
  const merged = [...parseCountryCodes(baseRaw), ...add];
  return parseCountryCodes(merged.join(',')).join(', ');
}

function Gauge({ title, value, subtitle, strictFull = false }: { title: string; value: number; subtitle: string; strictFull?: boolean }) {
  const clamped = Math.max(0, Math.min(100, value));
  const deg = Math.round((clamped / 100) * 360);
  const color = strictFull ? (clamped === 100 ? '#10b981' : '#ef4444') : (clamped <= 70 ? '#10b981' : clamped <= 90 ? '#f59e0b' : '#ef4444');
  return (
    <div className="gauge-card">
      <div className="gauge-ring" style={{ background: `conic-gradient(${color} ${deg}deg, #2a2a31 ${deg}deg)` }}>
        <div className="gauge-inner">{clamped}%</div>
      </div>
      <div className="gauge-title">{title}</div>
      <div className="gauge-sub">{subtitle}</div>
    </div>
  );
}

const METRIC_WORLD_VIEWBOX = { w: 1009.6727, h: 665.963 };
const METRIC_WORLD_GEO_BOUNDS = {
  leftLon: -169.110266,
  topLat: 83.600842,
  rightLon: 190.486279,
  bottomLat: -58.508473,
};
const COUNTRY_LONLAT: Record<string, { lon: number; lat: number }> = {
  US: { lon: -98, lat: 39 }, CA: { lon: -106, lat: 56 }, MX: { lon: -102, lat: 23 },
  BR: { lon: -51, lat: -10 }, AR: { lon: -64, lat: -35 }, CL: { lon: -71, lat: -33 }, CO: { lon: -74, lat: 4 },
  GB: { lon: -2, lat: 54 }, IE: { lon: -8, lat: 53 }, FR: { lon: 2, lat: 46 }, ES: { lon: -4, lat: 40 }, PT: { lon: -8, lat: 39 },
  DE: { lon: 10, lat: 51 }, NL: { lon: 5, lat: 52 }, BE: { lon: 4, lat: 50.5 }, IT: { lon: 12, lat: 42 }, CH: { lon: 8, lat: 47 },
  AT: { lon: 14, lat: 47.5 }, PL: { lon: 19, lat: 52 }, SE: { lon: 16, lat: 62 }, NO: { lon: 10, lat: 62 }, FI: { lon: 26, lat: 64 },
  DK: { lon: 10, lat: 56 }, CZ: { lon: 15, lat: 49.8 }, RO: { lon: 25, lat: 45.8 }, HU: { lon: 19, lat: 47.2 }, GR: { lon: 22, lat: 39 },
  AD: { lon: 1.6, lat: 42.5 }, LT: { lon: 23.9, lat: 55.2 }, DO: { lon: -70.2, lat: 18.9 },
  TR: { lon: 35, lat: 39 }, UA: { lon: 31, lat: 49 }, RU: { lon: 90, lat: 60 },
  MA: { lon: -7, lat: 31 }, DZ: { lon: 3, lat: 28 }, EG: { lon: 30, lat: 27 }, NG: { lon: 8, lat: 9 }, ZA: { lon: 24, lat: -29 }, KE: { lon: 37, lat: 0.5 },
  SA: { lon: 45, lat: 24 }, AE: { lon: 54, lat: 24 }, IL: { lon: 35, lat: 31 }, IN: { lon: 78, lat: 22 }, PK: { lon: 70, lat: 30 },
  CN: { lon: 104, lat: 35 }, JP: { lon: 138, lat: 36 }, KR: { lon: 127, lat: 36 }, TW: { lon: 121, lat: 23.5 }, HK: { lon: 114, lat: 22.3 },
  SG: { lon: 103.8, lat: 1.35 }, ID: { lon: 113, lat: -2 }, AU: { lon: 134, lat: -25 }, NZ: { lon: 174, lat: -41 },
};
const CONTINENT_LABELS = [
  { text: 'North America', x: 220, y: 390 },
  { text: 'Canada', x: 185, y: 245 },
  { text: 'South America', x: 260, y: 505 },
  { text: 'Europe', x: 475, y: 185 },
  { text: 'Africa', x: 525, y: 505 },
  { text: 'Asia', x: 860, y: 190 },
  { text: 'Australia', x: 860, y: 585 },
];

function extractSvgInnerMarkup(svg: string): string {
  const cleaned = svg.replace(/<\?xml[\s\S]*?\?>/gi, '').replace(/<!DOCTYPE[\s\S]*?>/gi, '');
  const match = cleaned.match(/<svg[\s\S]*?>([\s\S]*?)<\/svg>/i);
  return (match?.[1] || cleaned).trim();
}

function projectToMetricSvg(lon: number, lat: number): { x: number; y: number } {
  const { leftLon, rightLon, topLat, bottomLat } = METRIC_WORLD_GEO_BOUNDS;
  const lonSpan = rightLon - leftLon;
  const nx = lonSpan <= 0 ? 0.5 : (lon - leftLon) / lonSpan;
  const merc = (deg: number): number => {
    const clamped = Math.max(-85, Math.min(85, deg));
    const rad = (clamped * Math.PI) / 180;
    return Math.log(Math.tan(Math.PI / 4 + rad / 2));
  };
  const topM = merc(topLat);
  const bottomM = merc(bottomLat);
  const latM = merc(lat);
  const ny = Math.abs(topM - bottomM) < 1e-9 ? 0.5 : (topM - latM) / (topM - bottomM);
  return {
    x: Math.max(0, Math.min(1, nx)) * METRIC_WORLD_VIEWBOX.w,
    y: Math.max(0, Math.min(1, ny)) * METRIC_WORLD_VIEWBOX.h,
  };
}

const COUNTRY_LABEL_NUDGE: Record<string, { dx: number; dy: number }> = {
  DE: { dx: 16, dy: -2 },
  NL: { dx: -10, dy: -12 },
  FR: { dx: -18, dy: 6 },
  CH: { dx: 8, dy: 10 },
  BE: { dx: -12, dy: 12 },
  RU: { dx: 8, dy: -2 },
  SG: { dx: 8, dy: 6 },
  ID: { dx: 10, dy: 4 },
  US: { dx: 10, dy: 2 },
};

function GeoScatterMap({ countries, onSelectCountry }: { countries: CountryTraffic[]; onSelectCountry?: (code: string) => void }) {
  const [mapInner, setMapInner] = useState<string>('');
  const normalized = (countries || [])
    .map((c) => ({ ...c, code: String(c.country || '').trim().toUpperCase() }))
    .filter((c) => c.code && COUNTRY_LONLAT[c.code]);

  useEffect(() => {
    let canceled = false;
    fetch('/metric-worldmap.svg')
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(`map fetch failed: ${r.status}`))))
      .then((txt) => {
        if (!canceled) setMapInner(extractSvgInnerMarkup(txt));
      })
      .catch(() => {
        if (!canceled) setMapInner('');
      });
    return () => {
      canceled = true;
    };
  }, []);

  if (normalized.length === 0) {
    return <div className="muted">No mappable country data yet.</div>;
  }
  if (!mapInner) {
    return <div className="muted">Loading map geometry...</div>;
  }

  const topReq = Math.max(1, ...normalized.map((c) => c.requests || 0));
  return (
    <div className="geo-map-wrap">
      <svg
        className="geo-map-svg"
        viewBox={`0 0 ${METRIC_WORLD_VIEWBOX.w} ${METRIC_WORLD_VIEWBOX.h}`}
        role="img"
        aria-label="Request geo map"
      >
        <g className="geo-map-vector" dangerouslySetInnerHTML={{ __html: mapInner }} />
        {[0.2, 0.4, 0.6, 0.8].map((r, i) => (
          <line
            key={`h-${i}`}
            x1={0}
            y1={METRIC_WORLD_VIEWBOX.h * r}
            x2={METRIC_WORLD_VIEWBOX.w}
            y2={METRIC_WORLD_VIEWBOX.h * r}
            className="geo-map-grid"
          />
        ))}
        {[0.2, 0.4, 0.6, 0.8].map((r, i) => (
          <line
            key={`v-${i}`}
            x1={METRIC_WORLD_VIEWBOX.w * r}
            y1={0}
            x2={METRIC_WORLD_VIEWBOX.w * r}
            y2={METRIC_WORLD_VIEWBOX.h}
            className="geo-map-grid"
          />
        ))}
        {CONTINENT_LABELS.map((it) => (
          <text key={it.text} x={it.x} y={it.y} className="geo-map-label muted">
            {it.text}
          </text>
        ))}
        {normalized.map((c) => {
          const ll = COUNTRY_LONLAT[c.code];
          const p = projectToMetricSvg(ll.lon, ll.lat);
          const radius = Math.min(13, 3 + Math.round(((c.requests || 0) / topReq) * 8));
          const n = COUNTRY_LABEL_NUDGE[c.code] || { dx: radius + 4, dy: 3 };
          return (
            <g key={c.code} style={{ cursor: onSelectCountry ? 'pointer' : 'default' }} onClick={() => onSelectCountry?.(c.code)}>
              <circle cx={p.x} cy={p.y} r={radius} className="geo-map-bubble" style={{ opacity: 0.2 + ((c.requests || 0) / topReq) * 0.8 }} />
              <text x={p.x + n.dx} y={p.y + n.dy} className="geo-map-label">{c.code}</text>
            </g>
          );
        })}
      </svg>
      <div className="muted" style={{ marginTop: '.45rem' }}>
        Bubble size = request volume in selected window.
      </div>
    </div>
  );
}

function GeoLiveTraceMap({ points, onSelectCountry }: { points: LiveTracePoint[]; onSelectCountry?: (code: string) => void }) {
  const [mapInner, setMapInner] = useState<string>('');
  useEffect(() => {
    let canceled = false;
    fetch('/metric-worldmap.svg')
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(`map fetch failed: ${r.status}`))))
      .then((txt) => {
        if (!canceled) setMapInner(extractSvgInnerMarkup(txt));
      })
      .catch(() => {
        if (!canceled) setMapInner('');
      });
    return () => {
      canceled = true;
    };
  }, []);
  if (!mapInner) {
    return <div className="muted">Loading map geometry...</div>;
  }
  const now = Date.now();
  const ttlMs = 10_000;
  const visible = points.filter((p) => now - p.seenAt <= ttlMs && COUNTRY_LONLAT[p.country]);
  return (
    <div className="geo-map-wrap">
      <svg className="geo-map-svg" viewBox={`0 0 ${METRIC_WORLD_VIEWBOX.w} ${METRIC_WORLD_VIEWBOX.h}`} role="img" aria-label="Live trace geo map">
        <g className="geo-map-vector" dangerouslySetInnerHTML={{ __html: mapInner }} />
        {[0.2, 0.4, 0.6, 0.8].map((r, i) => (
          <line key={`h-live-${i}`} x1={0} y1={METRIC_WORLD_VIEWBOX.h * r} x2={METRIC_WORLD_VIEWBOX.w} y2={METRIC_WORLD_VIEWBOX.h * r} className="geo-map-grid" />
        ))}
        {[0.2, 0.4, 0.6, 0.8].map((r, i) => (
          <line key={`v-live-${i}`} x1={METRIC_WORLD_VIEWBOX.w * r} y1={0} x2={METRIC_WORLD_VIEWBOX.w * r} y2={METRIC_WORLD_VIEWBOX.h} className="geo-map-grid" />
        ))}
        {CONTINENT_LABELS.map((it) => (
          <text key={`live-${it.text}`} x={it.x} y={it.y} className="geo-map-label muted">{it.text}</text>
        ))}
        {visible.map((p) => {
          const ll = COUNTRY_LONLAT[p.country];
          const base = projectToMetricSvg(ll.lon, ll.lat);
          const jitterSeed = p.id.split('').reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
          const jx = ((jitterSeed % 7) - 3) * 1.35;
          const jy = (((Math.floor(jitterSeed / 7)) % 7) - 3) * 1.35;
          const age = Math.max(0, now - p.seenAt);
          const life = 1 - (age / ttlMs);
          const radius = p.scanner ? 4.8 : 3.8;
          const fill = p.scanner ? '#ef4444' : '#22c55e';
          const stroke = p.scanner ? '#fecaca' : '#a7f3d0';
          return (
            <g key={p.id} onClick={() => onSelectCountry?.(p.country)} style={{ cursor: onSelectCountry ? 'pointer' : 'default' }}>
              <circle cx={base.x + jx} cy={base.y + jy} r={radius + (1 - life) * 2} fill={fill} opacity={Math.max(0.12, life * 0.42)} />
              <circle cx={base.x + jx} cy={base.y + jy} r={radius} fill={fill} stroke={stroke} strokeWidth={1.2} opacity={Math.max(0.2, life)} />
            </g>
          );
        })}
      </svg>
      <div className="row" style={{ marginTop: '.45rem', marginBottom: 0, justifyContent: 'space-between' }}>
        <div className="muted">Live points: {visible.length} (TTL 10s)</div>
        <div className="row" style={{ marginBottom: 0 }}>
          <span className="badge ok">Normal</span>
          <span className="badge err">Bot/Scanner</span>
        </div>
      </div>
    </div>
  );
}

function GeoThreatIntelMap({ points, countryFocus, onSelectCountry }: { points: ThreatGeoPoint[]; countryFocus: string; onSelectCountry?: (code: string) => void }) {
  const [mapInner, setMapInner] = useState<string>('');
  const [showMonitor, setShowMonitor] = useState(true);
  const [showSoft, setShowSoft] = useState(true);
  const [showHard, setShowHard] = useState(true);
  useEffect(() => {
    let canceled = false;
    fetch('/metric-worldmap.svg')
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(`map fetch failed: ${r.status}`))))
      .then((txt) => {
        if (!canceled) setMapInner(extractSvgInnerMarkup(txt));
      })
      .catch(() => {
        if (!canceled) setMapInner('');
      });
    return () => {
      canceled = true;
    };
  }, []);
  if (!mapInner) {
    return <div className="muted">Loading map geometry...</div>;
  }
  const normalized = (points || [])
    .map((p) => ({
      country: String(p.country || '').trim().toUpperCase(),
      state: p.state === 'hard' ? 'hard' : p.state === 'soft' ? 'soft' : 'monitor',
      ips: Number(p.ips || 0),
      hits: Number(p.hits || 0),
    }))
    .filter((p) => p.country && COUNTRY_LONLAT[p.country] && p.ips > 0);
  const stateVisible = (state: 'monitor' | 'soft' | 'hard') =>
    (state === 'monitor' && showMonitor) || (state === 'soft' && showSoft) || (state === 'hard' && showHard);
  const filteredByState = normalized.filter((p) => stateVisible(p.state));
  const filtered = countryFocus === 'all' ? filteredByState : filteredByState.filter((p) => p.country === countryFocus.toUpperCase());
  if (filtered.length === 0) {
    return <div className="muted">No threat geo points for this filter.</div>;
  }
  const maxIPs = Math.max(1, ...filtered.map((p) => p.ips));
  const stateColor = (state: 'monitor' | 'soft' | 'hard') => {
    if (state === 'hard') return { fill: '#ef4444', stroke: '#fecaca' };
    if (state === 'soft') return { fill: '#f59e0b', stroke: '#fde68a' };
    return { fill: '#22c55e', stroke: '#a7f3d0' };
  };
  const unknown = (points || []).filter((p) => String(p.country || '').trim().toUpperCase() === 'ZZ').reduce((acc, p) => acc + Number(p.ips || 0), 0);
  const monitorIPs = normalized.filter((p) => p.state === 'monitor').reduce((acc, p) => acc + p.ips, 0);
  const softIPs = normalized.filter((p) => p.state === 'soft').reduce((acc, p) => acc + p.ips, 0);
  const hardIPs = normalized.filter((p) => p.state === 'hard').reduce((acc, p) => acc + p.ips, 0);
  return (
    <div className="geo-map-wrap">
      <svg className="geo-map-svg" viewBox={`0 0 ${METRIC_WORLD_VIEWBOX.w} ${METRIC_WORLD_VIEWBOX.h}`} role="img" aria-label="Threat intel geo map">
        <g className="geo-map-vector" dangerouslySetInnerHTML={{ __html: mapInner }} />
        {[0.2, 0.4, 0.6, 0.8].map((r, i) => (
          <line key={`h-ti-${i}`} x1={0} y1={METRIC_WORLD_VIEWBOX.h * r} x2={METRIC_WORLD_VIEWBOX.w} y2={METRIC_WORLD_VIEWBOX.h * r} className="geo-map-grid" />
        ))}
        {[0.2, 0.4, 0.6, 0.8].map((r, i) => (
          <line key={`v-ti-${i}`} x1={METRIC_WORLD_VIEWBOX.w * r} y1={0} x2={METRIC_WORLD_VIEWBOX.w * r} y2={METRIC_WORLD_VIEWBOX.h} className="geo-map-grid" />
        ))}
        {CONTINENT_LABELS.map((it) => (
          <text key={`ti-${it.text}`} x={it.x} y={it.y} className="geo-map-label muted">{it.text}</text>
        ))}
        {filtered.map((p) => {
          const ll = COUNTRY_LONLAT[p.country];
          const pos = projectToMetricSvg(ll.lon, ll.lat);
          const radius = Math.min(18, 5 + Math.round((p.ips / maxIPs) * 13));
          const c = stateColor(p.state);
          return (
            <g key={`${p.country}-${p.state}`} onClick={() => onSelectCountry?.(p.country)} style={{ cursor: onSelectCountry ? 'pointer' : 'default' }}>
              <circle cx={pos.x} cy={pos.y} r={radius + 2} fill={c.fill} opacity={0.2} />
              <circle cx={pos.x} cy={pos.y} r={radius} fill={c.fill} stroke={c.stroke} strokeWidth={1.4} opacity={0.95} />
              <text x={pos.x + radius + 3} y={pos.y + 3} className="geo-map-label">{p.country}</text>
            </g>
          );
        })}
      </svg>
      <div className="row" style={{ marginTop: '.45rem', marginBottom: 0, justifyContent: 'space-between' }}>
        <div className="muted">Threat IPs mapped: {filtered.reduce((acc, p) => acc + p.ips, 0)} · Unknown (ZZ): {unknown}</div>
        <div className="row" style={{ marginBottom: 0 }}>
          <button className="btn ghost" style={{ opacity: showMonitor ? 1 : 0.45 }} onClick={() => setShowMonitor((v) => !v)}>
            <span className="badge ok" style={{ marginRight: '.35rem' }}>Monitor</span>{monitorIPs}
          </button>
          <button className="btn ghost" style={{ opacity: showSoft ? 1 : 0.45 }} onClick={() => setShowSoft((v) => !v)}>
            <span className="badge warn" style={{ marginRight: '.35rem' }}>Soft block</span>{softIPs}
          </button>
          <button className="btn ghost" style={{ opacity: showHard ? 1 : 0.45 }} onClick={() => setShowHard((v) => !v)}>
            <span className="badge err" style={{ marginRight: '.35rem' }}>Hard block</span>{hardIPs}
          </button>
        </div>
      </div>
    </div>
  );
}

function MetricTile({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="metric-tile">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-hint">{hint}</div>
    </div>
  );
}

function AlertChip({ label, value, state }: { label: string; value: string; state: 'ok' | 'warn' | 'critical' }) {
  const cls = state === 'critical' ? 'err' : state === 'warn' ? 'warn' : 'ok';
  return (
    <div className={`ops-alert-chip ${cls}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <RootErrorBoundary>
    <App />
  </RootErrorBoundary>,
);
