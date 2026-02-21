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
type RuntimeSettings = { domain: string; baseDomain?: string; adminFqdn?: string; acmeEmail: string; acmeStaging: boolean; hasCloudflareToken: boolean; publicIpv4?: string; styleProfile?: string; styleCustom?: string; timeSyncMode?: 'system_only' | 'external_public' | 'external_lan'; timeSyncLANServers?: string[]; logServers?: LogServerSettings; hasLogHTTPBearer?: boolean };
type TimeSyncProbe = { name: string; target: string; ok: boolean; offsetMs: number; rttMs: number; error?: string; detail?: string };
type TimeSyncStatus = { mode: 'system_only' | 'external_public' | 'external_lan'; healthy: boolean; severity: 'ok' | 'warn' | 'critical'; summary: string; source?: string; offsetMs?: number; checkedAt: string; probes: TimeSyncProbe[] };
type ManagedUser = { id: number; username: string; role: string; domainIds: number[]; createdAt: string; updatedAt: string };
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

type Tab = 'dashboard' | 'metricCenter' | 'threatIntel' | 'domains' | 'hosts' | 'users' | 'settings' | 'api' | 'apiDocs' | 'ssh' | 'audit';
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
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const [loginUser, setLoginUser] = useState('admin');
  const [loginPass, setLoginPass] = useState('');
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
  const [timeSyncStatus, setTimeSyncStatus] = useState<TimeSyncStatus | null>(null);
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
  const [showPasswordDialog, setShowPasswordDialog] = useState(false);
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

  const refresh = async () => {
    setLoading(true);
    setError('');
    try {
      await api('/api/v1/csrf');
      const me = await api<{ identity: Identity }>('/api/v1/me');
      setIdentity(me.identity);
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
      } catch {
        setSettings(null);
        setSettingsPublicIPv4('');
        setSettingsBaseDomain('');
        setSettingsStyleProfile('monolith');
        setSettingsStyleCustom('');
        setSettingsTimeSyncMode('system_only');
        setSettingsTimeSyncLAN('');
        setSettingsLogServers(defaultLogServers());
      }
      try {
        const ts = await api<TimeSyncStatus>('/api/v1/time-sync');
        setTimeSyncStatus(ts);
      } catch {
        setTimeSyncStatus(null);
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
      if (err.status === 401 || /unauthorized/i.test(err.message)) {
        setIdentity(null);
        setDomains([]);
        setHosts([]);
        setAudit([]);
        setTrafficOverview(null);
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
      setTimeSyncStatus(null);
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
  const globalAdmins = users.filter((u) => u.role === 'admin').length;
  const domainAdmins = users.filter((u) => u.role === 'domain-admin').length;
  const readOnlyUsers = users.filter((u) => u.role === 'read-only').length;
  const usersWithoutDomainScope = users.filter((u) => u.role === 'domain-admin' && (!u.domainIds || u.domainIds.length === 0)).length;
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
  const hostTrafficReq = selectedHostTraffic?.requests || 0;
  const hostTraffic2xxRate = hostTrafficReq > 0 ? Math.round(((selectedHostTraffic?.status2xx || 0) / hostTrafficReq) * 100) : 0;
  const hostTrafficErrRate = hostTrafficReq > 0 ? Math.round((((selectedHostTraffic?.status4xx || 0) + (selectedHostTraffic?.status5xx || 0)) / hostTrafficReq) * 100) : 0;
  const hostTrafficBlockRate = hostTrafficReq > 0 ? Math.round(((selectedHostTraffic?.blocked || 0) / hostTrafficReq) * 100) : 0;
  const hostVisitorRatio = hostTrafficReq > 0 ? Math.round(((selectedHostTraffic?.uniqueVisitors || 0) / hostTrafficReq) * 100) : 0;
  const metricCountries = [...(metricCountryOverview?.countries || [])].sort((a, b) => (b.requests || 0) - (a.requests || 0));
  const metricTopReq = metricCountries.length > 0 ? metricCountries[0].requests || 1 : 1;
  const metricUnknownTotal = metricCountries.find((c) => (c.country || '').toUpperCase() === 'ZZ')?.requests || 0;
  const metricUnknownBreakdown = [...(metricCountryOverview?.unknownBreakdown || [])].sort((a, b) => (b.requests || 0) - (a.requests || 0));

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
    setSshKeyRouteIDs((prev) => prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]);
  };

  const editSSHRoute = (r: SSHBastionRoute) => {
    setSshSelectedHostFQDN(r.fqdn);
    setSshRouteFQDN(r.fqdn);
    setSshRouteTargetHost(r.targetHost);
    setSshRouteTargetPort(String(r.targetPort || 22));
    setSshRouteEnabled(!!r.enabled);
  };

  const generateSSHKeyForRoute = async (routeID: number, fqdn: string) => {
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
        }),
      });
      setNewUserName('');
      setNewUserPassword('');
      setNewUserRole('domain-admin');
      setNewUserDomainIDs([]);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteUser = async (id: number) => {
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

  const saveUserDomains = async (id: number, domainIds: number[]) => {
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/users/${id}/domains`, {
        method: 'PUT',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ domainIds }),
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const resetUserPassword = async (id: number, password: string) => {
    setLoading(true);
    setError('');
    try {
      await api(`/api/v1/users/${id}/password`, {
        method: 'PUT',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ password }),
      });
      await refresh();
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
      setShowPasswordDialog(false);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
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
              <div className="menu-title">Operations</div>
              <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}>Dashboard</button>
              <button className={tab === 'metricCenter' ? 'active' : ''} onClick={() => setTab('metricCenter')}>MetricCenter</button>
              <button className={tab === 'audit' ? 'active' : ''} onClick={() => setTab('audit')}>LogCenter</button>
            </div>
            <div className="menu-group">
              <div className="menu-title">Routing</div>
              <button className={tab === 'domains' ? 'active' : ''} onClick={() => setTab('domains')}>Domains</button>
              <button className={tab === 'hosts' ? 'active' : ''} onClick={() => setTab('hosts')}>Subdomains</button>
              <button className={tab === 'threatIntel' ? 'active' : ''} onClick={() => setTab('threatIntel')}>Threat Intel</button>
              {identity?.role === 'admin' ? <button className={tab === 'ssh' ? 'active' : ''} onClick={() => setTab('ssh')}>SSH Bastion</button> : null}
            </div>
            {identity?.role === 'admin' ? (
              <div className="menu-group">
                <div className="menu-title">Administration</div>
                <button className={tab === 'users' ? 'active' : ''} onClick={() => setTab('users')}>Users</button>
                <button className={tab === 'api' ? 'active' : ''} onClick={() => setTab('api')}>API Mgmt</button>
                <button className={tab === 'apiDocs' ? 'active' : ''} onClick={() => setTab('apiDocs')}>API Docs</button>
                <button className={tab === 'settings' ? 'active' : ''} onClick={() => setTab('settings')}>Settings</button>
              </div>
            ) : null}
          </nav>
        </aside>

        <main className="main">
          <header className="top">
            <div>
              <h1>Overview</h1>
              <p className="subtitle">{domains.length} Domains · {hosts.length} Subdomains</p>
            </div>
            <div className="top-actions">
              <button className="btn" onClick={refresh} disabled={loading}>Refresh</button>
              {identity && !isReadOnlyRole ? <button className="btn" onClick={() => setShowPasswordDialog(true)}>Change Password</button> : null}
              {identity ? <button className="btn" onClick={logout}>Logout</button> : null}
            </div>
          </header>

          {error ? <div className="error">{error}</div> : null}

          {tab === 'dashboard' ? (
            <section className="dashboard">
              {haHostsDegraded > 0 ? (
                <div className="error">
                  HA Alert: {haHostsDegraded}/{haHostsMonitored || haHostsDegraded} HA subdomains have offline backends.
                  <div className="muted" style={{ marginTop: '.35rem' }}>
                    {haDegradedDetails.map((it) => (
                      <div key={`ha-alert-${it.fqdn}`}>
                        {it.fqdn}: {it.online}/{it.total} online{it.offline.length > 0 ? ` · offline: ${it.offline.join(', ')}` : ''}
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
              <div className="kpi-row">
                <Card title="Domains" value={String(domains.length)} status="ok" />
                <Card title="Active Hosts" value={String(activeHosts)} status="ok" />
                <Card title="Host Errors" value={String(errorHosts)} status={errorHosts > 0 ? 'err' : 'ok'} />
                <Card title="Monitored Hosts" value={String(monitoredHosts)} status={monitoredHosts > 0 ? 'ok' : 'err'} />
              </div>
              <div className="dashboard-layout">
                <div className="dashboard-main">
                  <div className="card">
                    <div className="card-head"><h3>Health Gauges</h3></div>
                    <div className="gauge-grid">
                      <Gauge title="DNS Health" value={dnsHealthPct} subtitle={`${dnsHealthy}/${safeBase} hosts`} />
                      <Gauge title="HTTP Reachability" value={httpHealthPct} subtitle={`${httpHealthy}/${safeBase} hosts`} />
                      <Gauge title="HTTPS Reachability" value={httpsHealthPct} subtitle={`${httpsHealthy}/${safeBase} hosts`} />
                      <Gauge title="TLS Health" value={tlsHealthPct} subtitle={`${tlsHealthy}/${safeBase} hosts`} />
                      <Gauge title="Cert Window" value={certWindowPct} subtitle={certKnown.length > 0 ? `${certExpiringSoon} expiring <=14d` : 'no cert data'} />
                    </div>
                  </div>
                  <div className="card">
                    <div className="card-head"><h3>Performance Snapshot</h3></div>
                    <div className="metric-grid">
                      <MetricTile label="Avg HTTPS Status" value={avgHTTPSStatus > 0 ? String(avgHTTPSStatus) : '-'} hint="Target: < 400" />
                      <MetricTile label="Avg Cert Days Left" value={avgCertDays > 0 ? `${avgCertDays}d` : '-'} hint="Target: > 30d" />
                      <MetricTile label="TLS Failure Count" value={String(Math.max(0, monitoredHosts - tlsHealthy))} hint="Should trend to 0" />
                      <MetricTile label="DNS Failure Count" value={String(Math.max(0, monitoredHosts - dnsHealthy))} hint="Should trend to 0" />
                    </div>
                  </div>
                  <div className="card">
                    <div className="card-head"><h3>Traffic Snapshot (24h)</h3></div>
                    <div className="metric-grid">
                      <MetricTile label="Requests" value={String(trafficReq24h)} hint="Total across all subdomains" />
                      <MetricTile label="Unique Visitors" value={String(trafficVisitors24h)} hint="Distinct client IP hashes" />
                      <MetricTile label="Traffic Out" value={formatBytes(trafficOut24h)} hint="Response bytes" />
                      <MetricTile label="Geo Blocks" value={String(trafficBlocked24h)} hint="Blocked by GeoIP policy" />
                    </div>
                  </div>
                </div>
                <div className="dashboard-side">
                  <div className="card">
                    <div className="card-head"><h3>Control Plane Health</h3></div>
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
                  </div>
                  <div className="card">
                    <div className="card-head"><h3>Recent Events</h3></div>
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
                  </div>
                </div>
              </div>
            </section>
          ) : null}

          {tab === 'metricCenter' ? (
            <section className="entity-page">
              <div className="entity-main">
                <section className="card">
                  <div className="card-head"><h3>MetricCenter</h3></div>
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
                    <button className="btn" onClick={loadMetricCenter} disabled={loading}>Refresh</button>
                  </div>
                  <div className="metric-grid">
                    <MetricTile label="Requests" value={String(metricCountryOverview?.totalRequests || 0)} hint="Within selected time window" />
                    <MetricTile label="Blocked" value={String(metricCountryOverview?.totalBlocked || 0)} hint="Geo/Auth/Policy blocked requests" />
                    <MetricTile label="Traffic Out" value={formatBytes(metricCountryOverview?.totalBytesOut || 0)} hint="Response bytes" />
                    <MetricTile label="Countries" value={String(metricCountries.length)} hint="Distinct country buckets" />
                  </div>
                </section>
                <section className="card">
                  <div className="card-head"><h3>Geo Request Map</h3></div>
                  <GeoScatterMap countries={metricCountries} />
                </section>
                <section className="card">
                  <div className="card-head"><h3>Country Breakdown</h3></div>
                  {metricCountries.length === 0 ? (
                    <div className="muted">No traffic data for this filter yet.</div>
                  ) : (
                    <div className="event-list">
                      {metricCountries.map((c) => {
                        const pct = Math.max(1, Math.round(((c.requests || 0) / metricTopReq) * 100));
                        return (
                          <div key={c.country} className="event-item">
                            <div className="event-top">
                              <strong>{c.country || 'UNK'}</strong>
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
              </div>
              <aside className="entity-side">
                <section className="card">
                  <div className="card-head"><h3>Audit Snapshot</h3></div>
                  <div className="metric-grid">
                    <MetricTile label="Critical" value={String(auditCriticalTotal)} hint="Deletes, resets, revokes" />
                    <MetricTile label="Warnings" value={String(auditWarningTotal)} hint="Updates, retries, proxy issues" />
                    <MetricTile label="Info" value={String(auditInfoTotal)} hint="Read/list/login events" />
                    <MetricTile label="Unique Actors" value={String(auditActorsTotal)} hint="Across retained audit data" />
                  </div>
                </section>
                <section className="card">
                  <div className="card-head"><h3>Top Countries</h3></div>
                  {(metricCountries.slice(0, 8)).map((c) => (
                    <div key={`top-${c.country}`} className="host">
                      <div>
                        <strong>{c.country || 'UNK'}</strong>
                        <div className="muted">{Math.round(((c.requests || 0) / Math.max(1, metricCountryOverview?.totalRequests || 1)) * 100)}%</div>
                      </div>
                      <div className="muted">{c.requests}</div>
                    </div>
                  ))}
                  {metricCountries.length === 0 ? <div className="muted">No country data.</div> : null}
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
                    {hosts.map((h) => (
                      <div className="host" key={h.id}>
                        <div>
                          <strong>
                            <a href={`https://${h.fqdn}`} target="_blank" rel="noopener noreferrer">{h.fqdn}</a>
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

          {identity?.role === 'admin' && tab === 'settings' ? (
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
                    <div className="muted">
                      Runtime settings are persisted in SQLite and applied by the service runtime. Use `Reload Service` after updates that affect edge behavior.
                    </div>
                  ) : null}
                  <div className="row">
                    <button className="btn" onClick={saveSettings} disabled={loading}>Save Settings</button>
                    <button className="btn" onClick={reloadService} disabled={loading}>Reload Service</button>
                    <button className="btn" onClick={loadTimeSyncStatus} disabled={loading}>Check Time Sync</button>
                  </div>
                  {settingsMessage ? <div className="muted">{settingsMessage}</div> : null}
                </section>
              </div>
            </section>
          ) : null}

          {identity?.role === 'admin' && tab === 'users' ? (
            <section className="entity-page">
              <div className="entity-main">
                <section className="card">
                  <div className="card-head"><h3>User Management</h3></div>
                  <div className="row">
                    <input value={newUserName} onChange={(e) => setNewUserName(e.target.value.toLowerCase().trim())} placeholder="username" />
                    <input type="password" value={newUserPassword} onChange={(e) => setNewUserPassword(e.target.value)} placeholder="password (min 10)" />
                    <select value={newUserRole} onChange={(e) => setNewUserRole(e.target.value as 'admin' | 'domain-admin' | 'read-only')}>
                      <option value="domain-admin">Sub Admin (domain-admin)</option>
                      <option value="read-only">Read Only</option>
                      <option value="admin">Global Admin</option>
                    </select>
                  </div>
                  {newUserRole === 'domain-admin' ? (
                    <div className="domain-pills">
                      {domains.map((d) => (
                        <label key={d.id} className="pill">
                          <input type="checkbox" checked={newUserDomainIDs.includes(d.id)} onChange={() => toggleNewUserDomain(d.id)} />
                          {d.name}
                        </label>
                      ))}
                    </div>
                  ) : null}
                  <div className="row">
                    <button className="btn" onClick={createUser} disabled={loading || !newUserName || !newUserPassword || (newUserRole === 'domain-admin' && newUserDomainIDs.length === 0)}>Create User</button>
                  </div>
                </section>

                <section className="card">
                  <div className="card-head"><h3>Managed Users</h3></div>
                  {users.map((u) => (
                    <UserRow
                      key={u.id}
                      user={u}
                      domains={domains}
                      loading={loading}
                      currentUserID={identity?.type === 'session' ? identity.userId : 0}
                      onDelete={deleteUser}
                      onSaveDomains={saveUserDomains}
                      onResetPassword={resetUserPassword}
                    />
                  ))}
                </section>
              </div>
              <aside className="entity-side">
                <section className="card">
                  <div className="card-head"><h3>User Stats</h3></div>
                  <div className="metric-grid">
                    <MetricTile label="Total Users" value={String(users.length)} hint="Managed accounts" />
                    <MetricTile label="Global Admins" value={String(globalAdmins)} hint="Full control users" />
                    <MetricTile label="Domain Admins" value={String(domainAdmins)} hint="Scoped admins" />
                    <MetricTile label="Read Only" value={String(readOnlyUsers)} hint="View-only accounts" />
                    <MetricTile label="Missing Scope" value={String(usersWithoutDomainScope)} hint="Domain-admin without domains" />
                  </div>
                </section>
                <section className="card">
                  <div className="card-head"><h3>Role Guide</h3></div>
                  <div className="muted">`admin`: global access across domains, users, settings.</div>
                  <div className="muted" style={{ marginTop: '.45rem' }}>`domain-admin`: limited to assigned domains and hosts.</div>
                  <div className="muted" style={{ marginTop: '.45rem' }}>`read-only`: view-only access (no create/update/delete).</div>
                  <div className="muted" style={{ marginTop: '.45rem' }}>Use domain scope assignment right after user creation.</div>
                </section>
              </aside>
            </section>
          ) : null}

          {identity?.role === 'admin' && tab === 'api' ? (
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
                <button className="btn" onClick={createToken} disabled={loading || !newTokenName}>Create Token</button>
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
                  <button key={t.id} className="btn" onClick={() => revokeToken(t.id)}>Revoke {t.name} ({t.tokenPrefix})</button>
                ))}
              </div>
            </section>
          ) : null}

          {identity?.role === 'admin' && tab === 'apiDocs' ? (
            <section className="card">
              <div className="card-head"><h3>API Documentation</h3></div>
              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>Authentication</h4>
                <div className="muted">All mutating endpoints require authentication. No unauthenticated write API.</div>
                <pre style={{ marginTop: '.5rem' }}>{`# Session (WebUI)
GET  /api/v1/csrf
POST /api/v1/login

# Token (Automation)
Authorization: Bearer dnx_xxx`}</pre>
              </div>

              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>Token Permission Model</h4>
                <pre>{`global:read / global:write
domains:read / domains:write
hosts:read / hosts:write
settings:read / settings:write
users:read / users:write
tokens:read / tokens:write
audit:read
reload:write
dns:write / cert:write

If no global scope is set:
domainIds limit access to these domains/hosts.`}</pre>
              </div>

              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>API Base</h4>
                <pre>{`BASE=http://<domnex>:8443
TOKEN=dnx_xxx

curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/me"`}</pre>
              </div>

              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>Domain Actions</h4>
                <pre>{`# List domains
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/domains"

# Domain preflight
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"name":"example.com","dnsMode":"cloudflare","provider":"cloudflare","zoneId":""}' \\
  "$BASE/api/v1/domains/preflight"

# Create/Update domain
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"name":"example.com","dnsMode":"cloudflare","certMode":"letsencrypt","provider":"cloudflare","zoneId":""}' \\
  "$BASE/api/v1/domains"

# Domain Live Check
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/domains/24/live-check"

# Delete domain
curl -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/domains/24"`}</pre>
              </div>

              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>Subdomain / Host Actions</h4>
                <pre>{`# List hosts
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/hosts"

# Host preflight
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"domain":"example.com","subdomain":"app","upstream":"https://127.0.0.1:3000","insecureTls":true,"haEnabled":false}' \\
  "$BASE/api/v1/hosts/preflight"

# Create host
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"domain":"example.com","subdomain":"app","upstream":"https://127.0.0.1:3000","insecureTls":true,"haEnabled":false}' \\
  "$BASE/api/v1/hosts"

# Create HA host (explicit HA mode)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{
    "domain":"example.com",
    "subdomain":"app-ha",
    "insecureTls":true,
    "haEnabled":true,
    "haMode":"failover",
    "haBackends":[
      {"name":"server1","url":"https://10.0.0.11:8443"},
      {"name":"server2","url":"https://10.0.0.12:8443"}
    ]
  }' "$BASE/api/v1/hosts"

# Update host routing settings
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"upstream":"https://127.0.0.1:3001","insecureTls":false,"haEnabled":false}' \\
  "$BASE/api/v1/hosts/5"

# Host diagnostics
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/hosts/diagnostics"

# Host retry
curl -X POST -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/hosts/5/retry"

# Update host auth page settings
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"enabled":true,"username":"musicuser","password":"StrongPass123"}' \\
  "$BASE/api/v1/hosts/5/auth"

# Delete host
curl -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/hosts/5"`}</pre>
              </div>

              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>System Actions</h4>
                <pre>{`# Read settings
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/settings"

# Update settings
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"acmeEmail":"admin@example.com","acmeStaging":false,"publicIpv4":"203.0.113.10"}' \\
  "$BASE/api/v1/settings"

# Service reload
curl -X POST -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/reload"

# Audit logs
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/audit"`}</pre>
              </div>

              <div className="card" style={{ marginBottom: '.8rem' }}>
                <h4 style={{ marginTop: 0 }}>User & Token Management</h4>
                <pre>{`# User list
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/users"

# Create user
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"username":"ops1","password":"SuperSecret123","role":"domain-admin","domainIds":[24]}' \\
  "$BASE/api/v1/users"

# Token list
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/tokens"

# Create token (domain scoped)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{
    "name":"ci-token",
    "role":"operator",
    "domainIds":[24],
    "permissions":{"domainRead":true,"domainWrite":true,"globalRead":false,"globalWrite":false,"systemRead":false,"systemWrite":false},
    "scopes":[],
    "expiresIn":"720h"
  }' "$BASE/api/v1/tokens"

# Token revoke
curl -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/tokens/2"`}</pre>
              </div>
            </section>
          ) : null}

          {identity?.role === 'admin' && tab === 'ssh' ? (
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
                    <select value={sshSelectedHostFQDN} onChange={(e) => setSshSelectedHostFQDN(e.target.value)}>
                      <option value="">Select Subdomain (recommended)</option>
                      {sshCandidateHosts.map((h) => (
                        <option key={`ssh-cand-${h.id}`} value={h.fqdn}>
                          {h.fqdn}{sshRouteByFQDN[h.fqdn.toLowerCase()] ? ' (configured)' : ''}
                        </option>
                      ))}
                    </select>
                    <input value={sshRouteFQDN} onChange={(e) => setSshRouteFQDN(e.target.value)} placeholder="manual FQDN fallback" />
                    <input value={sshRouteTargetHost} onChange={(e) => setSshRouteTargetHost(e.target.value)} placeholder="192.168.1.14" />
                    <input value={sshRouteTargetPort} onChange={(e) => setSshRouteTargetPort(e.target.value)} placeholder="22" />
                    <label className="check"><input type="checkbox" checked={sshRouteEnabled} onChange={(e) => setSshRouteEnabled(e.target.checked)} /> enabled</label>
                    <button className="btn" onClick={saveSSHRoute} disabled={loading || (!sshSelectedHostFQDN.trim() && !sshRouteFQDN.trim())}>Save Route</button>
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
                          <button className="btn" onClick={() => editSSHRoute(r)} disabled={loading}>Edit</button>
                          <button className="btn" onClick={() => generateSSHKeyForRoute(r.id, r.fqdn)} disabled={loading}>Generate Host Key</button>
                          <button className="btn danger" onClick={() => deleteSSHRoute(r.id)} disabled={loading}>Delete</button>
                        </div>
                      </div>
                    ))
                  )}
                </section>
                <section className="card">
                  <div className="card-head"><h3>SSH Bastion Keys</h3></div>
                  <div className="row">
                    <input value={sshKeyName} onChange={(e) => setSshKeyName(e.target.value)} placeholder="user1-key" />
                    <button className="btn" onClick={generateSSHKey} disabled={loading || !sshKeyName || sshKeyRouteIDs.length === 0}>Generate Keypair</button>
                    <button className="btn" onClick={importSSHKey} disabled={loading || !sshKeyName || !sshKeyPublic || sshKeyRouteIDs.length === 0}>Import Public Key</button>
                  </div>
                  <textarea value={sshKeyPublic} onChange={(e) => setSshKeyPublic(e.target.value)} placeholder="ssh-ed25519 AAAA... user@host" rows={3} />
                  <div className="muted" style={{ marginBottom: '.3rem' }}>Allowed routes:</div>
                  <div className="domain-pills">
                    {sshRoutes.map((r) => (
                      <label key={`ssh-route-${r.id}`} className="pill">
                        <input type="checkbox" checked={sshKeyRouteIDs.includes(r.id)} onChange={() => toggleSSHKeyRoute(r.id)} />
                        {r.fqdn}
                      </label>
                    ))}
                  </div>
                  {sshGeneratedPrivateKey ? (
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
                          <div className="muted">{k.fingerprint}</div>
                          <div className="muted">Routes: {(k.routeIds || []).map((rid) => sshRoutes.find((r) => r.id === rid)?.fqdn || `#${rid}`).join(', ') || '-'}</div>
                        </div>
                        <button className="btn danger" onClick={() => deleteSSHKey(k.id)} disabled={loading}>Delete</button>
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

      {!identity ? (
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

      {identity && showPasswordDialog ? (
        <div className="overlay">
          <div className="login-card">
            <h3>Change Password</h3>
            <p className="muted">Update your current account password.</p>
            <div className="col">
              <input type="password" value={selfCurrentPassword} onChange={(e) => setSelfCurrentPassword(e.target.value)} placeholder="Current password" />
              <input type="password" value={selfNewPassword} onChange={(e) => setSelfNewPassword(e.target.value)} placeholder="New password (min 10)" />
              <input type="password" value={selfConfirmPassword} onChange={(e) => setSelfConfirmPassword(e.target.value)} placeholder="Confirm new password" />
              <div className="row" style={{ marginBottom: 0 }}>
                <button className="btn" onClick={changeOwnPassword} disabled={loading || selfNewPassword.length < 10 || selfNewPassword !== selfConfirmPassword}>Save Password</button>
                <button className="btn danger" onClick={() => { setShowPasswordDialog(false); setSelfCurrentPassword(''); setSelfNewPassword(''); setSelfConfirmPassword(''); }}>Cancel</button>
              </div>
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

      <style>{`
        :root { --bg:${activeTheme.bg}; --surface:${activeTheme.surface}; --panel:${activeTheme.panel}; --panel-hover:${activeTheme.panelHover}; --border:${activeTheme.border}; --text:${activeTheme.text}; --text-dim:${activeTheme.textDim}; --accent:${activeTheme.accent}; --accent-hover:${activeTheme.accentHover}; --accent-active:${activeTheme.accentActive}; --accent-soft:${activeTheme.accentSoft}; --green:${activeTheme.success}; --red:${activeTheme.danger}; --input-bg:${activeTheme.inputBg}; --hero-a:${activeTheme.heroA}; --hero-b:${activeTheme.heroB}; --radius:12px; }
        * { box-sizing: border-box; }
        body { margin:0; font-family:'Inter', system-ui, sans-serif; background:var(--bg); color:var(--text); }
        .app-shell { display:grid; grid-template-columns:240px 1fr; min-height:100vh; }
        .sidebar { background:var(--surface); border-right:1px solid var(--border); padding:1.5rem 0; }
        .logo { padding:0 .85rem 1.25rem; display:grid; place-items:center; }
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
        .menu { display:grid; gap:.25rem; padding:0 .5rem; }
        .menu-group { display:grid; gap:.25rem; margin-bottom:.35rem; }
        .menu-title { color:var(--text-dim); font-size:.7rem; letter-spacing:.08em; text-transform:uppercase; padding:.35rem .9rem .15rem; }
        .menu button { text-align:left; background:transparent; border:1px solid transparent; color:var(--text-dim); padding:.85rem 1rem; border-radius:10px; cursor:pointer; }
        .menu button:hover, .menu button.active { background:var(--accent-soft); color:var(--accent); }
        .main { padding:2.5rem 3rem; }
        .top { display:flex; justify-content:space-between; align-items:center; gap:1rem; margin-bottom:1.25rem; }
        h1 { margin:0; font-size:2.2rem; letter-spacing:-.6px; }
        .subtitle { margin:.25rem 0 0; color:var(--text-dim); }
        .top-actions { display:flex; gap:.5rem; }
        .dashboard { display:grid; gap:1rem; }
        .kpi-row { display:grid; gap:1rem; grid-template-columns:repeat(4,minmax(0,1fr)); }
        .dashboard-layout { display:grid; gap:1rem; grid-template-columns:minmax(0,1.7fr) minmax(320px,1fr); align-items:start; }
        .dashboard-main { display:grid; gap:1rem; }
        .dashboard-side { display:grid; gap:1rem; min-width:0; }
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
        .host { display:flex; justify-content:space-between; align-items:flex-start; gap:.6rem; border-top:1px solid var(--border); padding:.6rem 0; }
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
        @media (max-width:1150px){ .kpi-row{grid-template-columns:repeat(2,minmax(0,1fr));} .dashboard-layout{grid-template-columns:1fr;} .entity-page{grid-template-columns:1fr;} .logs-page{grid-template-columns:1fr;} .cc-kpi-strip{grid-template-columns:repeat(2,minmax(0,1fr));} .cc-split{grid-template-columns:1fr;} .log-filter-grid{grid-template-columns:repeat(2,minmax(0,1fr));} }
        @media (max-width:900px){ .app-shell{grid-template-columns:1fr;} .sidebar{border-right:none;border-bottom:1px solid var(--border);} .main{padding:1rem;} .card.wide{grid-column:auto;} .kpi-row{grid-template-columns:1fr;} .metric-grid{grid-template-columns:1fr;} .ti-filter-grid{grid-template-columns:1fr;} .threatintel-page .log-table{min-width:760px;} }
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

function Gauge({ title, value, subtitle }: { title: string; value: number; subtitle: string }) {
  const clamped = Math.max(0, Math.min(100, value));
  const deg = Math.round((clamped / 100) * 360);
  const color = clamped >= 85 ? '#10b981' : clamped >= 60 ? '#f59e0b' : '#ef4444';
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

const COUNTRY_COORDS: Record<string, { x: number; y: number }> = {
  US: { x: 206, y: 130 }, CA: { x: 185, y: 86 }, MX: { x: 198, y: 173 },
  BR: { x: 280, y: 250 }, AR: { x: 268, y: 312 }, CL: { x: 246, y: 292 }, CO: { x: 244, y: 211 },
  GB: { x: 428, y: 95 }, IE: { x: 416, y: 100 }, FR: { x: 438, y: 117 }, ES: { x: 426, y: 136 }, PT: { x: 415, y: 142 },
  DE: { x: 451, y: 106 }, NL: { x: 442, y: 103 }, BE: { x: 440, y: 109 }, IT: { x: 463, y: 132 }, CH: { x: 452, y: 119 },
  AT: { x: 460, y: 116 }, PL: { x: 470, y: 103 }, SE: { x: 466, y: 76 }, NO: { x: 452, y: 67 }, FI: { x: 486, y: 76 },
  DK: { x: 452, y: 92 }, CZ: { x: 461, y: 110 }, RO: { x: 489, y: 123 }, HU: { x: 472, y: 117 }, GR: { x: 490, y: 147 },
  TR: { x: 518, y: 136 }, UA: { x: 499, y: 104 }, RU: { x: 575, y: 86 },
  MA: { x: 413, y: 172 }, DZ: { x: 444, y: 173 }, EG: { x: 502, y: 169 }, NG: { x: 458, y: 223 }, ZA: { x: 492, y: 320 }, KE: { x: 503, y: 251 },
  SA: { x: 544, y: 186 }, AE: { x: 565, y: 184 }, IL: { x: 516, y: 163 }, IN: { x: 595, y: 197 }, PK: { x: 575, y: 179 },
  CN: { x: 666, y: 141 }, JP: { x: 744, y: 145 }, KR: { x: 718, y: 137 }, TW: { x: 721, y: 164 }, HK: { x: 705, y: 166 },
  SG: { x: 647, y: 227 }, ID: { x: 679, y: 249 }, AU: { x: 723, y: 312 }, NZ: { x: 784, y: 338 },
};

function GeoScatterMap({ countries }: { countries: CountryTraffic[] }) {
  const normalized = (countries || [])
    .map((c) => ({ ...c, code: String(c.country || '').trim().toUpperCase() }))
    .filter((c) => c.code && COUNTRY_COORDS[c.code]);
  if (normalized.length === 0) {
    return <div className="muted">No mappable country data yet.</div>;
  }
  const topReq = Math.max(1, ...normalized.map((c) => c.requests || 0));
  return (
    <div className="geo-map-wrap">
      <svg className="geo-map-svg" viewBox="0 0 900 380" role="img" aria-label="Request geo map">
        {[70, 130, 190, 250, 310].map((y) => <line key={`h-${y}`} x1="20" y1={y} x2="880" y2={y} className="geo-map-grid" />)}
        {[120, 240, 360, 480, 600, 720].map((x) => <line key={`v-${x}`} x1={x} y1="36" x2={x} y2="344" className="geo-map-grid" />)}
        {normalized.map((c) => {
          const p = COUNTRY_COORDS[c.code];
          const radius = 4 + Math.round(((c.requests || 0) / topReq) * 14);
          return (
            <g key={c.code}>
              <circle cx={p.x} cy={p.y} r={radius} className="geo-map-bubble" style={{ opacity: 0.2 + ((c.requests || 0) / topReq) * 0.8 }} />
              <text x={p.x + radius + 3} y={p.y + 3} className="geo-map-label">{c.code}</text>
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

function MetricTile({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="metric-tile">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-hint">{hint}</div>
    </div>
  );
}

function UserRow({
  user,
  domains,
  loading,
  currentUserID,
  onDelete,
  onSaveDomains,
  onResetPassword,
}: {
  user: ManagedUser;
  domains: Domain[];
  loading: boolean;
  currentUserID: number;
  onDelete: (id: number) => Promise<void>;
  onSaveDomains: (id: number, domainIds: number[]) => Promise<void>;
  onResetPassword: (id: number, password: string) => Promise<void>;
}) {
  const [domainIds, setDomainIds] = useState<number[]>(user.domainIds || []);
  const [newPassword, setNewPassword] = useState('');
  const isCurrentUser = currentUserID > 0 && user.id === currentUserID;

  useEffect(() => {
    setDomainIds(user.domainIds || []);
  }, [user.domainIds]);

  const toggle = (id: number) => {
    setDomainIds((prev) => (prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]));
  };

  return (
    <div className="card" style={{ marginBottom: '.6rem' }}>
      <div className="host" style={{ borderTop: 'none', paddingTop: 0 }}>
        <div>
          <strong>{user.username}</strong> <span className="muted">({user.role})</span>
          <div className="muted">ID: {user.id}</div>
        </div>
        <button className="btn danger" onClick={() => onDelete(user.id)} disabled={loading}>Delete</button>
      </div>
      {user.role === 'domain-admin' ? (
        <>
          <div className="domain-pills">
            {domains.map((d) => (
              <label key={d.id} className="pill">
                <input type="checkbox" checked={domainIds.includes(d.id)} onChange={() => toggle(d.id)} />
                {d.name}
              </label>
            ))}
          </div>
          <div className="row">
            <button className="btn" onClick={() => onSaveDomains(user.id, domainIds)} disabled={loading || domainIds.length === 0}>Save Domain Scope</button>
          </div>
        </>
      ) : null}
      <div className="row" style={{ marginTop: '.4rem' }}>
        <input
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder={isCurrentUser ? 'Use Change Password (top bar) for your account' : `Reset password for ${user.username} (min 10)`}
          disabled={isCurrentUser}
        />
        <button
          className="btn"
          onClick={async () => { await onResetPassword(user.id, newPassword); setNewPassword(''); }}
          disabled={isCurrentUser || loading || newPassword.length < 10}
        >
          Reset Password
        </button>
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <RootErrorBoundary>
    <App />
  </RootErrorBoundary>,
);
