// subgw web UI

const state = { tenant: '', window: '24h' };

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleString('zh-CN', { hour12: false });
}
function fmtSince(ts) {
  if (!ts) return '从未';
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60_000) return Math.floor(diff/1000) + ' 秒前';
  if (diff < 3600_000) return Math.floor(diff/60_000) + ' 分钟前';
  if (diff < 86400_000) return Math.floor(diff/3600_000) + ' 小时前';
  return Math.floor(diff/86400_000) + ' 天前';
}
function escapeHTML(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
function tokenShort(h) {
  if (!h) return '';
  return h.length > 16 ? h.slice(0, 16) + '…' : h;
}

function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show ' + kind;
  setTimeout(() => t.className = 'toast ' + kind, 3000);
}

async function api(path) {
  const r = await fetch(path);
  if (r.status === 401) { location.href = '/login'; return null; }
  if (!r.ok) { toast('API ' + r.status, 'error'); return null; }
  return r.json();
}
async function apiPost(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  if (r.status === 401) { location.href = '/login'; return null; }
  return r.json();
}

// ---- 路由 ----

const TAB_TITLES = {
  'dashboard': '概览',
  'events': '请求日志',
  'incidents': '异常事件',
  'ip-bans': 'IP 黑名单',
  'token-bans': 'Token 黑名单',
  'ip-whitelist': 'IP 白名单',
  'ua-rules': 'UA 规则',
  'cloud-ip': '云 IP 库',
  'settings': '设置',
  'tools': '工具',
};

const TAB_LOADERS = {
  'dashboard': () => loadSummary(),
  'events': () => loadEvents(),
  'incidents': () => loadIncidents(),
  'ip-bans': () => loadBans(),
  'token-bans': () => loadBans(),
  'ip-whitelist': () => loadIPWhitelist(),
  'ua-rules': () => loadUARules(),
  'cloud-ip': () => loadCloudStats(),
  'settings': () => { loadNotifier(); loadSettings(); },
  'tools': () => {},
};

$$('.navlink').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    $$('.navlink').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    const tab = a.dataset.tab;
    $$('.tab').forEach(s => s.classList.remove('active'));
    const sec = document.getElementById('tab-' + tab);
    if (sec) sec.classList.add('active');
    $('#pageTitle').textContent = TAB_TITLES[tab] || tab;
    if (TAB_LOADERS[tab]) TAB_LOADERS[tab]();
  });
});

$('#refreshBtn').addEventListener('click', () => {
  const active = document.querySelector('.navlink.active');
  if (active && TAB_LOADERS[active.dataset.tab]) TAB_LOADERS[active.dataset.tab]();
});

$('#logoutBtn').addEventListener('click', async () => {
  await apiPost('/api/logout', {});
  location.href = '/login';
});

$('#tenantSel').addEventListener('change', e => {
  state.tenant = e.target.value;
  const active = document.querySelector('.navlink.active');
  if (active && TAB_LOADERS[active.dataset.tab]) TAB_LOADERS[active.dataset.tab]();
});

$('#windowSel').addEventListener('change', e => {
  state.window = e.target.value;
  const active = document.querySelector('.navlink.active');
  if (active && TAB_LOADERS[active.dataset.tab]) TAB_LOADERS[active.dataset.tab]();
});

// ---- tenants ----
async function loadTenants() {
  const ts = await api('/api/tenants');
  if (!ts) return;
  const sel = $('#tenantSel');
  sel.innerHTML = '<option value="">全部 tenant</option>';
  for (const t of ts) {
    const o = document.createElement('option');
    o.value = t.name;
    o.textContent = t.name + ' (' + t.host + ')';
    sel.appendChild(o);
  }
}

// ---- dashboard ----
async function loadSummary() {
  const q = new URLSearchParams({ tenant: state.tenant, window: state.window });
  const s = await api('/api/summary?' + q);
  if (!s) return;
  const cards = $('#summaryCards');
  cards.innerHTML = '';
  const data = [
    ['total', '总请求', s.total_events],
    ['pass', 'PASS', s.pass],
    ['slow', 'SLOW', s.slow],
    ['fake', 'FAKE', s.fake],
    ['deny', 'DENY', s.deny],
    ['', '独立 IP', s.unique_ips],
    ['', '独立 Token', s.unique_tokens],
  ];
  for (const [cls, label, val] of data) {
    const c = document.createElement('div');
    c.className = 'stat-card ' + cls;
    c.innerHTML = `<div class="label">${cls ? '<span class="dot"></span>' : ''}${label}</div><div class="value">${val ?? 0}</div>`;
    cards.appendChild(c);
  }
  const sev = s.incident_by_level || {};
  for (const [lev, n] of Object.entries(sev)) {
    const c = document.createElement('div');
    c.className = 'stat-card ' + lev;
    c.innerHTML = `<div class="label"><span class="dot"></span>incident-${lev}</div><div class="value">${n}</div>`;
    cards.appendChild(c);
  }
  const ipTbody = $('#topIPs tbody'); ipTbody.innerHTML = '';
  (s.top_ips || []).forEach(k => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${escapeHTML(k.key)}</td><td style="text-align:right" class="mono">${k.count}</td>`;
    ipTbody.appendChild(tr);
  });
  const tokTbody = $('#topTokens tbody'); tokTbody.innerHTML = '';
  (s.top_tokens || []).forEach(k => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono" title="${escapeHTML(k.key)}">${escapeHTML(tokenShort(k.key))}</td><td style="text-align:right" class="mono">${k.count}</td>`;
    tokTbody.appendChild(tr);
  });
}

// ---- events ----
async function loadEvents() {
  const q = new URLSearchParams({
    tenant: state.tenant, window: state.window, limit: '200',
    ip: $('#evIP').value, token: $('#evToken').value, action: $('#evAction').value,
  });
  const evs = await api('/api/events?' + q);
  if (!evs) return;
  const tbody = $('#evTbody'); tbody.innerHTML = '';
  if (evs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state">没有匹配的事件</td></tr>';
    return;
  }
  for (const e of evs) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono" style="white-space:nowrap">${escapeHTML(fmtTime(e.TS))}</td>
      <td><span class="pill ${e.Action || ''}">${escapeHTML(e.Action || '-')}</span></td>
      <td class="mono">${e.Status || ''}</td>
      <td class="mono">${escapeHTML(e.ClientIP || '')}</td>
      <td class="mono" title="${escapeHTML(e.TokenHash || '')}">${escapeHTML(tokenShort(e.TokenHash))}</td>
      <td class="mono">${escapeHTML(e.Flag || '')}</td>
      <td class="mono" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHTML(e.Path || '')}">${escapeHTML(e.Path || '')}</td>
      <td class="mono">${escapeHTML((e.RuleTags || []).join(','))}</td>
      <td class="mono" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHTML(e.UA || '')}">${escapeHTML(e.UA || '')}</td>
    `;
    tbody.appendChild(tr);
  }
}
$('#evQuery').addEventListener('click', loadEvents);

// ---- incidents ----
async function loadIncidents() {
  const q = new URLSearchParams({
    tenant: state.tenant, window: state.window,
    severity: $('#inSeverity').value, limit: '200',
  });
  const ins = await api('/api/incidents?' + q);
  if (!ins) return;
  const tbody = $('#inTbody'); tbody.innerHTML = '';
  if (!ins.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">没有异常事件</td></tr>';
    return;
  }
  for (const i of ins) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono" style="white-space:nowrap">${escapeHTML(fmtTime(i.TS))}</td>
      <td><span class="pill ${i.Severity}">${escapeHTML(i.Severity)}</span></td>
      <td><span class="pill ${i.Action}">${escapeHTML(i.Action || '')}</span></td>
      <td class="mono">${escapeHTML(i.ClientIP || '')}</td>
      <td class="mono" title="${escapeHTML(i.TokenHash || '')}">${escapeHTML(tokenShort(i.TokenHash))}</td>
      <td class="mono">${escapeHTML((i.RuleTags || []).join(','))}</td>
      <td>${escapeHTML(i.Note || '')}</td>
    `;
    tbody.appendChild(tr);
  }
}
$('#inQuery').addEventListener('click', loadIncidents);

// ---- bans ----
async function loadBans() {
  const bs = await api('/api/bans');
  if (!bs) return;
  const ipTbody = $('#ipBanTbody'); ipTbody.innerHTML = '';
  const tokTbody = $('#tokenBanTbody'); tokTbody.innerHTML = '';
  let ipCount = 0, tokCount = 0;
  for (const b of bs || []) {
    const exp = b.ExpiresTS ? fmtTime(b.ExpiresTS) : '<span style="color:var(--danger)">永久</span>';
    const tr = document.createElement('tr');
    const isIP = b.Kind === 'ip';
    tr.innerHTML = `
      <td class="mono" title="${escapeHTML(b.Target)}">${isIP ? escapeHTML(b.Target) : escapeHTML(tokenShort(b.Target))}</td>
      <td>${escapeHTML(b.Reason || '')}</td>
      <td class="mono">${escapeHTML((b.RuleTags || []).join(','))}</td>
      <td class="mono" style="white-space:nowrap">${escapeHTML(fmtTime(b.CreatedTS))}</td>
      <td class="mono" style="white-space:nowrap">${exp}</td>
      <td><span class="pill ${b.CreatedBy === 'auto' ? 'red' : ''}">${escapeHTML(b.CreatedBy)}</span></td>
      <td><button class="danger" data-kind="${escapeHTML(b.Kind)}" data-target="${escapeHTML(b.Target)}">解封</button></td>
    `;
    if (isIP) { ipTbody.appendChild(tr); ipCount++; } else { tokTbody.appendChild(tr); tokCount++; }
  }
  if (!ipCount) ipTbody.innerHTML = '<tr><td colspan="7" class="empty-state">无封禁 IP</td></tr>';
  if (!tokCount) tokTbody.innerHTML = '<tr><td colspan="7" class="empty-state">无封禁 token</td></tr>';
  $$('#ipBanTbody button.danger, #tokenBanTbody button.danger').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('解封 ' + btn.dataset.target + ' ?')) return;
      const r = await apiPost('/api/bans/remove', { kind: btn.dataset.kind, target: btn.dataset.target });
      if (r && r.ok) { toast('已解封', 'success'); loadBans(); }
      else toast((r && r.error) || '失败', 'error');
    });
  });
}

$('#banIPAddBtn').addEventListener('click', async () => {
  const target = $('#banIPTarget').value.trim();
  if (!target) return toast('IP 不能为空', 'error');
  const r = await apiPost('/api/bans/add', {
    kind: 'ip', target,
    reason: $('#banIPReason').value.trim(),
    ttl: $('#banIPTTL').value.trim(),
  });
  if (r && r.ok) {
    $('#banIPTarget').value = ''; $('#banIPReason').value = ''; $('#banIPTTL').value = '';
    toast('已添加', 'success'); loadBans();
  } else toast((r && r.error) || '失败', 'error');
});

$('#banTokAddBtn').addEventListener('click', async () => {
  let hash = $('#banTokHash').value.trim();
  const original = $('#banTokOriginal').value.trim();
  if (!hash && original) {
    const r = await api('/api/hash-token?token=' + encodeURIComponent(original));
    if (r) hash = r.hash;
  }
  if (!hash) return toast('请填 token 原文或 hash', 'error');
  if (hash.length !== 64) return toast('hash 应当是 64 位 hex', 'error');
  const r = await apiPost('/api/bans/add', {
    kind: 'token', target: hash,
    reason: $('#banTokReason').value.trim(),
    ttl: $('#banTokTTL').value.trim(),
  });
  if (r && r.ok) {
    $('#banTokOriginal').value = ''; $('#banTokHash').value = ''; $('#banTokReason').value = ''; $('#banTokTTL').value = '';
    toast('已添加', 'success'); loadBans();
  } else toast((r && r.error) || '失败', 'error');
});

// ---- IP 白名单 ----
async function loadIPWhitelist() {
  const list = await api('/api/ip-whitelist') || [];
  const tbody = $('#ipWLTbody'); tbody.innerHTML = '';
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">还没有白名单条目</td></tr>';
    return;
  }
  for (const e of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${escapeHTML(e.Target)}</td>
      <td>${escapeHTML(e.Note || '')}</td>
      <td class="mono">${escapeHTML(fmtTime(e.CreatedTS))}</td>
      <td><button class="danger" data-id="${e.ID}">删除</button></td>
    `;
    tbody.appendChild(tr);
  }
  $$('#ipWLTbody button.danger').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('删除该白名单?')) return;
      const r = await apiPost('/api/ip-whitelist/remove', { id: parseInt(btn.dataset.id, 10) });
      if (r && r.ok) { toast('已删除', 'success'); loadIPWhitelist(); }
      else toast((r && r.error) || '失败', 'error');
    });
  });
}
$('#ipWLAddBtn').addEventListener('click', async () => {
  const target = $('#ipWLTarget').value.trim();
  if (!target) return toast('请输入 IP/CIDR', 'error');
  const r = await apiPost('/api/ip-whitelist/add', { target, note: $('#ipWLNote').value.trim() });
  if (r && r.ok) {
    $('#ipWLTarget').value = ''; $('#ipWLNote').value = '';
    toast('已添加', 'success'); loadIPWhitelist();
  } else toast((r && r.error) || '失败', 'error');
});

// ---- UA 规则 ----
async function loadUARules() {
  const all = await api('/api/ua-rules') || [];
  const bl = all.filter(r => r.Kind === 'blacklist');
  const wl = all.filter(r => r.Kind === 'whitelist');
  renderUARules('#uaBlTbody', bl);
  renderUARules('#uaWlTbody', wl);
}
function renderUARules(sel, list) {
  const tbody = $(sel); tbody.innerHTML = '';
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">还没有规则</td></tr>';
    return;
  }
  for (const r of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${escapeHTML(r.Pattern)}</td>
      <td>${escapeHTML(r.Note || '')}</td>
      <td class="mono">${escapeHTML(fmtTime(r.CreatedTS))}</td>
      <td><button class="danger" data-id="${r.ID}">删除</button></td>
    `;
    tbody.appendChild(tr);
  }
  $$(sel + ' button.danger').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('删除该规则?')) return;
      const r = await apiPost('/api/ua-rules/remove', { id: parseInt(btn.dataset.id, 10) });
      if (r && r.ok) { toast('已删除', 'success'); loadUARules(); }
      else toast((r && r.error) || '失败', 'error');
    });
  });
}
$('#uaBlAddBtn').addEventListener('click', async () => {
  const pattern = $('#uaBlPattern').value.trim();
  if (!pattern) return toast('请填正则', 'error');
  const r = await apiPost('/api/ua-rules/add', { kind: 'blacklist', pattern, note: $('#uaBlNote').value.trim() });
  if (r && r.ok) {
    $('#uaBlPattern').value = ''; $('#uaBlNote').value = '';
    toast('已添加', 'success'); loadUARules();
  } else toast((r && r.error) || '失败', 'error');
});
$('#uaWlAddBtn').addEventListener('click', async () => {
  const pattern = $('#uaWlPattern').value.trim();
  if (!pattern) return toast('请填前缀', 'error');
  const r = await apiPost('/api/ua-rules/add', { kind: 'whitelist', pattern, note: $('#uaWlNote').value.trim() });
  if (r && r.ok) {
    $('#uaWlPattern').value = ''; $('#uaWlNote').value = '';
    toast('已添加', 'success'); loadUARules();
  } else toast((r && r.error) || '失败', 'error');
});

$('#uaSeedBtn').addEventListener('click', async () => {
  if (!confirm('把内置默认 UA 黑白名单写入(已存在的会保留)?\n白名单约 30+ 个主流客户端,黑名单约 50+ 个扫描器/库。')) return;
  $('#uaSeedBtn').disabled = true;
  $('#uaSeedBtn').textContent = '写入中…';
  const r = await apiPost('/api/ua-rules/seed-defaults', {});
  $('#uaSeedBtn').disabled = false;
  $('#uaSeedBtn').textContent = '恢复 / 补全内置默认';
  if (r && r.ok) {
    toast('已写入(已存在的会自动更新备注)', 'success');
    loadUARules();
  } else toast((r && r.error) || '失败', 'error');
});

// ---- 云 IP ----
async function loadCloudStats() {
  const s = await api('/api/cloud-ip');
  if (!s) return;
  $('#cloudStats').innerHTML = `共 <b>${s.total || 0}</b> 条 CIDR;最后更新:<b>${s.updated && new Date(s.updated).getTime() > 0 ? fmtTime(s.updated) + '(' + fmtSince(s.updated) + ')' : '从未'}</b>`;
  const stats = $('#cloudProviders'); stats.innerHTML = '';
  for (const [p, n] of Object.entries(s.stats || {}).sort((a,b) => b[1]-a[1])) {
    const c = document.createElement('div');
    c.className = 'stat-card';
    c.innerHTML = `<div class="label">${escapeHTML(p)}</div><div class="value">${n}</div>`;
    stats.appendChild(c);
  }
  if (!Object.keys(s.stats || {}).length) {
    stats.innerHTML = '<div class="empty-state" style="grid-column:1/-1">还没有数据,点「立即更新」拉一次</div>';
  }
}
$('#cloudRefreshBtn').addEventListener('click', async () => {
  $('#cloudRefreshBtn').textContent = '更新中…';
  $('#cloudRefreshBtn').disabled = true;
  const r = await apiPost('/api/cloud-ip/refresh', {});
  if (r && r.started) {
    toast('已触发后台更新,1-2 分钟后刷新本页', 'success');
    setTimeout(() => { loadCloudStats(); $('#cloudRefreshBtn').textContent = '立即更新'; $('#cloudRefreshBtn').disabled = false; }, 5000);
  } else {
    toast((r && r.error) || '失败', 'error');
    $('#cloudRefreshBtn').textContent = '立即更新'; $('#cloudRefreshBtn').disabled = false;
  }
});
$('#cloudCheckBtn').addEventListener('click', async () => {
  const ip = $('#cloudCheckIP').value.trim();
  if (!ip) return;
  const r = await api('/api/cloud-ip/check?ip=' + encodeURIComponent(ip));
  if (r) {
    $('#cloudCheckResult').innerHTML = r.hit
      ? `<span style="color:var(--danger);font-weight:600">命中</span> · ${escapeHTML(r.provider)}`
      : `<span style="color:var(--success)">不在云段</span>`;
  }
});

// ---- 设置 ----
async function loadNotifier() {
  const n = await api('/api/notifier');
  if (!n) return;
  $('#tgEnabled').checked = !!n.enabled;
  $('#tgChatID').value = n.chat_id || '';
  $('#tgThrottle').value = n.throttle || '5m';
  $('#tgBotToken').value = '';
  $('#tgBotTokenHint').textContent = n.has_token
    ? '当前 token: ' + (n.bot_token_masked || '已设置') + '(留空表示保留)'
    : '尚未设置 token';
}
$('#tgSaveBtn').addEventListener('click', async () => {
  const body = {
    enabled: $('#tgEnabled').checked,
    bot_token: $('#tgBotToken').value,
    chat_id: $('#tgChatID').value.trim(),
    throttle: $('#tgThrottle').value.trim() || '5m',
  };
  const r = await apiPost('/api/notifier/update', body);
  if (r && r.ok) { toast('已保存(热生效)', 'success'); loadNotifier(); }
  else toast((r && r.error) || '保存失败', 'error');
});
$('#tgClearTokenBtn').addEventListener('click', async () => {
  if (!confirm('确定清空 bot token?清空后不会再发通知。')) return;
  const r = await apiPost('/api/notifier/update', {
    enabled: false, bot_token: '__clear__',
    chat_id: $('#tgChatID').value.trim(),
    throttle: $('#tgThrottle').value.trim() || '5m',
  });
  if (r && r.ok) { toast('token 已清空', 'success'); loadNotifier(); }
});
$('#testNotifyBtn').addEventListener('click', async () => {
  const r = await apiPost('/api/test-notify', {});
  if (r && r.ok) toast('已发送', 'success');
  else toast((r && r.error) || '失败', 'error');
});

async function loadSettings() {
  const c = await api('/api/config');
  if (c) $('#rulesPre').textContent = JSON.stringify({
    detector: c.detector,
    actions: c.actions,
    paths: c.paths,
    faker: c.faker,
  }, null, 2);
  const ts = await api('/api/tenants');
  if (ts) $('#tenantsPre').textContent = JSON.stringify(ts, null, 2);
}

// ---- 工具 ----
$('#hashBtn').addEventListener('click', async () => {
  const tok = $('#hashInput').value.trim();
  if (!tok) return;
  const r = await api('/api/hash-token?token=' + encodeURIComponent(tok));
  if (r) $('#hashOut').value = r.hash;
});

// ---- 启动 ----
(async function () {
  await loadTenants();
  loadSummary();
})();
