/**
 * AstrBot Scheduled Check-In Plugin - Dashboard Logic (Vanilla JS - 0 External Dependencies)
 */

let sites = [];
let settings = {
  enabled: true,
  random_enabled: true,
  start_time: '08:00',
  end_time: '10:30',
  checkin_time: '08:30',
  http_ssl_verify: true,
  http_timeout_seconds: 15,
  http_impersonate: '',
  http_impersonate_options: [],
  http_impersonate_mldsa: {},
  http_tls_mldsa: false,
  acw_sc_v2_auto_solve: true,
  max_history_records: 0,
  lock_notify_session: '',
  report_level: 'all',
  cf_browser_fallback: true,
  cf_browser_headless: true,
  cf_browser_channel: 'auto',
  cf_browser_timeout_seconds: 60,
  cf_browser_installed: false,
  playwright: {}
};
let logItems = [];
let logsNextBeforeId = null;
let logsHasMore = true;
let logsLoading = false;
let logsTotal = 0;
let logsStartDate = '';
let logsEndDate = '';
let isEdit = false;
let editIndex = -1;
let activeConfirmResolver = null;
let vaultState = { enabled: false, unlocked: false, locked: false };
let keySlots = [];
let activeAnalyticsSite = null;
let analyticsMonth = '';
// Set while a dialog asking for the vault key is open, to watch for an unlock
// performed elsewhere (the standalone passkey page, or another dashboard tab).
let vaultWatch = null;
const VAULT_POLL_MS = 3000;
// Dialogs whose only purpose is getting the vault unlocked. The unlock dialog
// can open the hand-off dialog over itself, so both may be on screen at once.
const VAULT_DIALOG_IDS = ['vault-unlock-modal', 'passkey-modal'];
const PLUGIN_ID = 'astrbot_plugin_scheduled_check_in';

const SLOT_TYPE_LABELS = {
  user_key: '用户密钥',
  webauthn_prf: '通行密钥'
};
// Credentials being edited in the site modal, kept out of `sites` until saved.
let credentialDraft = [];
let credentialSeq = 0;
// Scheduled tasks being edited in the site modal; see the 「定时任务」 tab.
let taskDraft = [];
let taskSeq = 0;

const CREDENTIAL_LABELS = {
  token: 'Authorization Token',
  cookie: 'Cookie',
  github_oauth: 'Github OAuth',
  linuxdo_oauth: 'LinuxDO OAuth'
};

const OAUTH_TYPES = ['github_oauth', 'linuxdo_oauth'];

// Suggested names used when a credential is created. Short on purpose, since
// they show up in the collapsed card header and the action pickers.
const DEFAULT_CREDENTIAL_LABELS = {
  token: 'Token',
  cookie: 'Cookie',
  github_oauth: 'Github',
  linuxdo_oauth: 'LinuxDO'
};

// The full cookie string is required: Github rejects an authorize request
// carrying only user_session and redirects to its login page instead.
const OAUTH_COOKIE_NOTES = {
  github_oauth: '需要 github.com 的完整 Cookie（user_session、__Host-user_session_same_site、_gh_sess、logged_in），仅有 user_session 会被 Github 拒绝。',
  linuxdo_oauth: '需要 connect.linux.do 的完整 Cookie（_t、_forum_session）——授权请求发往该 SSO 域名，复制 linux.do 论坛域名的 Cookie 无效。'
};

// Github fingerprints the client on each authorize request. A server-side call
// looks unlike the browser the cookie was issued to, so the session can be
// invalidated — sometimes logging the user out of github.com as well.
const OAUTH_COOKIE_VOLATILITY = {
  github_oauth: 'Github 会对请求环境做检测，服务端发起的授权可能触发风控并使该 Cookie 失效'
    + '（有时会连带注销浏览器登录）。失效后需重新复制，必要时改用 LinuxDO OAuth 或 Token / Cookie 凭据。',
  // Cloudflare fronts connect.linux.do and can serve a JS challenge. Say what
  // gets past it here, rather than only after a check-in failed. Kept to
  // roughly the length of the Github note above — the full detail is in the
  // failure message.
  linuxdo_oauth: 'connect.linux.do 由 Cloudflare 托管，可能以人机验证页拦截服务端请求；'
    + 'Cloudflare 会拦截不带 ML-DSA 的 Chrome 握手，可在「全局设置 → 网络与常规」开启「TLS 携带 ML-DSA」补上；'
    + '带上也不保证每次通过，长期稳定建议改用 Github OAuth 或 Token / Cookie 凭据。'
};

// What the global ML-DSA switch does under a fingerprint, keyed by
// core/http_client.py mldsa_support().
const MLDSA_SUPPORT_NOTES = {
  native: fingerprint => `所选指纹 ${fingerprint} 已自带 ML-DSA，开关与否都会携带。`,
  added: fingerprint => `所选指纹 ${fingerprint} 不带 ML-DSA，开启后在其签名算法前补上。`,
  not_chromium: fingerprint => `所选指纹 ${fingerprint} 不是 Chrome / Edge 指纹，此项不生效——真实的 Firefox / Safari 不发送 ML-DSA。`,
  old_build: () => '当前 curl_cffi 版本过旧，无法发送 ML-DSA，此项不生效；可在「全局设置 → 网络与常规」重新安装 curl_cffi（需 0.16.2 及以上）。'
};

// Endpoints each framework already knows, shown as placeholder hints.
const FRAMEWORK_DEFAULTS = {
  'new-api': {
    checkin: '留空自动 POST /api/user/checkin',
    balance: '留空自动使用 /api/user/self',
    newApiUser: '跟随框架时会自动探测 new-api-user 并回写到此处'
  },
  generic_rest: {
    checkin: '留空将直接 GET 访问 Base URL（该框架未适配签到接口）',
    balance: '留空则不查询余额（该框架未适配余额接口）',
    newApiUser: ''
  }
};

// Helper: Toast Notifications
function showToast(message, type = 'success', duration = 3500) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const rawText = String(message || '').trim();
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.title = rawText; // Hover to view full text when truncated
  toast.textContent = rawText.length > 500 ? rawText.substring(0, 500) + '...' : rawText;
  toast.addEventListener('click', () => toast.remove());
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, duration);
}

// Helper: Custom Confirm Dialog (Avoids iframe sandbox confirm() restrictions)
function showConfirm(message, onConfirm) {
  const msgEl = document.getElementById('confirm-message');
  const okBtn = document.getElementById('confirm-ok-btn');
  if (activeConfirmResolver) {
    activeConfirmResolver(false);
    activeConfirmResolver = null;
  }
  if (msgEl) msgEl.textContent = message;
  return new Promise(resolve => {
    activeConfirmResolver = resolve;
    if (okBtn) {
      okBtn.onclick = async () => {
        activeConfirmResolver = null;
        closeModal('confirm-modal');
        if (onConfirm) await onConfirm();
        resolve(true);
      };
    }
    openModal('confirm-modal');
  });
}

function cancelConfirm() {
  if (activeConfirmResolver) {
    const resolve = activeConfirmResolver;
    activeConfirmResolver = null;
    closeModal('confirm-modal');
    resolve(false);
    return;
  }
  closeModal('confirm-modal');
}

function isVaultLocked() {
  return vaultState.locked === true;
}

function getSiteId(site) {
  // Site IDs are transported as trimmed strings, matching the scheduler API.
  return String(site?.id ?? '').trim();
}

function normalizeImpersonateValue(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

// Helper: Open URL
function openUrl(url) {
  if (!url) return;
  let target = url;
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = 'https://' + target;
  }
  window.open(target, '_blank');
}

// API Bridge Wrappers
async function apiGet(endpoint, params = {}) {
  if (window.AstrBotPluginPage) {
    try {
      return await window.AstrBotPluginPage.apiGet(endpoint, params);
    } catch (e) {
      console.error('AstrBotPluginPage apiGet error:', e);
    }
  }
  const query = new URLSearchParams(params).toString();
  const url = query ? `${endpoint}?${query}` : endpoint;
  const res = await fetch(url);
  return await res.json();
}

async function apiPost(endpoint, body = {}) {
  if (window.AstrBotPluginPage) {
    try {
      return await window.AstrBotPluginPage.apiPost(endpoint, body);
    } catch (e) {
      console.error('AstrBotPluginPage apiPost error:', e);
    }
  }
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return await res.json();
}

// Like apiPost, but a failure's message reaches the caller rather than the
// console, and a failed request is never sent a second time: installs are not
// something to repeat by accident.
async function apiPostReportingErrors(endpoint, body = {}) {
  if (window.AstrBotPluginPage) {
    try {
      return await window.AstrBotPluginPage.apiPost(endpoint, body);
    } catch (e) {
      return { status: 'error', message: e?.message || String(e) };
    }
  }
  return apiPost(endpoint, body);
}

// Modal Controls
function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('active');
  // Every way out of a vault dialog — its close button, 取消 / 了解, and an
  // overlay click — lands here. Stop the watch only once the last one is gone:
  // closing the hand-off dialog while the unlock dialog is still open must not
  // end the wait it is still there for.
  if (VAULT_DIALOG_IDS.includes(id) && !anyVaultDialogOpen()) stopVaultWatch();
}

function handleOverlayClick(event, id) {
  if (event.target.id === id) {
    if (id === 'confirm-modal') {
      cancelConfirm();
    } else {
      closeModal(id);
    }
  }
}

// Data Loaders & Renderers
async function loadSites() {
  const tbody = document.getElementById('sites-tbody');
  try {
    const data = await apiGet('/api/sites');
    sites = Array.isArray(data) ? data : [];
    renderSitesTable();
  } catch (e) {
    renderTableMessage(tbody, '读取站点列表失败');
    showToast('读取站点列表失败', 'error');
  }
}

function getTodayStr() {
  const d = new Date();
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function getCurrentMonthStr() {
  return getTodayStr().substring(0, 7);
}

function renderCheckInStatus(site) {
  const todayStr = getTodayStr();
  const statusButton = document.createElement('button');
  statusButton.type = 'button';
  statusButton.className = 'status-chip';
  statusButton.title = '点击查看签到日历和余额变化';
  statusButton.addEventListener('click', () => openSiteAnalytics(site));
  const timeStr = site.last_checkin_time ? String(site.last_checkin_time).substring(0, 5) : '';

  if (site.last_checkin_date === todayStr && site.last_checkin_success) {
    statusButton.classList.add('status-chip-success');
    statusButton.textContent = `已签到${timeStr ? ' (' + timeStr + ')' : ''}`;
    return statusButton;
  }
  if (site.last_checkin_date === todayStr && site.last_checkin_success === false) {
    statusButton.classList.add('status-chip-failure');
    statusButton.textContent = `失败${timeStr ? ' (' + timeStr + ')' : ''}`;
    return statusButton;
  }
  statusButton.classList.add('status-chip-warning');
  statusButton.textContent = '未签到';
  return statusButton;
}

function renderTableMessage(tbody, message) {
  if (!tbody) return;
  tbody.replaceChildren();
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = 6;
  cell.className = 'empty-text';
  cell.textContent = message;
  row.appendChild(cell);
  tbody.appendChild(row);
}

function createActionButton(label, className, handler, addMargin = true) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `btn btn-sm${className ? ` ${className}` : ''}`;
  button.textContent = label;
  if (addMargin) button.style.marginRight = '6px';
  button.addEventListener('click', handler);
  return button;
}

function renderSitesTable() {
  const tbody = document.getElementById('sites-tbody');
  if (!tbody) return;

  if (sites.length === 0) {
    renderTableMessage(tbody, '暂无中转站，请点击右上角添加');
    return;
  }

  tbody.replaceChildren();
  sites.forEach((site, index) => {
    const row = document.createElement('tr');
    const locked = site.locked === true;
    if (locked) row.classList.add('row-locked');

    const nameCell = document.createElement('td');
    const name = document.createElement('strong');
    name.textContent = site.name;
    nameCell.appendChild(name);
    if (locked) {
      const lockTag = document.createElement('span');
      lockTag.className = 'badge badge-warning';
      lockTag.style.marginLeft = '8px';
      lockTag.textContent = '锁定';
      lockTag.title = '配置已加密，请先输入密钥解锁';
      nameCell.appendChild(lockTag);
    }
    row.appendChild(nameCell);

    const typeCell = document.createElement('td');
    const typeBadge = document.createElement('span');
    typeBadge.className = `badge ${site.type === 'new-api' ? 'badge-success' : 'badge-info'}`;
    typeBadge.textContent = site.type;
    typeCell.appendChild(typeBadge);
    row.appendChild(typeCell);

    const urlCell = document.createElement('td');
    const urlButton = document.createElement('button');
    urlButton.type = 'button';
    urlButton.className = 'link link-button';
    urlButton.textContent = site.base_url;
    urlButton.addEventListener('click', () => openUrl(site.base_url));
    urlCell.appendChild(urlButton);
    row.appendChild(urlCell);

    const statusCell = document.createElement('td');
    statusCell.appendChild(renderCheckInStatus(site));
    if (site.checkin_target && site.checkin_target.display_text) {
      const target = document.createElement('div');
      target.className = 'form-hint';
      target.textContent = `自定义时间：${site.checkin_target.display_text}`;
      statusCell.appendChild(target);
    }
    row.appendChild(statusCell);

    const enabledCell = document.createElement('td');
    const switchLabel = document.createElement('label');
    switchLabel.className = 'switch';
    const enabledInput = document.createElement('input');
    enabledInput.type = 'checkbox';
    enabledInput.checked = site.enabled === true;
    enabledInput.addEventListener('change', event => {
      toggleSiteEnabled(index, event.currentTarget.checked);
    });
    const slider = document.createElement('span');
    slider.className = 'slider';
    switchLabel.append(enabledInput, slider);
    enabledCell.appendChild(switchLabel);
    row.appendChild(enabledCell);

    const actionsCell = document.createElement('td');
    actionsCell.style.textAlign = 'right';
    actionsCell.style.paddingRight = '24px';
    const actionButtons = [];
    const siteId = getSiteId(site);
    const recheckButton = createActionButton(
      '重新签到',
      'btn-success-plain',
      async () => {
        if (recheckButton.dataset.rechecking === 'true') return;
        recheckButton.disabled = true;
        recheckButton.dataset.rechecking = 'true';
        try {
          await recheckInSite(index);
        } finally {
          if (getSiteId(sites[index]) === siteId) {
            recheckButton.disabled = false;
          }
          delete recheckButton.dataset.rechecking;
        }
      }
    );
    const testButton = createActionButton('测试', 'btn-primary-plain', () => testSingleSite(index));
    const editButton = createActionButton('编辑', '', () => openEditSiteModal(index));
    if (locked) {
      // Editing or running a locked site would overwrite unreadable secrets.
      [recheckButton, testButton, editButton].forEach(button => {
        button.disabled = true;
        button.title = '配置已加密，请先输入密钥解锁';
      });
    }
    actionButtons.push(
      recheckButton,
      testButton,
      editButton,
      createActionButton('删除', 'btn-danger-plain', () => deleteSite(index), false)
    );
    actionsCell.append(...actionButtons);
    row.appendChild(actionsCell);
    tbody.appendChild(row);
  });
}

function formatBalanceNumber(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  return Number(number.toFixed(3)).toString();
}

function formatBalance(value) {
  if (value === null || value === undefined || value === '') return '暂无数据';
  const formatted = formatBalanceNumber(value);
  return formatted === null ? '暂无数据' : `$${formatted}`;
}

function formatBalanceChange(value) {
  if (value === null || value === undefined || value === '') return '首次记录';
  const number = Number(value);
  if (!Number.isFinite(number)) return '首次记录';
  return `${number > 0 ? '+' : ''}$${formatBalanceNumber(number)}`;
}

function formatSignedBalance(value) {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  return `${number >= 0 ? '+' : '-'}$${formatBalanceNumber(Math.abs(number))}`;
}

function getAnalyticsTypeLabel(type) {
  if (type === 'test') return '测试连接';
  if (type === 'manual') return '手动签到';
  return '自动签到';
}

function formatAnalyticsMonth(month) {
  const match = /^(\d{4})-(\d{2})$/.exec(month || '');
  return match ? `${match[1]} 年 ${Number(match[2])} 月` : month || '签到日历';
}

function changeAnalyticsMonth(delta) {
  if (!analyticsMonth) analyticsMonth = getCurrentMonthStr();
  const [year, month] = analyticsMonth.split('-').map(Number);
  const next = new Date(year, month - 1 + delta, 1);
  analyticsMonth = `${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, '0')}`;
  loadSiteAnalytics();
}

function openSiteAnalytics(site) {
  if (!site) return;
  activeAnalyticsSite = site;
  analyticsMonth = getCurrentMonthStr();
  const title = document.getElementById('site-analytics-title');
  if (title) title.textContent = `${site.name || '站点'} · 签到日历`;
  openModal('site-analytics-modal');
  loadSiteAnalytics();
}

async function loadSiteAnalytics() {
  if (!activeAnalyticsSite) return;
  const siteId = getSiteId(activeAnalyticsSite);
  const requestedMonth = analyticsMonth || getCurrentMonthStr();
  analyticsMonth = requestedMonth;
  const calendar = document.getElementById('site-checkin-calendar');
  const chart = document.getElementById('site-balance-chart');
  const notice = document.getElementById('site-analytics-notice');
  if (calendar) calendar.innerHTML = '<div class="analytics-loading">正在读取签到记录...</div>';
  if (chart) chart.innerHTML = '<div class="analytics-loading">正在读取余额变化...</div>';
  if (notice) {
    notice.hidden = true;
    notice.textContent = '';
  }

  try {
    const data = await apiGet('/api/sites/activity', {
      site_id: siteId,
      month: requestedMonth
    });
    if (!data || data.error || data.status === 'error') {
      throw new Error(data?.message || data?.error || '读取站点活动记录失败');
    }
    if (
      !activeAnalyticsSite
      || getSiteId(activeAnalyticsSite) !== siteId
      || analyticsMonth !== requestedMonth
    ) {
      return;
    }
    renderSiteAnalytics(data);
  } catch (e) {
    console.error('loadSiteAnalytics error:', e);
    if (calendar) calendar.innerHTML = '<div class="analytics-empty">暂时无法读取签到记录</div>';
    if (chart) chart.innerHTML = '<div class="analytics-empty">暂时无法读取余额变化</div>';
    showToast(e.message || '读取站点活动记录失败', 'error');
  }
}

function renderSiteAnalytics(data) {
  const monthLabel = document.getElementById('site-analytics-month');
  if (monthLabel) monthLabel.textContent = formatAnalyticsMonth(data.month || analyticsMonth);

  const supportsBalance = data.supports_balance === true
    || ['new-api', 'one-api'].includes(String(data.site?.type || '').trim().toLowerCase());
  const balanceSection = document.getElementById('site-balance-section');
  if (balanceSection) balanceSection.hidden = !supportsBalance;

  const notice = document.getElementById('site-analytics-notice');
  if (notice) {
    const truncated = data.history_truncated === true;
    const limit = Number(data.history_record_limit || 0);
    notice.hidden = !truncated;
    notice.textContent = truncated
      ? `本月日志超过 ${limit.toLocaleString()} 条，仅展示最近记录，统计可能不完整`
      : '';
  }

  const summary = document.getElementById('site-analytics-summary');
  if (summary) {
    summary.replaceChildren();
    const summaryItems = [
      ['本月签到', `${Number(data.success_days || 0)} 天`, 'success'],
      ['失败记录', `${Number(data.failure_days || 0)} 天`, 'failure'],
    ];
    if (supportsBalance) {
      summaryItems.push([
        '签到余额(总余额)',
        formatBalance(data.current_balance !== undefined ? data.current_balance : data.latest_balance),
        'balance'
      ]);
    }
    summaryItems.forEach(([label, value, className]) => {
      const item = document.createElement('div');
      item.className = `analytics-stat ${className}`;
      const labelElement = document.createElement('span');
      labelElement.textContent = label;
      const valueElement = document.createElement('strong');
      valueElement.textContent = value;
      item.append(labelElement, valueElement);
      summary.appendChild(item);
    });
  }

  renderSiteCalendar(
    Array.isArray(data.days) ? data.days : [],
    data.month || analyticsMonth,
    supportsBalance ? data.current_balance : null,
    supportsBalance
  );
  renderBalanceHistory(supportsBalance && Array.isArray(data.balance_history) ? data.balance_history : []);
}

function renderSiteCalendar(days, month, currentBalance = null, showBalance = true) {
  const container = document.getElementById('site-checkin-calendar');
  if (!container) return;
  container.replaceChildren();

  const match = /^(\d{4})-(\d{2})$/.exec(month || '');
  if (!match) {
    container.textContent = '月份格式无效';
    return;
  }
  const year = Number(match[1]);
  const monthNumber = Number(match[2]);
  const firstDay = (new Date(year, monthNumber - 1, 1).getDay() + 6) % 7;
  const daysInMonth = new Date(year, monthNumber, 0).getDate();
  const dayMap = new Map(days.map(day => [day.date, day]));

  const grid = document.createElement('div');
  grid.className = 'analytics-calendar-grid';
  ['一', '二', '三', '四', '五', '六', '日'].forEach(label => {
    const weekday = document.createElement('div');
    weekday.className = 'analytics-calendar-weekday';
    weekday.textContent = label;
    grid.appendChild(weekday);
  });

  for (let index = 0; index < firstDay; index += 1) {
    const emptyCell = document.createElement('div');
    emptyCell.className = 'analytics-calendar-cell is-empty';
    grid.appendChild(emptyCell);
  }

  for (let dayNumber = 1; dayNumber <= daysInMonth; dayNumber += 1) {
    const date = `${year}-${String(monthNumber).padStart(2, '0')}-${String(dayNumber).padStart(2, '0')}`;
    const record = dayMap.get(date);
    const cell = document.createElement('div');
    cell.className = 'analytics-calendar-cell';
    if (date === getTodayStr()) cell.classList.add('is-today');
    if (record) cell.classList.add(record.status === 'success' ? 'is-success' : 'is-failure');
    cell.title = record?.message || (
      record ? (record.status === 'success' ? '签到成功' : '签到失败') : '当天没有签到记录'
    );

    const number = document.createElement('span');
    number.className = 'analytics-calendar-date';
    number.textContent = String(dayNumber);
    const marker = document.createElement('span');
    marker.className = 'analytics-calendar-marker';
    marker.textContent = record ? (record.status === 'success' ? '✓' : '×') : '·';
    cell.append(number, marker);

    if (showBalance && record?.balance !== null && record?.balance !== undefined) {
      const balanceRow = document.createElement('div');
      balanceRow.className = 'analytics-calendar-balance-row';
      balanceRow.title = '左侧为本次签到增量，括号内为记录总余额';
      const gained = document.createElement('small');
      gained.className = 'analytics-calendar-gain';
      gained.textContent = formatSignedBalance(record.gained_quota);
      const displayBalance = date === getTodayStr() && currentBalance !== null && currentBalance !== undefined
        ? currentBalance
        : record.balance;
      const total = document.createElement('small');
      total.className = 'analytics-calendar-total';
      total.textContent = `(${formatBalance(displayBalance)})`;
      balanceRow.append(gained, total);
      cell.appendChild(balanceRow);
    }
    grid.appendChild(cell);
  }
  container.appendChild(grid);
}

function renderBalanceHistory(history) {
  const chartContainer = document.getElementById('site-balance-chart');
  const listContainer = document.getElementById('site-balance-list');
  if (!chartContainer || !listContainer) return;
  chartContainer.replaceChildren();
  listContainer.replaceChildren();

  if (history.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'analytics-empty';
    empty.textContent = '本月没有可用的余额记录';
    chartContainer.appendChild(empty);
    return;
  }

  const chartPoints = history
    .slice(-60)
    .filter(item => Number.isFinite(Number(item.balance)));
  if (chartPoints.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'analytics-empty';
    empty.textContent = '本月没有可用的数值余额记录';
    chartContainer.appendChild(empty);
  } else {
    const values = chartPoints.map(item => Number(item.balance));
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min;
    const chart = document.createElement('div');
    chart.className = 'analytics-balance-chart';
    chartPoints.forEach(item => {
      const value = Number(item.balance);
      const column = document.createElement('div');
      column.className = 'analytics-balance-column';
      column.title = `${item.timestamp || ''} · ${formatBalance(value)}`;
      const barTrack = document.createElement('div');
      barTrack.className = 'analytics-balance-bar-track';
      const bar = document.createElement('div');
      bar.className = 'analytics-balance-bar';
      bar.style.height = `${span === 0 ? 52 : 18 + ((value - min) / span) * 82}%`;
      barTrack.appendChild(bar);
      const date = document.createElement('small');
      date.textContent = String(item.date || '').substring(5);
      const valueLabel = document.createElement('span');
      valueLabel.textContent = formatBalance(value);
      column.append(barTrack, valueLabel, date);
      chart.appendChild(column);
    });
    chartContainer.appendChild(chart);
  }

  const list = document.createElement('div');
  list.className = 'analytics-balance-list';
  history.slice().reverse().forEach(item => {
    const row = document.createElement('div');
    row.className = 'analytics-balance-row';
    const info = document.createElement('div');
    info.className = 'analytics-balance-info';
    const timestamp = document.createElement('strong');
    timestamp.textContent = item.timestamp || '未记录时间';
    const type = document.createElement('span');
    type.textContent = getAnalyticsTypeLabel(item.type);
    info.append(timestamp, type);
    const value = document.createElement('div');
    value.className = 'analytics-balance-value';
    const balance = document.createElement('strong');
    balance.textContent = formatBalance(item.balance);
    const change = document.createElement('span');
    const changeNumber = Number(item.change);
    change.className = Number.isFinite(changeNumber)
      ? (changeNumber > 0 ? 'is-increase' : changeNumber < 0 ? 'is-decrease' : 'is-flat')
      : 'is-first';
    change.textContent = formatBalanceChange(item.change);
    value.append(balance, change);
    row.append(info, value);
    list.appendChild(row);
  });
  listContainer.appendChild(list);
}

async function toggleSiteEnabled(index, enabled) {
  if (sites[index]) {
    sites[index].enabled = enabled;
    await saveSites();
  }
}

async function saveSites() {
  try {
    const data = await apiPostReportingErrors('/api/sites', sites);
    if (data && data.status === 'error') {
      showToast(data.message || '保存配置失败', 'error', 8000);
      return false;
    }
    showToast('配置更新成功', 'success');
    return true;
  } catch (e) {
    showToast('保存配置失败', 'error');
    return false;
  }
}

// Header Dynamic Key-Value Editor Helpers (one editor per action)
function getHeadersContainer(action) {
  return document.getElementById(`${action}-headers-container`);
}

function addHeaderRow(action, key = '', value = '') {
  const container = getHeadersContainer(action);
  if (!container) return;

  const row = document.createElement('div');
  row.className = 'kv-row';
  const keyInput = document.createElement('input');
  keyInput.type = 'text';
  keyInput.className = 'form-control kv-key';
  keyInput.placeholder = 'Header 名称';
  keyInput.value = key;
  const valueInput = document.createElement('input');
  valueInput.type = 'text';
  valueInput.className = 'form-control kv-value';
  valueInput.placeholder = 'Header 值';
  valueInput.value = value;
  const removeButton = document.createElement('button');
  removeButton.type = 'button';
  removeButton.className = 'btn-icon-danger';
  removeButton.title = '删除此 Header';
  removeButton.textContent = '×';
  removeButton.addEventListener('click', () => row.remove());
  row.append(keyInput, valueInput, removeButton);
  container.appendChild(row);
}

function setHeaderRows(action, pairs) {
  const container = getHeadersContainer(action);
  if (!container) return;
  container.replaceChildren();
  (Array.isArray(pairs) ? pairs : []).forEach(pair => {
    if (pair && pair.key) addHeaderRow(action, pair.key, pair.value ?? '');
  });
}

function getHeaderPairs(action) {
  const container = getHeadersContainer(action);
  if (!container) return [];
  const pairs = [];
  container.querySelectorAll('.kv-row').forEach(row => {
    const key = row.querySelector('.kv-key')?.value.trim();
    const value = row.querySelector('.kv-value')?.value.trim();
    if (key) pairs.push({ key, value: value || '' });
  });
  return pairs;
}

// Site Modal Tabs
function switchSiteTab(tab) {
  if (tab === 'tasks') {
    readCredentialDraftFromDom();
    refreshTaskCredentialOptions();
  }
  document.querySelectorAll('#site-tab-bar .tab-btn').forEach(button => {
    button.classList.toggle('active', button.dataset.tab === tab);
  });
  document.querySelectorAll('#site-modal .tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.dataset.panel === tab);
  });
}

// Settings Modal Tabs
function switchSettingsTab(tab) {
  document.querySelectorAll('#settings-tab-bar .tab-btn').forEach(button => {
    button.classList.toggle('active', button.dataset.tab === tab);
  });
  document.querySelectorAll('#settings-modal .tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.dataset.panel === tab);
  });
}

// Credential Editor
function nextCredentialId() {
  credentialSeq += 1;
  return `cred_${Date.now()}_${credentialSeq}`;
}

function addCredential(type) {
  credentialDraft.push({
    id: nextCredentialId(),
    type,
    // Pre-filled from the type so a card is never nameless; the user may edit
    // or clear it, and an empty label falls back to the type in the pickers.
    label: DEFAULT_CREDENTIAL_LABELS[type] || CREDENTIAL_LABELS[type] || '',
    value: '',
    auto_bearer: type === 'token' ? true : undefined,
    has_session: false
  });
  renderCredentials();
  renderActionCredentialOptions('checkin');
  renderActionCredentialOptions('balance');
}

function removeCredential(credentialId) {
  credentialDraft = credentialDraft.filter(item => item.id !== credentialId);
  renderCredentials();
  renderActionCredentialOptions('checkin');
  renderActionCredentialOptions('balance');
}

function readCredentialDraftFromDom() {
  const list = document.getElementById('credentials-list');
  if (!list) return;
  list.querySelectorAll('.cred-card').forEach(card => {
    const credential = credentialDraft.find(item => item.id === card.dataset.credId);
    if (!credential) return;
    credential.label = card.querySelector('.cred-label')?.value.trim() || '';
    credential.value = card.querySelector('.cred-value')?.value.trim() || '';
    const autoBearer = card.querySelector('.cred-auto-bearer');
    if (autoBearer) credential.auto_bearer = autoBearer.checked;
  });
}

// Cookies each OAuth provider needs, mirroring core/oauth.py PROVIDERS.
const OAUTH_REQUIRED_COOKIES = {
  github_oauth: ['user_session', '__Host-user_session_same_site', '_gh_sess', 'logged_in'],
  linuxdo_oauth: ['_t', '_forum_session']
};

const OAUTH_COOKIE_DOMAIN = {
  github_oauth: 'github.com',
  linuxdo_oauth: 'connect.linux.do'
};

/** Parse a raw Cookie header into an ordered name/value map. */
function parseCookieString(raw) {
  const jar = {};
  String(raw || '').split(';').forEach(part => {
    const index = part.indexOf('=');
    if (index <= 0) return;
    const name = part.slice(0, index).trim();
    if (name) jar[name] = part.slice(index + 1).trim();
  });
  return jar;
}

function buildCookieString(jar) {
  return Object.entries(jar)
    .filter(([name, value]) => name && value)
    .map(([name, value]) => `${name}=${value}`)
    .join('; ');
}

/**
 * Pull the Cookie header out of a pasted "Copy as cURL" command.
 * Chrome emits -H 'Cookie: ...', PowerShell copies use double quotes, and
 * newer Chrome uses -b 'Cookie'. All three are accepted.
 */
function extractCookieFromCurl(text) {
  const raw = String(text || '');
  if (!/\bcurl\b/i.test(raw)) return '';
  const patterns = [
    /-H\s+'cookie:\s*([^']*)'/i,
    /-H\s+"cookie:\s*((?:[^"\\]|\\.)*)"/i,
    /-b\s+'([^']*)'/i,
    /-b\s+"((?:[^"\\]|\\.)*)"/i
  ];
  for (const pattern of patterns) {
    const match = raw.match(pattern);
    if (match) return match[1].replace(/\\"/g, '"').trim();
  }
  return '';
}

/** Describe which required cookies are absent from a cookie string. */
function missingCookies(type, value) {
  const required = OAUTH_REQUIRED_COOKIES[type] || [];
  const jar = parseCookieString(value);
  return required.filter(name => !jar[name]);
}

function credentialSummary(credential) {
  if (OAUTH_TYPES.includes(credential.type)) {
    if (!credential.value) return '未填写';
    const missing = missingCookies(credential.type, credential.value);
    return missing.length ? `缺少 ${missing.length} 项 Cookie` : 'Cookie 完整';
  }
  if (!credential.value) return '未填写';
  const text = String(credential.value);
  return text.length <= 10 ? '******' : `${text.slice(0, 4)}***${text.slice(-4)}`;
}

/** Say what the ML-DSA switch does under a fingerprint (the saved one by default), if known. */
function mldsaSupportNote(fingerprint = settings.http_impersonate || '') {
  const note = MLDSA_SUPPORT_NOTES[settings.http_impersonate_mldsa?.[fingerprint]];
  return note ? note(fingerprint) : '';
}

function buildCredentialCard(credential) {
  const isOauth = OAUTH_TYPES.includes(credential.type);
  const card = document.createElement('div');
  card.className = 'cred-card collapsed';
  card.dataset.credId = credential.id;

  // ---------- header (always visible, toggles the body) ----------
  const header = document.createElement('div');
  header.className = 'cred-card-header';

  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'cred-toggle';
  toggle.setAttribute('aria-expanded', 'false');

  const caret = document.createElement('span');
  caret.className = 'cred-caret';
  caret.textContent = '▸';
  const tag = document.createElement('span');
  tag.className = `cred-type-tag${isOauth ? ' oauth' : ''}`;
  tag.textContent = CREDENTIAL_LABELS[credential.type] || credential.type;
  const name = document.createElement('span');
  name.className = 'cred-name';
  name.textContent = credential.label || '未命名';
  const summary = document.createElement('span');
  summary.className = 'cred-summary';
  summary.textContent = credentialSummary(credential);
  toggle.append(caret, tag, name, summary);

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'btn-icon-danger';
  remove.title = '删除此凭据';
  remove.textContent = '×';
  remove.addEventListener('click', event => {
    event.stopPropagation();
    readCredentialDraftFromDom();
    removeCredential(credential.id);
  });
  header.append(toggle, remove);
  card.appendChild(header);

  const body = document.createElement('div');
  body.className = 'cred-card-body';
  toggle.addEventListener('click', () => {
    const collapsed = card.classList.toggle('collapsed');
    caret.textContent = collapsed ? '▸' : '▾';
    toggle.setAttribute('aria-expanded', String(!collapsed));
  });

  // ---------- label ----------
  const labelGroup = document.createElement('div');
  labelGroup.className = 'form-group';
  const labelText = document.createElement('label');
  labelText.textContent = '备注名称 (可选)';
  const labelInput = document.createElement('input');
  labelInput.type = 'text';
  labelInput.className = 'form-control cred-label';
  labelInput.placeholder = '用于在签到/余额页中区分同类凭据';
  labelInput.value = credential.label || '';
  labelInput.addEventListener('input', () => {
    credential.label = labelInput.value.trim();
    name.textContent = credential.label || '未命名';
    renderActionCredentialOptions('checkin');
    renderActionCredentialOptions('balance');
  });
  labelGroup.append(labelText, labelInput);
  body.appendChild(labelGroup);

  // ---------- value ----------
  if (isOauth) {
    body.appendChild(buildOauthCookieEditor(credential, summary));
  } else {
    const valueGroup = document.createElement('div');
    valueGroup.className = 'form-group';
    const valueLabel = document.createElement('label');
    valueLabel.textContent = `${CREDENTIAL_LABELS[credential.type]} *`;
    const valueInput = document.createElement('textarea');
    valueInput.className = 'form-control cred-value';
    valueInput.rows = 3;
    valueInput.placeholder = credential.type === 'token'
      ? '粘贴 Access Token'
      : '例如 session=xxxx; other=yyyy';
    valueInput.value = credential.value || '';
    valueInput.addEventListener('input', () => {
      credential.value = valueInput.value.trim();
      summary.textContent = credentialSummary(credential);
    });
    valueGroup.append(valueLabel, valueInput);
    body.appendChild(valueGroup);
  }

  if (credential.type === 'token') {
    const inlineGroup = document.createElement('div');
    inlineGroup.className = 'form-group cred-inline-row';
    const autoLabel = document.createElement('label');
    autoLabel.className = 'checkbox-label';
    autoLabel.title = '发送请求时自动加上 Bearer 前缀';
    const autoInput = document.createElement('input');
    autoInput.type = 'checkbox';
    autoInput.className = 'cred-auto-bearer';
    autoInput.checked = credential.auto_bearer !== false;
    const autoText = document.createElement('span');
    autoText.textContent = '自动补全 Bearer';
    autoLabel.append(autoInput, autoText);
    inlineGroup.appendChild(autoLabel);
    body.appendChild(inlineGroup);
  }

  if (credential.type === 'cookie' && credential.source_credential_id) {
    const source = credentialDraft.find(item => item.id === credential.source_credential_id);
    const state = document.createElement('div');
    state.className = 'cred-session-state has-session';
    state.textContent = `由「${source ? (source.label || CREDENTIAL_LABELS[source.type]) : '已删除的 OAuth 凭据'}」登录后自动回写`
      + `${credential.value_updated_at ? ` (${credential.value_updated_at})` : ''}，每次登录覆盖；签到与余额需在各自页面选用它才会使用。`;
    body.appendChild(state);
  }

  if (isOauth) {
    const state = document.createElement('div');
    const hasSession = credential.has_session === true || Boolean(credential.session_cookie);
    state.className = `cred-session-state${hasSession ? ' has-session' : ''}`;
    state.textContent = hasSession
      ? `${describeStationSession(credential)}${credential.session_updated_at ? ` (${credential.session_updated_at})` : ''}`
      : '尚未登录，首次签到时会自动完成 OAuth';
    body.appendChild(state);
  }

  card.appendChild(body);
  return card;
}

/**
 * Name the station secrets an OAuth credential holds. Newer New-API builds
 * issue a refresh-token cookie plus a short-lived access token instead of a
 * session cookie; the values themselves never reach the dashboard.
 */
function describeStationSession(credential) {
  const parts = [credential.has_refresh_token ? '刷新令牌 Cookie' : '会话 Cookie'];
  if (credential.has_access_token) {
    const expiresAt = Number(credential.access_expires_at) || 0;
    const expiry = expiresAt
      ? (expiresAt * 1000 > Date.now()
        ? `，${new Date(expiresAt * 1000).toLocaleString()} 到期`
        : `，已过期${credential.has_refresh_token ? '，使用时自动刷新' : ''}`)
      : '';
    parts.push(`访问令牌${expiry}`);
  }
  return `站点已保存：${parts.join('、')}`;
}

/**
 * Cookie editor with two interchangeable modes: one field per required cookie,
 * or a single box accepting a full Cookie header or a pasted cURL command.
 * Both write the same normalized string to `.cred-value`.
 */
function buildOauthCookieEditor(credential, summaryEl) {
  const wrap = document.createElement('div');
  wrap.className = 'form-group cred-cookie-editor';

  const headerRow = document.createElement('div');
  headerRow.className = 'kv-header';
  const label = document.createElement('label');
  label.style.margin = '0';
  label.textContent = `${OAUTH_COOKIE_DOMAIN[credential.type] || '第三方'} Cookie *`;
  const modes = document.createElement('div');
  modes.className = 'cred-mode-switch';
  headerRow.append(label, modes);
  wrap.appendChild(headerRow);

  // The canonical value lives here; both modes keep it in sync.
  const hidden = document.createElement('textarea');
  hidden.className = 'cred-value';
  hidden.hidden = true;
  hidden.value = credential.value || '';
  wrap.appendChild(hidden);

  const formPane = document.createElement('div');
  formPane.className = 'cred-cookie-form';
  const rawPane = document.createElement('div');
  rawPane.className = 'cred-cookie-raw';
  rawPane.style.display = 'none';

  const required = OAUTH_REQUIRED_COOKIES[credential.type] || [];
  const fields = {};

  const status = document.createElement('div');
  status.className = 'form-hint';

  const commit = value => {
    credential.value = value.trim();
    hidden.value = credential.value;
    if (summaryEl) summaryEl.textContent = credentialSummary(credential);
    const missing = missingCookies(credential.type, credential.value);
    const volatility = OAUTH_COOKIE_VOLATILITY[credential.type];
    if (!credential.value) {
      status.className = 'form-hint';
      status.textContent = OAUTH_COOKIE_NOTES[credential.type] || '';
    } else if (missing.length) {
      status.className = 'form-hint cred-cookie-warn';
      status.textContent = `缺少 ${missing.join('、')}，授权可能被拒绝`;
    } else {
      // Complete is not the same as durable, so say so exactly here — this is
      // the moment the user would otherwise assume it is set up for good.
      status.className = 'form-hint cred-cookie-ok';
      status.textContent = `已填写全部 ${required.length} 项必需 Cookie`
        + (volatility ? `。注意：${volatility}` : '');
    }
  };

  // ---- structured mode ----
  required.forEach(cookieName => {
    const row = document.createElement('div');
    row.className = 'kv-row';
    const nameLabel = document.createElement('span');
    nameLabel.className = 'cred-cookie-name';
    nameLabel.textContent = cookieName;
    nameLabel.title = cookieName;
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'form-control';
    input.placeholder = '值';
    input.addEventListener('input', () => {
      const jar = parseCookieString(hidden.value);
      const typed = input.value.trim();
      if (typed) jar[cookieName] = typed;
      else delete jar[cookieName];
      commit(buildCookieString(jar));
    });
    fields[cookieName] = input;
    row.append(nameLabel, input);
    formPane.appendChild(row);
  });

  const extraHint = document.createElement('div');
  extraHint.className = 'form-hint';
  extraHint.textContent = '其他 Cookie 会在切换到「完整粘贴」时保留。';
  formPane.appendChild(extraHint);

  // ---- raw mode ----
  const rawInput = document.createElement('textarea');
  rawInput.className = 'form-control';
  rawInput.rows = 4;
  rawInput.placeholder = '粘贴完整 Cookie，或直接粘贴 DevTools 的「Copy as cURL」命令';
  rawInput.addEventListener('input', () => {
    const fromCurl = extractCookieFromCurl(rawInput.value);
    if (fromCurl) {
      // A pasted cURL command is replaced by just its Cookie header.
      rawInput.value = fromCurl;
      showToast('已从 cURL 命令中提取 Cookie', 'success');
    }
    commit(rawInput.value);
    syncFormFromValue();
  });
  rawPane.appendChild(rawInput);

  function syncFormFromValue() {
    const jar = parseCookieString(hidden.value);
    required.forEach(cookieName => {
      if (fields[cookieName]) fields[cookieName].value = jar[cookieName] || '';
    });
  }

  const setMode = mode => {
    const isRaw = mode === 'raw';
    formPane.style.display = isRaw ? 'none' : 'block';
    rawPane.style.display = isRaw ? 'block' : 'none';
    modes.querySelectorAll('button').forEach(button => {
      button.classList.toggle('active', button.dataset.mode === mode);
    });
    if (isRaw) rawInput.value = hidden.value;
    else syncFormFromValue();
  };

  [['form', '分项填写'], ['raw', '完整粘贴']].forEach(([mode, text]) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-sm';
    button.dataset.mode = mode;
    button.textContent = text;
    button.addEventListener('click', () => setMode(mode));
    modes.appendChild(button);
  });

  wrap.append(formPane, rawPane, status);
  syncFormFromValue();
  commit(hidden.value);
  // Default to the raw box when a value already exists, since a pasted string
  // may hold cookies beyond the required ones.
  setMode(credential.value ? 'raw' : 'form');
  return wrap;
}

function renderCredentials() {
  const list = document.getElementById('credentials-list');
  const count = document.getElementById('credentials-count');
  if (count) count.textContent = String(credentialDraft.length);
  if (!list) return;
  list.replaceChildren();
  if (credentialDraft.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-text';
    empty.textContent = '暂无凭据，请从上方按钮添加';
    list.appendChild(empty);
    return;
  }
  credentialDraft.forEach(credential => list.appendChild(buildCredentialCard(credential)));
}

// Action credential pickers reflect the credentials currently drafted.
function renderActionCredentialOptions(action) {
  const select = document.getElementById(`${action}-credential`);
  const hint = document.getElementById(`${action}-credential-hint`);
  if (!select) return;

  const protocol = document.getElementById(`${action}-protocol`)?.value || 'auto';
  const wantsOauth = action === 'checkin' && protocol === 'oauth';
  const previous = select.value;

  select.replaceChildren();
  const auto = document.createElement('option');
  auto.value = '';
  auto.textContent = wantsOauth ? '自动（优先 Github，其次 LinuxDO）' : '自动（优先 Token，其次 Cookie）';
  select.appendChild(auto);

  const usable = credentialDraft.filter(credential =>
    wantsOauth ? OAUTH_TYPES.includes(credential.type) : true
  );

  // OAUTH_TYPES is in the same order the backend resolves them, so the label
  // can name what will actually be picked instead of a generic priority that
  // may not apply — with only LinuxDO configured, "优先 Github" is misleading.
  const presentOauth = OAUTH_TYPES.filter(type => usable.some(item => item.type === type));
  if (wantsOauth) {
    if (presentOauth.length === 1) {
      auto.textContent = `自动（使用 ${CREDENTIAL_LABELS[presentOauth[0]]}）`;
    } else if (presentOauth.length > 1) {
      auto.textContent = `自动（优先 ${presentOauth.map(t => CREDENTIAL_LABELS[t]).join('，其次 ')}）`;
    }
  }

  usable.forEach(credential => {
    const option = document.createElement('option');
    option.value = credential.id;
    const name = CREDENTIAL_LABELS[credential.type] || credential.type;
    option.textContent = credential.label ? `${name} — ${credential.label}` : name;
    select.appendChild(option);
  });
  select.value = usable.some(item => item.id === previous) ? previous : '';

  if (hint) {
    const missingOauth = OAUTH_TYPES.filter(type => !presentOauth.includes(type));
    if (credentialDraft.length === 0) {
      hint.textContent = '请先在「凭据」页添加至少一个凭据。';
    } else if (wantsOauth && usable.length === 0) {
      hint.textContent = 'OAuth 协议需要一个 Github 或 LinuxDO OAuth 凭据。';
    } else if (wantsOauth && missingOauth.length) {
      // Point out the alternative provider: Github credentials are the fragile
      // ones, so knowing LinuxDO can be added here is worth surfacing.
      hint.textContent =
        `还可在「凭据」页添加 ${missingOauth.map(t => CREDENTIAL_LABELS[t]).join('、')} 作为备选，`
        + '在当前凭据失效时切换使用。';
    } else {
      hint.textContent = '';
    }
  }

  const protocolHint = document.getElementById(`${action}-protocol-hint`);
  if (protocolHint) {
    protocolHint.textContent = wantsOauth
      ? '适用于二次开发后关闭了通用签到端点、只能靠重新登录自动签到的站点：每次签到都会重新走一次 OAuth 登录，而不是复用已保存的会话。'
      : '';
  }
  if (action === 'checkin') renderFrameworkHints();
}

function renderFrameworkHints() {
  const type = document.getElementById('site-type')?.value || 'new-api';
  const defaults = FRAMEWORK_DEFAULTS[type] || FRAMEWORK_DEFAULTS['new-api'];
  const checkinHint = document.getElementById('checkin-path-hint');
  const balanceHint = document.getElementById('balance-path-hint');
  const isOauth = document.getElementById('checkin-protocol')?.value === 'oauth';
  if (checkinHint) {
    checkinHint.textContent = isOauth
      ? 'Path 会被忽略：登录本身即签到，不再请求任何签到端点。'
      : defaults.checkin;
  }
  if (balanceHint) balanceHint.textContent = defaults.balance;
  ['checkin', 'balance'].forEach(name => {
    const headerHint = document.getElementById(`${name}-headers-hint`);
    if (headerHint) headerHint.textContent = defaults.newApiUser;
    // Only New-API exposes a new-api-user id to fetch.
    const fetchButton = document.getElementById(`${name}-fetch-user`);
    if (fetchButton) fetchButton.style.display = type === 'new-api' ? '' : 'none';
  });
}

function fillActionForm(action, config) {
  const source = config && typeof config === 'object' ? config : {};
  const path = document.getElementById(`${action}-path`);
  const protocol = document.getElementById(`${action}-protocol`);
  if (path) path.value = source.path || '';
  if (protocol) protocol.value = source.protocol || 'auto';
  setHeaderRows(action, source.headers);
  renderActionCredentialOptions(action);
  const credential = document.getElementById(`${action}-credential`);
  if (credential) {
    const wanted = source.credential_id || '';
    credential.value = credentialDraft.some(item => item.id === wanted) ? wanted : '';
  }
  if (action === 'checkin') fillCheckinSchedule(source.schedule);
}

function readActionForm(action) {
  const config = {
    path: document.getElementById(`${action}-path`)?.value.trim() || '',
    protocol: document.getElementById(`${action}-protocol`)?.value || 'auto',
    credential_id: document.getElementById(`${action}-credential`)?.value || '',
    headers: getHeaderPairs(action)
  };
  if (action === 'checkin') config.schedule = readCheckinSchedule();
  return config;
}

const CHECKIN_SCHEDULE_DEFAULTS = { mode: 'global', time: '08:30', start: '08:00', end: '10:30' };

/** Load a site's own check-in time into the 签到 tab. */
function fillCheckinSchedule(schedule) {
  const source = { ...CHECKIN_SCHEDULE_DEFAULTS, ...(schedule && typeof schedule === 'object' ? schedule : {}) };
  document.getElementById('checkin-schedule-mode').value = source.mode;
  document.getElementById('checkin-schedule-time').value = source.time;
  document.getElementById('checkin-schedule-start').value = source.start;
  document.getElementById('checkin-schedule-end').value = source.end;
  renderCheckinScheduleFields();
}

/** Every field is sent whatever the mode, so switching back loses nothing. */
function readCheckinSchedule() {
  const value = id => document.getElementById(id)?.value || '';
  return {
    mode: value('checkin-schedule-mode') || 'global',
    time: value('checkin-schedule-time') || CHECKIN_SCHEDULE_DEFAULTS.time,
    start: value('checkin-schedule-start') || CHECKIN_SCHEDULE_DEFAULTS.start,
    end: value('checkin-schedule-end') || CHECKIN_SCHEDULE_DEFAULTS.end
  };
}

function renderCheckinScheduleFields() {
  const mode = document.getElementById('checkin-schedule-mode')?.value || 'global';
  document.getElementById('checkin-schedule-fixed').style.display = mode === 'fixed' ? '' : 'none';
  document.getElementById('checkin-schedule-range').style.display = mode === 'range' ? '' : 'none';
  const hint = document.getElementById('checkin-schedule-hint');
  if (hint) {
    hint.textContent = mode === 'global'
      ? '按「定时签到设置」中的时间与其他站点一起签到。'
      : mode === 'fixed'
        ? '每天在该时间单独签到，不再随全局时间签到；简报单独推送。'
        : '每天在该范围内随机选一个时刻单独签到，不再随全局时间签到；简报单独推送。';
  }
}

/** Check that a site's own range runs forwards within one day. */
function validateCheckinSchedule(schedule) {
  if (schedule.mode === 'fixed' && !schedule.time) return '请填写签到时间';
  if (schedule.mode === 'range') {
    if (!schedule.start || !schedule.end) return '请填写签到时间范围';
    if (schedule.end < schedule.start) return '签到时间范围的结束不能早于开始';
  }
  return '';
}

/**
 * Fetch new-api-user from the station and write it into this action's headers.
 *
 * New-API scopes a Cookie session to a numeric account id through this header.
 * One-API has no equivalent, so a failure there is expected and is reported as
 * such rather than as a breakage.
 */
async function fetchNewApiUser(action) {
  const button = document.getElementById(`${action}-fetch-user`);
  const siteType = document.getElementById('site-type')?.value || 'new-api';
  if (siteType !== 'new-api') {
    showToast('仅 New-API 框架需要 new-api-user，请先将框架类型设为 New-API', 'warning');
    return;
  }
  const baseUrl = document.getElementById('site-url')?.value.trim();
  if (!baseUrl) {
    showToast('请先填写 Base URL', 'warning');
    switchSiteTab('basic');
    return;
  }

  readCredentialDraftFromDom();
  if (credentialDraft.length === 0) {
    showToast('请先在「凭据」页添加一个 Token 或 Cookie 凭据', 'warning');
    switchSiteTab('credentials');
    return;
  }

  const original = button ? button.textContent : '';
  if (button) {
    button.disabled = true;
    button.textContent = '获取中…';
  }
  try {
    // Send the in-progress form rather than the saved site, so the value can be
    // fetched before the site has ever been saved.
    const data = await apiPost('/api/sites/probe-new-api-user', buildSitePayloadFromForm());
    if (!data || data.status !== 'ok' || !data.user_id) {
      showToast(data?.message || '获取 new-api-user 失败', 'error', 7000);
      return;
    }
    setHeaderRows(action, upsertHeaderPair(getHeaderPairs(action), data.header, data.user_id));
    showToast(data.message || `已填入 ${data.header}`, 'success');
  } catch (e) {
    showToast('获取 new-api-user 请求失败', 'error');
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = original;
    }
  }
}

/** Set a header pair by case-insensitive name, appending when absent. */
function upsertHeaderPair(pairs, key, value) {
  const wanted = String(key || '').toLowerCase();
  const next = pairs.map(pair => ({ ...pair }));
  const existing = next.find(pair => pair.key.toLowerCase() === wanted);
  if (existing) {
    existing.value = String(value);
    return next;
  }
  next.push({ key, value: String(value) });
  return next;
}

// ---------------------------------------------------------------------------
// Scheduled tasks (site editor, 「定时任务」 tab)
// ---------------------------------------------------------------------------
// Mirrors core/task_schema.py.
const TASK_INTERVAL_LIMITS = { min: 1, max: 7 * 24 * 60 };
const TASK_CRON_EXAMPLES = '例：*/30 * * * *（每 30 分钟）、0 * * * *（每小时整点）、0 8 * * *（每天 08:00）、0 9 * * 1-5（工作日 09:00）。'
  + '字段依次为 分 时 日 月 星期，星期 0 与 7 都是周日；按运行 AstrBot 的机器的本地时间计算。';

function nextTaskId() {
  taskSeq += 1;
  return `task_${Date.now()}_${taskSeq}`;
}

function newTaskDraft() {
  return {
    id: nextTaskId(),
    name: '',
    enabled: true,
    schedule: 'cron',
    cron: '0 * * * *',
    interval_min: 60,
    interval_max: 120,
    method: 'GET',
    url: '',
    credential_id: '',
    headers: [],
    body: '',
    log_history: true,
    pow_purpose: '',
    state: {},
    expanded: true
  };
}

function addTask() {
  readTaskDraftFromDom();
  taskDraft.forEach(task => { task.expanded = false; });
  taskDraft.push(newTaskDraft());
  renderTasks();
}

function removeTask(taskId) {
  readTaskDraftFromDom();
  taskDraft = taskDraft.filter(task => task.id !== taskId);
  renderTasks();
}

function renderTasks() {
  const list = document.getElementById('tasks-list');
  const count = document.getElementById('tasks-count');
  if (count) count.textContent = String(taskDraft.length);
  if (!list) return;
  list.replaceChildren();
  if (taskDraft.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-text';
    empty.textContent = '暂无定时任务，请从上方按钮添加';
    list.appendChild(empty);
    return;
  }
  taskDraft.forEach(task => list.appendChild(buildTaskCard(task)));
}

function taskHeadersKey(task) {
  return `task-${task.id}`;
}

/**
 * The purpose to solve for, '' when the switch is off.
 *
 * Mirrors normalize_pow_purpose() in core/pow.py, so a purpose that reduces to
 * nothing is caught here rather than saved as no PoW at all.
 */
function readPowPurpose(enabled, purpose) {
  if (!enabled) return '';
  return String(purpose || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 32);
}

/** Read every task card back into taskDraft, headers included. */
function readTaskDraftFromDom() {
  document.querySelectorAll('#tasks-list .task-card').forEach(card => {
    const task = taskDraft.find(item => item.id === card.dataset.taskId);
    if (!task) return;
    const value = selector => card.querySelector(selector);
    task.name = value('.task-name').value.trim();
    task.enabled = value('.task-enabled').checked;
    task.schedule = value('.task-schedule').value;
    task.cron = value('.task-cron').value.trim().split(/\s+/).filter(Boolean).join(' ');
    task.interval_min = Number(value('.task-interval-min').value);
    task.interval_max = Number(value('.task-interval-max').value);
    task.method = value('.task-method').value;
    task.url = value('.task-url').value.trim();
    task.credential_id = value('.task-credential').value;
    task.headers = getHeaderPairs(taskHeadersKey(task));
    task.body = value('.task-body').value;
    task.log_history = value('.task-log-history').checked;
    // Editor-only: a switch turned on before its purpose is typed stays on.
    task.powSwitch = value('.task-pow-enabled').checked;
    task.pow_purpose = readPowPurpose(task.powSwitch, value('.task-pow-purpose').value);
    task.expanded = !card.classList.contains('collapsed');
  });
}

/** Why a task cannot be saved or run, mirroring validate_task(); '' when it can. */
function validateTaskDraft(task) {
  if (!task.url) return '请填写请求 URL';
  if (!/^(https?:\/\/|\/)/i.test(task.url)) return 'URL 须以 http:// 或 https:// 开头，或以 / 开头表示站点 Base URL 下的路径';
  if (task.powSwitch && !task.pow_purpose) return '已开启 Vs PoW，请填写题目用途（如 checkin）';
  if (task.schedule === 'cron') {
    if (!task.cron) return '请填写 cron 表达式';
    if (task.cron.split(' ').length !== 5) return 'cron 表达式应有 5 个字段（分 时 日 月 星期）';
  } else {
    const { min, max } = TASK_INTERVAL_LIMITS;
    const low = task.interval_min;
    const high = task.interval_max;
    if (!Number.isInteger(low) || !Number.isInteger(high) || low < min || high < min || low > max || high > max) {
      return `随机间隔须为 ${min} ~ ${max} 之间的整数分钟`;
    }
    if (low > high) return '随机间隔的最小值不能大于最大值';
  }
  if (task.method === 'POST' && task.body.trim()) {
    try {
      JSON.parse(task.body);
    } catch (e) {
      return `JSON Body 不是合法的 JSON：${e.message}`;
    }
  }
  return '';
}

/** The tasks as they are saved: the editor-only fields left out. */
function readTasksForSave() {
  readTaskDraftFromDom();
  return taskDraft.map(task => ({
    id: task.id,
    name: task.name,
    enabled: task.enabled,
    schedule: task.schedule,
    cron: task.cron,
    interval_min: task.interval_min,
    interval_max: task.interval_max,
    method: task.method,
    url: task.url,
    credential_id: task.credential_id,
    headers: task.headers,
    body: task.body,
    log_history: task.log_history,
    pow_purpose: task.pow_purpose
  }));
}

function describeTaskSchedule(task) {
  if (task.schedule === 'interval') {
    return task.interval_min === task.interval_max
      ? `每 ${task.interval_min} 分钟`
      : `每 ${task.interval_min}~${task.interval_max} 分钟`;
  }
  return task.cron ? `cron ${task.cron}` : '未设置 cron';
}

function describeTaskState(task) {
  const state = task.state || {};
  const parts = [];
  if (!task.enabled) {
    parts.push('已停用');
  } else if (state.next_run_at) {
    parts.push(`下次运行 ${state.next_run_at.slice(0, 16)}`);
  }
  if (state.last_run_at) {
    parts.push(`上次 ${state.last_run_at.slice(5, 16)} ${state.last_success ? '成功' : '失败'}`);
  }
  return parts.join(' · ') || '尚未运行，保存后开始计时';
}

// The credential picker lists the credentials currently drafted.
function fillTaskCredentialOptions(select, selected) {
  select.replaceChildren();
  const none = document.createElement('option');
  none.value = '';
  none.textContent = '不使用凭据（仅发送下方请求头）';
  select.appendChild(none);
  credentialDraft.forEach(credential => {
    const option = document.createElement('option');
    option.value = credential.id;
    const name = CREDENTIAL_LABELS[credential.type] || credential.type;
    option.textContent = credential.label ? `${name} — ${credential.label}` : name;
    select.appendChild(option);
  });
  if (selected && !credentialDraft.some(item => item.id === selected)) {
    const missing = document.createElement('option');
    missing.value = selected;
    missing.textContent = '（该凭据已删除，请重新选择）';
    select.appendChild(missing);
  }
  select.value = selected || '';
}

function refreshTaskCredentialOptions() {
  document.querySelectorAll('#tasks-list .task-card').forEach(card => {
    const select = card.querySelector('.task-credential');
    fillTaskCredentialOptions(select, select.value);
  });
}

let taskPreviewTimers = {};

/** Show the next run times of a card's schedule, as the server works them out. */
function scheduleTaskPreview(card, task) {
  clearTimeout(taskPreviewTimers[task.id]);
  const hint = card.querySelector('.task-schedule-preview');
  taskPreviewTimers[task.id] = setTimeout(async () => {
    const schedule = card.querySelector('.task-schedule').value;
    const payload = {
      schedule,
      cron: card.querySelector('.task-cron').value,
      interval_min: Number(card.querySelector('.task-interval-min').value),
      interval_max: Number(card.querySelector('.task-interval-max').value)
    };
    if (schedule === 'cron' && !payload.cron.trim()) {
      hint.textContent = TASK_CRON_EXAMPLES;
      hint.classList.remove('task-hint-error');
      return;
    }
    try {
      const data = await apiPost('/api/tasks/preview', payload);
      if (data?.error) {
        hint.textContent = data.error;
        hint.classList.add('task-hint-error');
      } else {
        const runs = Array.isArray(data?.runs) ? data.runs : [];
        hint.textContent = schedule === 'cron' ? `接下来：${runs.join('、')}` : runs.join('');
        hint.classList.remove('task-hint-error');
      }
    } catch (e) {
      hint.textContent = schedule === 'cron' ? TASK_CRON_EXAMPLES : '';
      hint.classList.remove('task-hint-error');
    }
  }, 350);
}

function buildTaskCard(task) {
  const card = document.createElement('div');
  card.className = `cred-card task-card${task.expanded ? '' : ' collapsed'}`;
  card.dataset.taskId = task.id;
  const field = (labelText, ...children) => {
    const group = document.createElement('div');
    group.className = 'form-group';
    if (labelText) {
      const label = document.createElement('label');
      label.textContent = labelText;
      group.appendChild(label);
    }
    group.append(...children);
    return group;
  };
  const input = (className, type = 'text', value = '') => {
    const element = document.createElement('input');
    element.type = type;
    element.className = `form-control ${className}`;
    element.value = value;
    return element;
  };
  const select = (className, options, value) => {
    const element = document.createElement('select');
    element.className = `form-control ${className}`;
    options.forEach(([optionValue, text]) => {
      const option = document.createElement('option');
      option.value = optionValue;
      option.textContent = text;
      element.appendChild(option);
    });
    element.value = value;
    return element;
  };
  const hint = (className = '') => {
    const element = document.createElement('div');
    element.className = `form-hint ${className}`.trim();
    return element;
  };
  const checkbox = (className, text, checked) => {
    const label = document.createElement('label');
    label.className = 'checkbox-label';
    const element = document.createElement('input');
    element.type = 'checkbox';
    element.className = className;
    element.checked = checked;
    const span = document.createElement('span');
    span.textContent = text;
    label.append(element, span);
    return { label, element };
  };

  // ---------- header ----------
  const header = document.createElement('div');
  header.className = 'cred-card-header';
  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'cred-toggle';
  const caret = document.createElement('span');
  caret.className = 'cred-caret';
  caret.textContent = task.expanded ? '▾' : '▸';
  const tag = document.createElement('span');
  const name = document.createElement('span');
  name.className = 'cred-name';
  const summary = document.createElement('span');
  summary.className = 'cred-summary';
  toggle.append(caret, tag, name, summary);
  toggle.addEventListener('click', () => {
    const collapsed = card.classList.toggle('collapsed');
    caret.textContent = collapsed ? '▸' : '▾';
  });
  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'btn-icon-danger';
  remove.title = '删除此任务';
  remove.textContent = '×';
  remove.addEventListener('click', event => {
    event.stopPropagation();
    showConfirm(`确定删除定时任务「${task.name || '未命名任务'}」吗？保存站点后生效。`, () => removeTask(task.id));
  });
  header.append(toggle, remove);

  const body = document.createElement('div');
  body.className = 'cred-card-body';

  // ---------- name and switch ----------
  const nameInput = input('task-name', 'text', task.name);
  nameInput.placeholder = '例如：保活请求';
  body.appendChild(field('任务名称', nameInput));
  const enabled = checkbox('task-enabled', '启用此任务', task.enabled !== false);
  const enabledInput = enabled.element;
  body.appendChild(field('', enabled.label));

  // ---------- schedule ----------
  const scheduleSelect = select('task-schedule', [['cron', 'Cron 表达式'], ['interval', '随机时间间隔']], task.schedule);
  const cronInput = input('task-cron', 'text', task.cron);
  cronInput.placeholder = '*/30 * * * *';
  cronInput.spellcheck = false;
  const minInput = input('task-interval task-interval-min', 'number', task.interval_min);
  const maxInput = input('task-interval task-interval-max', 'number', task.interval_max);
  [minInput, maxInput].forEach(element => {
    element.min = String(TASK_INTERVAL_LIMITS.min);
    element.max = String(TASK_INTERVAL_LIMITS.max);
    element.step = '1';
  });
  const intervalRow = document.createElement('div');
  intervalRow.className = 'task-row';
  const between = document.createElement('span');
  between.textContent = '~';
  const unit = document.createElement('span');
  unit.textContent = '分钟（每次运行后在此范围内随机取值）';
  intervalRow.append(minInput, between, maxInput, unit);
  const preview = hint('task-schedule-preview');
  body.appendChild(field('调度方式', scheduleSelect));
  const cronGroup = field('Cron 表达式', cronInput);
  const intervalGroup = field('随机间隔', intervalRow);
  body.append(cronGroup, intervalGroup);
  body.appendChild(preview);

  // ---------- request ----------
  const methodSelect = select('task-method', [['GET', 'GET'], ['POST', 'POST']], task.method);
  const urlInput = input('task-url', 'text', task.url);
  urlInput.placeholder = 'https://example.com/api/ping 或 /api/ping（相对站点 Base URL）';
  const requestRow = document.createElement('div');
  requestRow.className = 'task-row';
  requestRow.append(methodSelect, urlInput);
  body.appendChild(field('请求', requestRow));

  const credentialSelect = document.createElement('select');
  credentialSelect.className = 'form-control task-credential';
  fillTaskCredentialOptions(credentialSelect, task.credential_id);
  const credentialHint = hint();
  credentialHint.textContent = '选用凭据时按签到请求的方式带上它（Token / Cookie，或 OAuth 登录后的会话），下方请求头最后应用、可覆盖同名项。';
  body.appendChild(field('使用凭据', credentialSelect, credentialHint));

  // ---------- headers (the shared key-value editor) ----------
  const headersKey = taskHeadersKey(task);
  const headersGroup = document.createElement('div');
  headersGroup.className = 'form-group';
  const headersHeader = document.createElement('div');
  headersHeader.className = 'kv-header';
  const headersLabel = document.createElement('label');
  headersLabel.style.margin = '0';
  headersLabel.textContent = '自定义请求头 (可选)';
  const addHeader = document.createElement('button');
  addHeader.type = 'button';
  addHeader.className = 'btn btn-sm btn-primary-plain';
  addHeader.textContent = '+ 添加 Header';
  addHeader.addEventListener('click', () => addHeaderRow(headersKey));
  headersHeader.append(headersLabel, addHeader);
  const headersContainer = document.createElement('div');
  headersContainer.className = 'kv-editor';
  headersContainer.id = `${headersKey}-headers-container`;
  headersGroup.append(headersHeader, headersContainer);
  body.appendChild(headersGroup);

  // ---------- JSON body ----------
  const bodyInput = document.createElement('textarea');
  bodyInput.className = 'form-control task-body';
  bodyInput.rows = 5;
  bodyInput.spellcheck = false;
  bodyInput.placeholder = '{"key": "value"}';
  bodyInput.value = task.body || '';
  const bodyHint = hint();
  const formatBody = document.createElement('button');
  formatBody.type = 'button';
  formatBody.className = 'btn btn-sm';
  formatBody.textContent = '格式化';
  formatBody.addEventListener('click', () => {
    try {
      bodyInput.value = JSON.stringify(JSON.parse(bodyInput.value), null, 2);
      checkBody();
    } catch (e) {
      checkBody();
    }
  });
  const checkBody = () => {
    const text = bodyInput.value.trim();
    if (!text) {
      bodyHint.textContent = '留空则不发送请求体。会以 Content-Type: application/json 发送。';
      bodyHint.classList.remove('task-hint-error');
      return;
    }
    try {
      JSON.parse(text);
      bodyHint.textContent = 'JSON 格式正确。';
      bodyHint.classList.remove('task-hint-error');
    } catch (e) {
      bodyHint.textContent = `JSON 格式错误：${e.message}`;
      bodyHint.classList.add('task-hint-error');
    }
  };
  bodyInput.addEventListener('input', checkBody);
  const bodyHeader = document.createElement('div');
  bodyHeader.className = 'kv-header';
  const bodyLabel = document.createElement('label');
  bodyLabel.style.margin = '0';
  bodyLabel.textContent = 'JSON Body (可选)';
  bodyHeader.append(bodyLabel, formatBody);
  const bodyGroup = document.createElement('div');
  bodyGroup.className = 'form-group';
  bodyGroup.append(bodyHeader, bodyInput, bodyHint);
  body.appendChild(bodyGroup);

  // ---------- history ----------
  const logHistory = checkbox('task-log-history', '每次运行写入历史日志', task.log_history !== false);
  logHistory.label.title = '运行频繁的任务可关闭，以免挤占历史日志的保留条数；手动运行总会记录';
  body.appendChild(field('', logHistory.label));

  // ---------- Vs PoW ----------
  const pow = checkbox('task-pow-enabled', '请求前求解 Vs PoW', Boolean(task.pow_purpose) || task.powSwitch === true);
  pow.label.title = '部分 New-API 改版站点（如 vsllm.cc）要求请求附带工作量证明';
  const powPurposeInput = input('task-pow-purpose', 'text', task.pow_purpose);
  powPurposeInput.placeholder = '题目用途，如 checkin';
  powPurposeInput.spellcheck = false;
  powPurposeInput.setAttribute('list', 'pow-purpose-options');
  const powHint = hint();
  powHint.textContent = '开启后，每次运行前先请求 /api/pow/challenge?purpose=用途 并随请求发送解答。'
    + '须同时在「基本」页开启「求解 Vs PoW」；用途须与该接口在站点前端中的一致，否则会被拒绝。';
  const powDetails = document.createElement('div');
  powDetails.className = 'pow-purpose-row';
  powDetails.append(powPurposeInput, powHint);
  body.appendChild(field('', pow.label, powDetails));

  // ---------- state and run-now ----------
  const stateRow = document.createElement('div');
  stateRow.className = 'task-state';
  const stateText = document.createElement('span');
  stateText.className = 'task-state-text';
  const lastMessage = document.createElement('span');
  const runButton = document.createElement('button');
  runButton.type = 'button';
  runButton.className = 'btn btn-sm btn-success-plain';
  runButton.textContent = '立即运行';
  runButton.title = '按当前填写的内容（无需先保存）发送一次请求，结果写入历史日志';
  runButton.addEventListener('click', () => runTaskNow(task.id, runButton, lastMessage));
  stateRow.append(stateText, runButton);
  const messageRow = hint();
  messageRow.appendChild(lastMessage);
  body.append(stateRow, messageRow);

  const renderLastMessage = () => {
    const state = task.state || {};
    lastMessage.className = state.last_success ? 'ok' : 'fail';
    lastMessage.textContent = state.last_message ? `上次结果：${state.last_message}` : '';
  };

  // ---------- keep the header and the visible fields in step ----------
  const sync = () => {
    readTaskDraftFromDom();
    const isCron = scheduleSelect.value === 'cron';
    cronGroup.style.display = isCron ? '' : 'none';
    intervalGroup.style.display = isCron ? 'none' : '';
    bodyGroup.style.display = methodSelect.value === 'POST' ? '' : 'none';
    powDetails.style.display = pow.element.checked ? '' : 'none';
    tag.className = `cred-type-tag task-tag${enabledInput.checked ? '' : ' disabled'}`;
    tag.textContent = enabledInput.checked ? methodSelect.value : '停用';
    name.textContent = nameInput.value.trim() || '未命名任务';
    summary.textContent = `${describeTaskSchedule(task)} · ${describeTaskState(task)}`;
    stateText.textContent = describeTaskState(task);
  };
  [nameInput, cronInput, minInput, maxInput, urlInput].forEach(element => element.addEventListener('input', sync));
  [enabledInput, scheduleSelect, methodSelect, pow.element].forEach(element => element.addEventListener('change', sync));
  [scheduleSelect, cronInput, minInput, maxInput].forEach(element => {
    element.addEventListener(element === scheduleSelect ? 'change' : 'input', () => scheduleTaskPreview(card, task));
  });

  card.append(header, body);
  // Header rows need the container in the document to be found by id.
  queueMicrotask(() => {
    setHeaderRows(headersKey, task.headers);
    sync();
    checkBody();
    renderLastMessage();
    scheduleTaskPreview(card, task);
  });
  card.renderLastMessage = renderLastMessage;
  card.syncTask = sync;
  return card;
}

async function runTaskNow(taskId, button, output) {
  readCredentialDraftFromDom();
  readTaskDraftFromDom();
  const task = taskDraft.find(item => item.id === taskId);
  if (!task) return;
  const problem = validateTaskDraft(task);
  if (problem) {
    output.className = 'fail';
    output.textContent = problem;
    showToast(problem, 'warning');
    return;
  }
  const site = buildSitePayloadFromForm();
  if (task.url.startsWith('/') && !site.base_url) {
    showToast('URL 为相对路径时，请先在「基本」页填写 Base URL', 'warning');
    return;
  }
  button.disabled = true;
  output.className = '';
  output.textContent = '正在运行…';
  try {
    const data = await apiPostReportingErrors('/api/sites/tasks/run', { site, task_id: taskId });
    if (!data || data.status !== 'ok') {
      output.className = 'fail';
      output.textContent = data?.message || '运行失败';
      showToast(output.textContent, 'error');
      return;
    }
    const result = data.result || {};
    task.state = data.state && Object.keys(data.state).length
      ? data.state
      : { ...task.state, last_success: result.success, last_message: result.message };
    const card = document.querySelector(`#tasks-list .task-card[data-task-id="${CSS.escape(taskId)}"]`);
    card?.syncTask?.();
    card?.renderLastMessage?.();
    showToast(result.message || (result.success ? '运行成功' : '运行失败'), result.success ? 'success' : 'error', 6000);
  } catch (e) {
    output.className = 'fail';
    output.textContent = '运行请求失败';
  } finally {
    button.disabled = false;
  }
}

/**
 * Whether runs may rewrite this credential's value while the editor is open:
 * OAuth provider cookies rotate, and an OAuth login overwrites a Cookie
 * credential with the station cookie, a hand-added one included. Such a
 * value is left out of a save when untouched.
 */
function rewrittenByRuns(credential) {
  return OAUTH_TYPES.includes(credential.type) || credential.type === 'cookie';
}

/** Build a site payload from the editor, for actions that run before saving. */
function buildSitePayloadFromForm() {
  const previous = isEdit && editIndex >= 0 ? sites[editIndex] : null;
  return {
    id: previous ? previous.id : '',
    name: document.getElementById('site-name')?.value.trim() || '',
    type: document.getElementById('site-type')?.value || 'new-api',
    base_url: document.getElementById('site-url')?.value.trim() || '',
    proxy: document.getElementById('site-proxy')?.value.trim() || '',
    credentials: credentialDraft.map(credential => {
      const entry = {
        id: credential.id,
        type: credential.type,
        label: credential.label || ''
      };
      // Omitting the value means "unchanged"; storage restores the stored one.
      // Only cookies rewritten underneath us are eligible: OAuth provider
      // cookies, and the station Cookie an OAuth login writes back.
      const untouchedOauthCookie = rewrittenByRuns(credential)
        && credential.loadedValue
        && credential.value === credential.loadedValue;
      if (!untouchedOauthCookie) entry.value = credential.value || '';
      if (credential.type === 'token') entry.auto_bearer = credential.auto_bearer !== false;
      // Carry the stored session so the probe can reuse it instead of logging in.
      if (OAUTH_TYPES.includes(credential.type) && credential.session_cookie) {
        entry.session_cookie = credential.session_cookie;
      }
      return entry;
    }),
    checkin: readActionForm('checkin'),
    balance: readActionForm('balance'),
    tasks: readTasksForSave(),
    vs_pow: document.getElementById('site-vs-pow')?.checked === true,
    enabled: document.getElementById('site-enabled')?.checked === true
  };
}

// Site Form Actions
function openAddSiteModal() {
  isEdit = false;
  editIndex = -1;
  document.getElementById('site-modal-title').textContent = '新增中转站';
  document.getElementById('site-name').value = '';
  document.getElementById('site-type').value = 'new-api';
  document.getElementById('site-url').value = '';
  document.getElementById('site-proxy').value = '';
  document.getElementById('site-enabled').checked = true;
  document.getElementById('site-vs-pow').checked = false;
  credentialDraft = [];
  renderCredentials();
  taskDraft = [];
  renderTasks();
  fillActionForm('checkin', {});
  fillActionForm('balance', {});
  renderFrameworkHints();
  switchSiteTab('basic');
  openModal('site-modal');
}

function openEditSiteModal(index) {
  const site = sites[index];
  if (!site) return;
  if (site.locked) {
    showToast('该站点配置已加密，请先输入密钥解锁', 'warning');
    return;
  }
  isEdit = true;
  editIndex = index;
  document.getElementById('site-modal-title').textContent = '编辑中转站';
  document.getElementById('site-name').value = site.name || '';
  document.getElementById('site-type').value = site.type || 'new-api';
  document.getElementById('site-url').value = site.base_url || '';
  document.getElementById('site-proxy').value = site.proxy || '';
  document.getElementById('site-enabled').checked = site.enabled === true;
  document.getElementById('site-vs-pow').checked = site.vs_pow === true;

  credentialDraft = (Array.isArray(site.credentials) ? site.credentials : []).map(credential => ({
    ...credential,
    id: credential.id || nextCredentialId(),
    // Remember what was loaded. An OAuth cookie the user never touches is
    // omitted on save, so a rotation that happened while this editor was open
    // is not reverted by an unrelated edit.
    loadedValue: credential.value || ''
  }));
  renderCredentials();
  taskDraft = (Array.isArray(site.tasks) ? site.tasks : []).map(task => ({
    ...task,
    headers: Array.isArray(task.headers) ? task.headers.map(pair => ({ ...pair })) : [],
    state: task.state || {},
    expanded: false
  }));
  renderTasks();
  fillActionForm('checkin', site.checkin);
  fillActionForm('balance', site.balance);
  renderFrameworkHints();
  switchSiteTab('basic');
  openModal('site-modal');
}

async function submitSiteForm() {
  const name = document.getElementById('site-name').value.trim();
  const type = document.getElementById('site-type').value;
  const base_url = document.getElementById('site-url').value.trim();
  const proxy = document.getElementById('site-proxy').value.trim();
  const enabled = document.getElementById('site-enabled').checked;
  const vs_pow = document.getElementById('site-vs-pow').checked;

  if (!name || !base_url) {
    showToast('请填写站点名称与 Base URL', 'warning');
    switchSiteTab('basic');
    return;
  }

  readCredentialDraftFromDom();
  if (credentialDraft.length === 0) {
    showToast('请至少添加一个凭据', 'warning');
    switchSiteTab('credentials');
    return;
  }
  const blank = credentialDraft.find(credential => !credential.value);
  if (blank) {
    const label = CREDENTIAL_LABELS[blank.type] || '凭据';
    showToast(`凭据「${blank.label || label}」尚未填写内容`, 'warning');
    switchSiteTab('credentials');
    return;
  }

  const checkin = readActionForm('checkin');
  if (checkin.protocol === 'oauth' && !credentialDraft.some(c => OAUTH_TYPES.includes(c.type))) {
    showToast('签到协议为 OAuth，请先添加一个 OAuth 凭据', 'warning');
    switchSiteTab('checkin');
    return;
  }
  const scheduleProblem = validateCheckinSchedule(checkin.schedule);
  if (scheduleProblem) {
    showToast(scheduleProblem, 'warning');
    switchSiteTab('checkin');
    return;
  }

  const tasks = readTasksForSave();
  for (const task of taskDraft) {
    const problem = validateTaskDraft(task);
    if (problem) {
      showToast(`定时任务「${task.name || '未命名任务'}」：${problem}`, 'warning', 6000);
      switchSiteTab('tasks');
      const card = document.querySelector(`#tasks-list .task-card[data-task-id="${CSS.escape(task.id)}"]`);
      if (card?.classList.contains('collapsed')) card.querySelector('.cred-toggle')?.click();
      return;
    }
  }

  const previous = isEdit && editIndex >= 0 ? sites[editIndex] : null;
  const siteData = {
    id: previous ? previous.id : 'site_' + Date.now(),
    name,
    type,
    base_url,
    proxy,
    credentials: credentialDraft.map(credential => {
      const entry = {
        id: credential.id,
        type: credential.type,
        label: credential.label || ''
      };
      // Omitting the value means "unchanged"; storage restores the stored one.
      // Only cookies rewritten underneath us are eligible; see rewrittenByRuns.
      const untouchedOauthCookie = rewrittenByRuns(credential)
        && credential.loadedValue
        && credential.value === credential.loadedValue;
      if (!untouchedOauthCookie) entry.value = credential.value || '';
      if (credential.type === 'token') entry.auto_bearer = credential.auto_bearer !== false;
      return entry;
    }),
    checkin,
    balance: readActionForm('balance'),
    tasks,
    vs_pow,
    enabled
  };
  if (previous) {
    // Preserve state the dashboard never edits. updated_at tells storage
    // which station cookies a login wrote after this editor loaded.
    ['last_checkin_date', 'last_checkin_time', 'last_checkin_success', 'last_quota', 'updated_at'].forEach(key => {
      if (previous[key] !== undefined) siteData[key] = previous[key];
    });
  }

  if (isEdit && editIndex >= 0) {
    sites[editIndex] = siteData;
  } else {
    sites.push(siteData);
  }

  renderSitesTable();
  if (!(await saveSites())) {
    // Keep the editor open with its contents; put the table back as stored.
    await loadSites();
    return;
  }
  closeModal('site-modal');
  await loadSites();
}

function deleteSite(index) {
  const site = sites[index];
  const name = site ? site.name : '该中转站';
  showConfirm(`确定要删除“${name}”吗？`, async () => {
    sites.splice(index, 1);
    renderSitesTable();
    await saveSites();
  });
}

async function recheckInSite(index) {
  const site = sites[index];
  if (!site) return false;
  if (site.locked || isVaultLocked()) {
    showToast('配置已加密未解锁，请先输入密钥', 'warning');
    return false;
  }
  const siteId = getSiteId(site);

  const confirmed = await showConfirm(`确定要重新签到“${site.name}”吗？这会再次请求签到接口。`);
  if (!confirmed) return false;

  try {
    const data = await apiPost('/api/sites/recheckin', { site_id: siteId });
    const result = data?.result;
    if (result?.success) {
      showToast(`${site.name}: ${result.message || '重新签到成功'}`, 'success');
    } else {
      showToast(`${site.name}: ${result?.message || data?.message || '重新签到失败'}`, 'error');
    }
    await loadSites();
    await loadLogs();
  } catch (e) {
    showToast('重新签到请求失败', 'error');
  }
  return true;
}

async function testSingleSite(index) {
  const site = sites[index];
  if (!site) return;
  if (site.locked || isVaultLocked()) {
    showToast('配置已加密未解锁，请先输入密钥', 'warning');
    return;
  }
  try {
    const data = await apiPost('/api/sites/test', site);
    if (data && data.success) {
      showToast(`${site.name}: ${data.message} (余额: $${data.total_quota})`, 'success');
    } else {
      showToast(`${site.name}: ${data.message || '测试失败'}`, 'error');
    }
    await loadSites();
    loadLogs();
  } catch (e) {
    showToast('测试请求失败', 'error');
  }
}

async function runCheckInAll() {
  if (isVaultLocked()) {
    showToast('配置已加密未解锁，请先输入密钥', 'warning');
    return;
  }
  const btn = document.getElementById('btn-run-all');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '签到中...';
  }
  try {
    await apiPost('/api/checkin/run', {});
    showToast('一键打卡完成！', 'success');
    loadSites();
    loadLogs();
  } catch (e) {
    showToast('打卡请求异常', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '立即全部签到';
    }
  }
}

// Vault (AES-256-GCM Encryption) Actions
function applyVaultState(state) {
  if (state && typeof state === 'object') {
    vaultState = {
      enabled: state.enabled === true,
      unlocked: state.unlocked === true,
      locked: state.locked === true
    };
  }
  renderVaultUi();
}

function renderVaultUi() {
  const banner = document.getElementById('lock-banner');
  if (banner) banner.style.display = vaultState.locked ? 'flex' : 'none';

  const badge = document.getElementById('vault-badge');
  if (badge) {
    badge.style.display = vaultState.enabled ? 'inline-block' : 'none';
    badge.className = `badge ${vaultState.locked ? 'badge-warning' : 'badge-success'}`;
    badge.textContent = vaultState.locked ? '已加密 · 锁定' : '已加密 · 已解锁';
  }

  const toggle = document.getElementById('setting-vault-enabled');
  if (toggle) toggle.checked = vaultState.enabled;

  const controls = document.getElementById('vault-controls');
  if (controls) controls.style.display = vaultState.enabled ? 'flex' : 'none';

  const hint = document.getElementById('vault-state-hint');
  if (hint) {
    if (!vaultState.enabled) {
      hint.textContent = '加密凭据、请求头与代理。启用后生成一个仅显示一次的密钥。';
    } else if (vaultState.locked) {
      hint.textContent = '已锁定：敏感字段不可读，定时签到会跳过所有站点。';
    } else {
      hint.textContent = '已解锁：插件重载后需重新解锁。';
    }
  }

  renderKeySlots();
}

async function loadVaultState() {
  try {
    const data = await apiGet('/api/vault');
    applyVaultState(data);
  } catch (e) {
    console.error('loadVaultState error:', e);
  }
  await loadKeySlots();
}

// Key Slot Actions
async function loadKeySlots() {
  try {
    const data = await apiGet('/api/vault/slots');
    keySlots = Array.isArray(data?.slots) ? data.slots : [];
  } catch (e) {
    console.error('loadKeySlots error:', e);
    keySlots = [];
  }
  renderKeySlots();
}

function renderKeySlots() {
  const block = document.getElementById('slots-block');
  if (block) block.style.display = vaultState.enabled ? 'block' : 'none';

  const list = document.getElementById('slots-list');
  if (!list) return;
  list.replaceChildren();
  if (keySlots.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-text';
    empty.textContent = '暂无槽位';
    list.appendChild(empty);
    return;
  }

  keySlots.forEach(slot => {
    const card = document.createElement('div');
    card.className = 'cred-card';

    const header = document.createElement('div');
    header.className = 'cred-card-header';
    const title = document.createElement('div');
    title.className = 'cred-title';
    const tag = document.createElement('span');
    tag.className = `cred-type-tag${slot.type === 'webauthn_prf' ? ' oauth' : ''}`;
    tag.textContent = SLOT_TYPE_LABELS[slot.type] || slot.type;
    const name = document.createElement('span');
    name.textContent = slot.label || '未命名';
    title.append(tag, name);
    header.appendChild(title);

    if (slot.removable) {
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'btn-icon-danger';
      remove.title = '删除此槽位';
      remove.textContent = '×';
      remove.addEventListener('click', () => removeKeySlot(slot));
      header.appendChild(remove);
    } else {
      const badge = document.createElement('span');
      badge.className = 'badge badge-info';
      badge.textContent = '恢复槽位';
      badge.title = '不可删除，确保丢失通行密钥后仍能解锁';
      header.appendChild(badge);
    }
    card.appendChild(header);

    const meta = document.createElement('div');
    meta.className = 'cred-session-state';
    const bits = [];
    if (slot.rp_id) bits.push(`域名 ${slot.rp_id}`);
    if (slot.created_at) bits.push(`创建于 ${slot.created_at}`);
    bits.push(slot.last_used_at ? `最近使用 ${slot.last_used_at}` : '尚未使用');
    meta.textContent = bits.join(' · ');
    card.appendChild(meta);

    list.appendChild(card);
  });
}

function removeKeySlot(slot) {
  const name = slot.label || '该槽位';
  showConfirm(`确定要删除「${name}」吗？该设备将无法再解锁配置。`, async () => {
    try {
      const data = await apiPost('/api/vault/slots/remove', { slot_id: slot.id });
      if (!data || data.status !== 'ok') {
        showToast(data?.message || '删除槽位失败', 'error');
        return;
      }
      applyVaultState(data.vault);
      showToast(data.message || '槽位已删除', 'success');
      await loadKeySlots();
    } catch (e) {
      showToast('删除槽位请求失败', 'error');
    }
  });
}

function getPasskeyPageUrl() {
  // This iframe has an opaque origin, so location.origin reads "null" and
  // parent.location is unreachable. The document can still read its own
  // protocol and host, which are the dashboard's — that is enough to build an
  // absolute URL the user can paste into a new tab.
  const path = `/api/v1/plugins/extensions/${PLUGIN_ID}/passkey`;
  const { protocol, host } = window.location;
  if (host && protocol && protocol !== 'null:') {
    return `${protocol}//${host}${path}`;
  }
  return path;
}

function openPasskeyModal() {
  const box = document.getElementById('passkey-url');
  if (box) box.textContent = getPasskeyPageUrl();
  clearCopyStatus('passkey-url', 'passkey-url-status');
  openModal('passkey-modal');
  startVaultWatch();
}

function isModalOpen(id) {
  return document.getElementById(id)?.classList.contains('active') === true;
}

function anyVaultDialogOpen() {
  return VAULT_DIALOG_IDS.some(isModalOpen);
}

/**
 * Watch for an unlock performed outside this page, while a vault dialog is open.
 *
 * The other tab cannot tell this one directly: the iframe has an opaque origin,
 * which rules out BroadcastChannel, localStorage and cross-tab postMessage
 * alike. Polling the vault state is the only channel left, and it is only worth
 * running while a dialog that asks for the key is still on screen.
 *
 * Idempotent: the unlock dialog opens the hand-off dialog on top of itself, and
 * the second call must not restart the watch or recapture `lockedAtOpen` — by
 * then the vault may already be unlocked, which would flip the watch into its
 * "nothing to wait for" mode and never close either dialog.
 */
function startVaultWatch() {
  if (vaultWatch) return;
  const lockedAtOpen = isVaultLocked();
  vaultWatch = {
    lockedAtOpen,
    // Locked: poll, for the case where both tabs are visible side by side and
    // no visibility change ever fires. Coming back to a backgrounded tab is
    // already handled globally, so this deliberately adds no second listener.
    timer: lockedAtOpen ? window.setInterval(syncVaultProgress, VAULT_POLL_MS) : null,
    // Unlocked: an unlocked vault is the precondition for registering a device,
    // so the only thing the other tab can change is the slot list — worth
    // re-reading once, on return, but not worth polling for.
    onVisible: lockedAtOpen ? null : () => {
      if (!document.hidden) loadKeySlots();
    }
  };
  if (vaultWatch.onVisible) {
    document.addEventListener('visibilitychange', vaultWatch.onVisible);
  }
}

function stopVaultWatch() {
  if (!vaultWatch) return;
  if (vaultWatch.timer) window.clearInterval(vaultWatch.timer);
  if (vaultWatch.onVisible) {
    document.removeEventListener('visibilitychange', vaultWatch.onVisible);
  }
  vaultWatch = null;
}

/** Poll for an unlock performed in the other tab, and adopt it when it lands. */
async function syncVaultProgress() {
  if (!vaultWatch?.lockedAtOpen) return;

  let unlocked = false;
  try {
    const data = await apiGet('/api/vault');
    unlocked = data?.locked !== true;
  } catch (e) {
    // A dropped request is not a state change. Stay quiet and keep watching:
    // the user is mid-unlock in another tab and a toast here helps nobody.
    return;
  }
  // The dialog may have been closed by hand while the request was in flight.
  if (!vaultWatch || !unlocked) return;
  await refreshVaultState({ quiet: true });
}

/**
 * Close every dialog that existed only to get the vault unlocked.
 *
 * Both of them qualify, and both can be on screen at once: the unlock dialog
 * offers a button that opens the hand-off dialog over it. Closing only the top
 * one leaves the other sitting there asking for a key that is no longer needed.
 *
 * Returns how many were actually closed, so the caller can decide what to say
 * rather than having a message imposed here — an unlock performed in this tab
 * and one performed in another warrant different wording.
 */
function closeVaultDialogs() {
  const open = VAULT_DIALOG_IDS.filter(isModalOpen);
  open.forEach(closeModal);
  stopVaultWatch();
  return open.length;
}

async function copyPasskeyUrl() {
  await runCopy({
    boxId: 'passkey-url',
    statusId: 'passkey-url-status',
    successText: '地址已复制，请在新标签页中打开',
    failureTitle: '复制失败，请手动复制下面的地址',
    noun: '地址'
  });
}

/**
 * Re-read the vault state without reloading the page.
 *
 * Unlocking and registering happen in a separate tab, so this dashboard has no
 * way to learn about it. Rather than making the user reload the whole AstrBot
 * page, pull the state and repaint everything that depends on it.
 */
async function refreshVaultState(options = {}) {
  const { quiet = false } = options;
  try {
    const wasLocked = isVaultLocked();
    await loadVaultState();
    await loadSites();
    const locked = isVaultLocked();
    // Whichever path noticed the unlock — a dialog's own poll, the manual
    // button, or returning to the tab — every dialog that was asking for the key
    // has nothing left to ask for once it has been supplied elsewhere.
    let dismissed = 0;
    if (wasLocked && !locked) {
      dismissed = closeVaultDialogs();
      if (dismissed) showToast('已在其他标签页解锁，配置已同步', 'success');
    }
    if (!quiet && !dismissed) {
      showToast(locked ? '仍处于锁定状态' : '已同步：配置已解锁', locked ? 'warning' : 'success');
    }
    return true;
  } catch (e) {
    console.error('refreshVaultState error:', e);
    if (!quiet) showToast('刷新状态失败', 'error');
    return false;
  }
}

/**
 * Copy a one-shot value and report the outcome inline, next to the value.
 *
 * A corner toast is the wrong place for either outcome here: the vault key is
 * shown exactly once, so a user who misses a failed copy — or who treats a
 * successful copy as "saved" and closes the dialog before pasting anywhere —
 * has to reset the vault. Both messages therefore land directly above the
 * value and stay there until the dialog is reopened.
 */
async function runCopy({ boxId, statusId, successText, successNotice, failureTitle, noun }) {
  const box = document.getElementById(boxId);
  const value = box?.textContent || '';
  if (!value) return false;

  const copied = await copyText(value);
  if (copied) {
    if (box) box.classList.remove('copy-failed');
    if (successNotice) {
      renderCopyStatus(statusId, 'notice', '✓', successNotice.title, successNotice.detail);
    } else {
      clearCopyStatus(boxId, statusId);
    }
    showToast(successText, 'success');
    return true;
  }

  // Select the text so the only remaining step is one keystroke.
  const selected = selectElementText(box);
  if (box) box.classList.add('copy-failed');
  renderCopyStatus(
    statusId,
    'error',
    '!',
    failureTitle,
    selected
      ? `${noun}已选中，按 Ctrl/⌘+C 复制。`
      : `请选中下面的${noun}并按 Ctrl/⌘+C 复制。`
  );
  return false;
}

/** Render an inline copy status block above a value box. */
function renderCopyStatus(statusId, variant, iconText, title, detail) {
  const status = document.getElementById(statusId);
  if (!status) return;
  status.replaceChildren();
  status.className = `copy-status copy-status-${variant}`;

  const icon = document.createElement('span');
  icon.className = 'copy-status-icon';
  icon.textContent = iconText;

  const text = document.createElement('div');
  const heading = document.createElement('strong');
  heading.textContent = title;
  const body = document.createElement('span');
  body.textContent = detail;
  text.append(heading, body);

  status.append(icon, text);
  status.style.display = 'flex';
  status.scrollIntoView({ block: 'nearest' });
}

/** Reset the copy status state for one value box. */
function clearCopyStatus(boxId, statusId) {
  const box = document.getElementById(boxId);
  const status = document.getElementById(statusId);
  if (box) box.classList.remove('copy-failed');
  if (status) {
    status.className = 'copy-status';
    status.style.display = 'none';
    status.replaceChildren();
  }
}

/**
 * Select an element's text so the user only needs to press Ctrl+C.
 *
 * Returns whether the selection took, so the failure message can tell the
 * truth instead of promising a selection that never happened. The check uses
 * rangeCount/isCollapsed rather than the selection's string value: after the
 * copy fallback moves focus, the stringified selection can lag by a frame and
 * would make a successful selection look like a failure.
 */
function selectElementText(element) {
  if (!element) return false;
  try {
    const range = document.createRange();
    range.selectNodeContents(element);
    const selection = document.getSelection();
    if (!selection) return false;
    selection.removeAllRanges();
    selection.addRange(range);
    return selection.rangeCount > 0 && !selection.isCollapsed;
  } catch (e) {
    return false;
  }
}

/**
 * Copy text to the clipboard, falling back to the legacy command.
 *
 * navigator.clipboard is unusable in this page: the dashboard sandboxes plugin
 * iframes without allow-same-origin, giving them an opaque origin that the
 * clipboard-write permissions policy (default allowlist "self") can never
 * match, so writeText always rejects with NotAllowedError. execCommand is
 * governed by user-gesture rules instead and still works, so it is the one
 * that actually succeeds here.
 */
async function copyText(text) {
  const value = String(text || '');
  if (!value) return false;

  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (e) {
      // Expected inside the sandbox; fall through to execCommand.
    }
  }

  let textarea = null;
  try {
    textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', '');
    // Keep it off-screen without using display:none, which would make it
    // unselectable and defeat the copy.
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.width = '1px';
    textarea.style.height = '1px';
    textarea.style.padding = '0';
    textarea.style.border = 'none';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);

    const selection = document.getSelection();
    const previousRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;

    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, value.length);
    const copied = document.execCommand('copy');

    // Leave the selection in a clean state. Without this it still points into
    // the textarea we are about to remove, and a later selectElementText()
    // would silently produce an empty selection.
    if (selection) {
      selection.removeAllRanges();
      if (previousRange) selection.addRange(previousRange);
    }
    textarea.blur();
    return copied;
  } catch (e) {
    return false;
  } finally {
    if (textarea) textarea.remove();
  }
}

function toggleVaultEncryption(input) {
  const wantsEnabled = input.checked;
  // The switch only reflects server state; revert it until the call succeeds.
  input.checked = vaultState.enabled;
  if (wantsEnabled === vaultState.enabled) return;
  if (wantsEnabled) {
    showConfirm(
      '启用后将使用 AES-256-GCM 加密凭据、自定义请求头与代理地址。密钥只显示一次，丢失后只能重置。是否继续？',
      enableVault
    );
  } else {
    showConfirm('关闭加密会把所有敏感字段还原为明文保存。是否继续？', disableVault);
  }
}

async function enableVault() {
  try {
    const data = await apiPost('/api/vault/enable', {});
    if (!data || data.status !== 'ok' || !data.key) {
      showToast(data?.message || '启用加密失败', 'error');
      await loadVaultState();
      return;
    }
    applyVaultState(data.vault);
    await loadKeySlots();
    const keyBox = document.getElementById('vault-key-text');
    if (keyBox) keyBox.textContent = data.key;
    clearCopyStatus('vault-key-text', 'vault-key-status');
    openModal('vault-key-modal');
    await loadSites();
  } catch (e) {
    showToast('启用加密请求失败', 'error');
  }
}

async function disableVault() {
  try {
    const data = await apiPost('/api/vault/disable', {});
    if (!data || data.status !== 'ok') {
      showToast(data?.message || '关闭加密失败', 'error');
      await loadVaultState();
      return;
    }
    applyVaultState(data.vault);
    await loadKeySlots();
    showToast(data.message || '加密已关闭', 'success');
    await loadSites();
  } catch (e) {
    showToast('关闭加密请求失败', 'error');
  }
}

async function copyVaultKey() {
  await runCopy({
    boxId: 'vault-key-text',
    statusId: 'vault-key-status',
    successText: '密钥已复制到剪贴板',
    // Copying is not saving: the clipboard can be overwritten at any moment,
    // and this key is never shown again.
    successNotice: {
      title: '先粘贴保存，再关闭',
      detail: '密钥不会再次显示，剪贴板随时可能被覆盖。'
    },
    failureTitle: '复制失败，请手动复制',
    noun: '密钥'
  });
}

function openUnlockModal() {
  const input = document.getElementById('vault-unlock-key');
  if (input) input.value = '';
  openModal('vault-unlock-modal');
  if (input) input.focus();
  // The user may unlock on the standalone page instead of typing here, so watch
  // for that from the moment this opens rather than only from the hand-off
  // dialog — this one is what stays on screen underneath it.
  startVaultWatch();
}

async function submitUnlockVault() {
  const input = document.getElementById('vault-unlock-key');
  const key = input ? input.value.trim() : '';
  if (!key) {
    showToast('请粘贴密钥', 'warning');
    return;
  }
  try {
    const data = await apiPost('/api/vault/unlock', { key });
    if (!data || data.status !== 'ok') {
      showToast(data?.message || '解锁失败', 'error');
      return;
    }
    applyVaultState(data.vault);
    if (input) input.value = '';
    // The hand-off dialog may be stacked over this one, offering an unlock that
    // has just happened here instead.
    closeVaultDialogs();
    showToast('解锁成功', 'success');
    await loadSites();
  } catch (e) {
    showToast('解锁请求失败', 'error');
  }
}

function lockVault() {
  showConfirm('锁定后需要重新输入密钥才能查看和使用敏感配置，定时签到将暂时跳过所有站点。是否继续？', async () => {
    try {
      const data = await apiPost('/api/vault/lock', {});
      applyVaultState(data?.vault);
      showToast(data?.message || '已锁定', 'success');
      await loadSites();
    } catch (e) {
      showToast('锁定请求失败', 'error');
    }
  });
}

function openResetVaultModal() {
  const input = document.getElementById('vault-reset-confirm');
  if (input) input.value = '';
  openModal('vault-reset-modal');
  if (input) input.focus();
}

async function submitResetVault() {
  const input = document.getElementById('vault-reset-confirm');
  if ((input ? input.value.trim().toUpperCase() : '') !== 'RESET') {
    showToast('请输入 RESET 以确认重置', 'warning');
    return;
  }
  const confirmed = await showConfirm('最后确认：所有站点的凭据、自定义请求头与代理地址都会被清空，且无法恢复。');
  if (!confirmed) return;
  try {
    const data = await apiPost('/api/vault/reset', { confirm: 'reset' });
    if (!data || data.status !== 'ok') {
      showToast(data?.message || '重置失败', 'error');
      return;
    }
    applyVaultState(data.vault);
    await loadKeySlots();
    closeModal('vault-reset-modal');
    showToast(data.message || '已重置加密', 'success');
    await loadSites();
  } catch (e) {
    showToast('重置请求失败', 'error');
  }
}

// Global Settings Actions
async function loadSettings() {
  try {
    const data = await apiGet('/api/settings');
    if (data && typeof data === 'object') {
      settings = { ...settings, ...data };
      renderSettingsForm();
      applyVaultState(data.vault);
      const badge = document.getElementById('target-time-badge');
      if (badge && data.today_target_time) {
        badge.textContent = data.today_target_time;
      }
    }
  } catch (e) {
    console.error('loadSettings error:', e);
  }
}

function renderSettingsForm() {
  document.getElementById('setting-enabled').checked = settings.enabled === true;
  const isRandom = settings.random_enabled === true;
  document.getElementById('setting-random').checked = isRandom;
  document.getElementById('setting-start-time').value = settings.start_time;
  document.getElementById('setting-end-time').value = settings.end_time;
  document.getElementById('setting-fixed-time').value = settings.checkin_time;
  document.getElementById('setting-http-ssl-verify').checked = settings.http_ssl_verify === true;
  document.getElementById('setting-http-timeout').value = settings.http_timeout_seconds;
  const maxRecordsInput = document.getElementById('setting-max-history-records');
  if (maxRecordsInput) {
    maxRecordsInput.value = settings.max_history_records ?? 0;
  }
  const lockNotifyInput = document.getElementById('setting-lock-notify-session');
  if (lockNotifyInput) {
    lockNotifyInput.value = settings.lock_notify_session ?? '';
  }
  const reportLevelSelect = document.getElementById('setting-report-level');
  if (reportLevelSelect) {
    reportLevelSelect.value = settings.report_level || 'all';
  }
  document.getElementById('setting-tls-mldsa').checked = settings.http_tls_mldsa === true;
  document.getElementById('setting-acw-solve').checked = settings.acw_sc_v2_auto_solve !== false;
  renderCloudflareBrowserFields();
  renderImpersonateOptions();
  renderMldsaHint();
  renderCurlCffiStatus();
  toggleRandomMode();
  renderVaultUi();
}

// What the ML-DSA switch does under the fingerprint picked in the form.
function renderMldsaHint() {
  const hint = document.getElementById('setting-mldsa-hint');
  if (!hint) return;
  const fingerprint = document.getElementById('setting-http-impersonate')?.value || settings.http_impersonate || '';
  hint.textContent = mldsaSupportNote(fingerprint);
}

function renderImpersonateOptions() {
  const select = document.getElementById('setting-http-impersonate');
  if (!select) return;

  const values = Array.isArray(settings.http_impersonate_options)
    ? settings.http_impersonate_options.map(normalizeImpersonateValue).filter(Boolean)
    : [];
  const normalizedCurrent = normalizeImpersonateValue(settings.http_impersonate);
  const options = [...new Set(values)];

  select.replaceChildren();
  if (options.length === 0) {
    const emptyOption = document.createElement('option');
    emptyOption.value = '';
    emptyOption.textContent = '当前版本未提供可用指纹';
    emptyOption.disabled = true;
    emptyOption.selected = true;
    select.appendChild(emptyOption);
    return;
  }

  options.forEach(value => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });
  select.value = options.includes(normalizedCurrent) ? normalizedCurrent : options[0];
}

// Which curl_cffi runs, and whether a reinstall is waiting for a restart.
function renderCurlCffiStatus() {
  const status = document.getElementById('curl-cffi-status');
  const button = document.getElementById('btn-reinstall-curl-cffi');
  if (!status || !button) return;
  const info = settings.curl_cffi || {};
  const loaded = info.loaded_version || '未知版本';
  const installed = info.installed_version || '';
  const options = Array.isArray(settings.http_impersonate_options) ? settings.http_impersonate_options : [];
  button.disabled = info.reinstalling === true;
  if (info.reinstalling) {
    status.textContent = '正在重新安装 curl_cffi…';
  } else if (installed && installed !== loaded) {
    status.textContent = `已安装 curl_cffi ${installed}，当前运行的仍是 ${loaded}，重启 AstrBot 后生效。`;
  } else if (!options.includes('chrome150')) {
    status.textContent = `当前 curl_cffi ${loaded} 不含 chrome150 指纹（插件要求 ${info.requirement || 'curl_cffi>=0.16.2'}），建议重新安装。`;
  } else {
    status.textContent = `当前 curl_cffi ${loaded}。`;
  }
}

function reinstallCurlCffi() {
  showConfirm(
    '将通过 AstrBot 的 pip（沿用其镜像源与安装参数）重新安装 curl_cffi，可能需要一两分钟。安装完成后须重启 AstrBot 才会生效，确定继续？',
    async () => {
      const button = document.getElementById('btn-reinstall-curl-cffi');
      const status = document.getElementById('curl-cffi-status');
      button.disabled = true;
      status.textContent = '正在重新安装 curl_cffi，请勿关闭本页…';
      try {
        const data = await apiPost('/api/dependencies/curl_cffi/reinstall', {});
        if (!data || data.status !== 'ok') {
          status.textContent = data?.message || '重新安装 curl_cffi 失败';
          showToast(status.textContent, 'error', 8000);
          return;
        }
        settings.curl_cffi = data.curl_cffi || settings.curl_cffi;
        renderCurlCffiStatus();
        showToast(data.message || 'curl_cffi 已重新安装，重启 AstrBot 后生效', 'success', 8000);
      } catch (e) {
        status.textContent = '重新安装请求失败';
        showToast(status.textContent, 'error');
      } finally {
        button.disabled = false;
      }
    }
  );
}

function renderCloudflareBrowserFields() {
  document.getElementById('setting-cf-browser').checked = settings.cf_browser_fallback !== false;
  document.getElementById('setting-cf-browser-headless').checked = settings.cf_browser_headless !== false;
  renderBrowserChannelOptions(settings.cf_browser_channel || 'auto');
  document.getElementById('setting-cf-browser-timeout').value = settings.cf_browser_timeout_seconds ?? 60;
  document.getElementById('cf-browser-check-result').textContent = '';
  renderBrowserInstallHint();
  renderPlaywrightSetup();
  toggleCloudflareBrowserFields();
  const info = settings.playwright || {};
  if (info.installing || info.chromium?.downloading) watchPlaywrightSetup();
}

const BROWSER_CHANNEL_NAMES = { chrome: 'Chrome', msedge: 'Edge', chromium: 'Chromium' };

// The browser choices are the browsers the server found on its machine, in the
// order "auto" tries them. A saved choice no longer found stays selectable,
// marked as such, rather than being switched to another behind the user's back.
function renderBrowserChannelOptions(selected) {
  const select = document.getElementById('setting-cf-browser-channel');
  const browsers = Array.isArray(settings.playwright?.browsers) ? settings.playwright.browsers : [];
  const names = browsers.map(b => b.name);
  const option = (value, text, title = '') => {
    const element = document.createElement('option');
    element.value = value;
    element.textContent = text;
    if (title) element.title = title;
    return element;
  };

  let autoText = '自动（未检测到可用的浏览器）';
  if (names.length === 1) autoText = `自动（${names[0]}）`;
  else if (names.length > 1) autoText = `自动（依次尝试 ${names.join('、')}，使用第一个能启动的）`;
  select.replaceChildren(option('auto', autoText));
  browsers.forEach(b => {
    const version = b.version ? ` ${b.version}` : '';
    const origin = b.channel === 'chromium' ? '（Playwright 下载）' : '';
    select.appendChild(option(b.channel, `${b.name}${version}${origin}`, b.path || ''));
  });
  if (selected !== 'auto' && !browsers.some(b => b.channel === selected) && BROWSER_CHANNEL_NAMES[selected]) {
    select.appendChild(option(selected, `${BROWSER_CHANNEL_NAMES[selected]}（未检测到）`));
  }
  select.value = selected;
  if (select.value !== selected) select.value = 'auto';

  document.getElementById('cf-browser-channel-hint').textContent = names.length
    ? '列出的是在运行 AstrBot 的机器上检测到的浏览器（Chrome / Edge 按 Playwright 查找的安装位置检测，不启动浏览器）。可用下方「检测浏览器」确认能否启动。'
    : '未在运行 AstrBot 的机器上检测到 Chrome、Edge 或 Playwright 的 Chromium：请按上方说明下载 Chromium。';
}

function renderBrowserInstallHint() {
  document.getElementById('cf-browser-install-hint').textContent = settings.cf_browser_installed
    ? ''
    : '当前未安装 Playwright，此项暂不生效：开启后可在下方「浏览器组件」中一键安装。';
}

// Playwright, and the Chromium it drives, as the server last reported them.
function renderPlaywrightSetup() {
  const info = settings.playwright || {};
  const chromium = info.chromium || {};
  const commands = info.commands || {};
  const loaded = info.loaded === true;
  const installed = info.installed_version || '';

  const installButton = document.getElementById('btn-install-playwright');
  const status = document.getElementById('playwright-status');
  installButton.style.display = loaded ? 'none' : '';
  installButton.disabled = info.installing === true;
  if (info.installing) {
    status.textContent = '正在安装 Playwright，请勿关闭本页…';
  } else if (loaded) {
    status.textContent = `Playwright ${installed} 已就绪。`;
  } else if (installed && info.import_error) {
    status.textContent = `已安装 Playwright ${installed}，但当前进程无法加载（${info.import_error}），请重启 AstrBot。`;
  } else if (installed) {
    status.textContent = `已安装 Playwright ${installed}，重启 AstrBot 后生效。`;
  } else {
    status.textContent = `未安装 Playwright（插件要求 ${info.requirement || 'playwright>=1.49.0'}，约 40 MB）。安装后无需重启即可使用。`;
  }
  const pipGuide = document.getElementById('playwright-pip-guide');
  pipGuide.style.display = !loaded && !installed && commands.pip ? '' : 'none';
  document.getElementById('playwright-pip-command').textContent = commands.pip || '';

  // Chromium is downloaded by Playwright's own installer, so only once it runs.
  document.getElementById('chromium-setup').style.display = loaded ? '' : 'none';
  const downloaded = chromium.downloaded === true;
  const version = chromium.version ? ` ${chromium.version}` : '';
  const systemBrowsers = (Array.isArray(info.browsers) ? info.browsers : [])
    .filter(b => b.channel !== 'chromium')
    .map(b => b.name);
  const downloadButton = document.getElementById('btn-download-chromium');
  const chromiumStatus = document.getElementById('chromium-status');
  downloadButton.style.display = downloaded ? 'none' : '';
  downloadButton.disabled = chromium.downloading === true;
  if (chromium.downloading) {
    chromiumStatus.textContent = chromium.progress || '正在下载 Chromium，请稍候…';
  } else if (downloaded) {
    chromiumStatus.textContent = `已下载 Playwright 的 Chromium${version}。`;
  } else if (systemBrowsers.length) {
    chromiumStatus.textContent = `未下载 Playwright 的 Chromium${version}。已检测到 ${systemBrowsers.join('、')}，可直接使用，无需下载。`;
  } else {
    chromiumStatus.textContent = `未下载 Playwright 的 Chromium${version}，也未检测到 Chrome / Edge，请下载（约 200 MB）。`;
  }
  const command = commands.browser || '';
  document.getElementById('chromium-guide').style.display = !downloaded && !systemBrowsers.length && command ? '' : 'none';
  document.getElementById('chromium-command').textContent = command;
  document.getElementById('chromium-guide-note').textContent = command.includes('--with-deps')
    ? '--with-deps 会一并用系统包管理器安装 Chromium 所需的系统库，需要 root 权限（一键下载仅在 AstrBot 以 root 运行时附带此项）。下载经由 AstrBot 进程的 HTTPS_PROXY 代理。'
    : '下载经由 AstrBot 进程的 HTTPS_PROXY 代理。';
  // A download may have just added Chromium; keep what the form has chosen.
  renderBrowserChannelOptions(document.getElementById('setting-cf-browser-channel').value || 'auto');
}

async function copyCommand(id) {
  const box = document.getElementById(id);
  if (await copyText(box?.textContent || '')) {
    showToast('命令已复制', 'success');
  } else {
    selectElementText(box);
    showToast('复制失败，命令已选中，请按 Ctrl+C 复制', 'error');
  }
}

// Poll Playwright's state while an install or download runs, so its progress
// shows — including one started before this page was opened.
let playwrightWatchTimer = null;
let playwrightSetupsRunning = 0;

function watchPlaywrightSetup() {
  if (playwrightWatchTimer) return;
  playwrightWatchTimer = setInterval(async () => {
    const info = await refreshPlaywrightStatus();
    const busy = info && (info.installing || info.chromium?.downloading);
    if (!busy && playwrightSetupsRunning === 0) {
      clearInterval(playwrightWatchTimer);
      playwrightWatchTimer = null;
    }
  }, 1500);
}

async function refreshPlaywrightStatus() {
  try {
    const data = await apiGet('/api/dependencies/playwright');
    if (data?.playwright) {
      settings.playwright = data.playwright;
      settings.cf_browser_installed = data.playwright.loaded === true;
      renderBrowserInstallHint();
      renderPlaywrightSetup();
      return data.playwright;
    }
  } catch (e) {
    // Keep what is shown; the next poll or the final response catches up.
  }
  return null;
}

async function runPlaywrightSetup({ endpoint, buttonId, statusId, pendingText, failureText }) {
  const button = document.getElementById(buttonId);
  const status = document.getElementById(statusId);
  button.disabled = true;
  status.textContent = pendingText;
  playwrightSetupsRunning += 1;
  watchPlaywrightSetup();
  let data = null;
  try {
    data = await apiPostReportingErrors(endpoint, {});
  } catch (e) {
    data = { status: 'error', message: `${failureText}（详情见 AstrBot 日志）` };
  } finally {
    playwrightSetupsRunning -= 1;
  }
  if (data?.status === 'ok' && data.playwright) {
    settings.playwright = data.playwright;
    settings.cf_browser_installed = data.playwright.loaded === true;
    renderBrowserInstallHint();
    renderPlaywrightSetup();
    showToast(data.message || '已完成', 'success', 8000);
    return;
  }
  await refreshPlaywrightStatus();
  button.disabled = false;
  status.textContent = data?.message || failureText;
  showToast(status.textContent, 'error', 10000);
}

function installPlaywright() {
  showConfirm(
    '将通过 AstrBot 的 pip（沿用其镜像源与安装参数）安装 Playwright，可能需要一两分钟，确定继续？',
    () => runPlaywrightSetup({
      endpoint: '/api/dependencies/playwright/install',
      buttonId: 'btn-install-playwright',
      statusId: 'playwright-status',
      pendingText: '正在安装 Playwright，请勿关闭本页…',
      failureText: '安装 Playwright 失败'
    })
  );
}

function downloadChromium() {
  showConfirm(
    '将在运行 AstrBot 的机器上下载 Playwright 所用的 Chromium（约 200 MB），视网络情况可能需要数分钟，确定继续？',
    () => runPlaywrightSetup({
      endpoint: '/api/dependencies/playwright/chromium',
      buttonId: 'btn-download-chromium',
      statusId: 'chromium-status',
      pendingText: '正在下载 Chromium，请勿关闭本页…',
      failureText: '下载 Chromium 失败'
    })
  );
}

function toggleCloudflareBrowserFields() {
  const enabled = document.getElementById('setting-cf-browser').checked;
  document.getElementById('cf-browser-fields').style.display = enabled ? 'block' : 'none';
}

function readCloudflareBrowserForm() {
  const timeoutElement = document.getElementById('setting-cf-browser-timeout');
  const timeout = Number(timeoutElement.value);
  const cf_browser_timeout_seconds = Number.isFinite(timeout) ? Math.min(300, Math.max(15, Math.round(timeout))) : 60;
  timeoutElement.value = String(cf_browser_timeout_seconds);
  return {
    cf_browser_fallback: document.getElementById('setting-cf-browser').checked,
    cf_browser_headless: document.getElementById('setting-cf-browser-headless').checked,
    cf_browser_channel: document.getElementById('setting-cf-browser-channel').value || 'auto',
    cf_browser_timeout_seconds
  };
}

async function checkCloudflareBrowser() {
  const button = document.getElementById('btn-check-browser');
  const result = document.getElementById('cf-browser-check-result');
  button.disabled = true;
  result.textContent = '正在启动浏览器…';
  try {
    // The form as it stands, so a channel can be tried before it is saved.
    const data = await apiPost('/api/cloudflare/browser/check', readCloudflareBrowserForm());
    if (!data || data.status !== 'ok') {
      result.textContent = data?.message || '浏览器检测失败';
      return;
    }
    result.textContent = data.message || `已启动 ${data.browser}`;
  } catch (e) {
    result.textContent = '浏览器检测请求失败';
  } finally {
    button.disabled = false;
  }
}

function toggleRandomMode() {
  const isRandom = document.getElementById('setting-random').checked;
  document.getElementById('random-time-fields').style.display = isRandom ? 'block' : 'none';
  document.getElementById('fixed-time-field').style.display = isRandom ? 'none' : 'block';
}

function openSettingsModal() {
  switchSettingsTab('schedule');
  openModal('settings-modal');
  loadSettings();
}

async function saveSettings() {
  const enabled = document.getElementById('setting-enabled').checked;
  const random_enabled = document.getElementById('setting-random').checked;
  const start_time = document.getElementById('setting-start-time').value;
  const end_time = document.getElementById('setting-end-time').value;
  const checkin_time = document.getElementById('setting-fixed-time').value;
  const http_ssl_verify = document.getElementById('setting-http-ssl-verify').checked;
  const timeoutInputElement = document.getElementById('setting-http-timeout');
  const timeoutInput = Number(timeoutInputElement.value);
  const http_timeout_seconds = Number.isFinite(timeoutInput)
    ? Math.min(300, Math.max(1, Math.round(timeoutInput)))
    : 15;
  timeoutInputElement.value = String(http_timeout_seconds);
  const httpImpersonateSelect = document.getElementById('setting-http-impersonate');
  const http_impersonate = httpImpersonateSelect.value;
  const maxRecordsInput = document.getElementById('setting-max-history-records');
  const max_history_records = Math.max(0, parseInt(maxRecordsInput ? maxRecordsInput.value : 0, 10) || 0);
  if (maxRecordsInput) maxRecordsInput.value = String(max_history_records);
  const lockNotifyInput = document.getElementById('setting-lock-notify-session');
  const lock_notify_session = lockNotifyInput ? lockNotifyInput.value.trim() : '';
  if (lockNotifyInput) lockNotifyInput.value = lock_notify_session;
  const reportLevelSelect = document.getElementById('setting-report-level');
  const report_level = reportLevelSelect ? reportLevelSelect.value : 'all';
  const http_tls_mldsa = document.getElementById('setting-tls-mldsa').checked;
  const acw_sc_v2_auto_solve = document.getElementById('setting-acw-solve').checked;
  const cloudflareBrowser = readCloudflareBrowserForm();

  settings = {
    enabled,
    random_enabled,
    start_time,
    end_time,
    checkin_time,
    http_ssl_verify,
    http_timeout_seconds,
    http_impersonate,
    max_history_records,
    lock_notify_session,
    report_level,
    http_tls_mldsa,
    acw_sc_v2_auto_solve,
    ...cloudflareBrowser
  };

  try {
    await apiPost('/api/settings', settings);
    showToast('定时设置更新成功', 'success');
    closeModal('settings-modal');
    loadSettings();
  } catch (e) {
    showToast('保存设置失败', 'error');
  }
}

// Custom Target Time Modal Actions
function openTargetTimeModal() {
  let initialTime = settings.manual_target_time || '';
  if (!initialTime && settings.target_info && settings.target_info.target_time) {
    initialTime = settings.target_info.target_time;
  }
  const input = document.getElementById('custom-target-time-input');
  if (input) {
    input.value = initialTime !== '--:--' ? initialTime : '';
  }
  openModal('target-time-modal');
}

async function saveCustomTargetTime() {
  const targetTime = document.getElementById('custom-target-time-input').value;
  if (!targetTime) {
    showToast('请选择有效的时刻', 'warning');
    return;
  }
  try {
    await apiPost('/api/settings/target_time', { target_time: targetTime });
    showToast(`下次签到时间已设定为: ${targetTime}`, 'success');
    closeModal('target-time-modal');
    loadSettings();
  } catch (e) {
    showToast('更新签到时间失败', 'error');
  }
}

async function resetCustomTargetTime() {
  try {
    await apiPost('/api/settings/target_time', { target_time: '' });
    showToast('已恢复全局自动计算', 'success');
    closeModal('target-time-modal');
    loadSettings();
  } catch (e) {
    showToast('恢复配置失败', 'error');
  }
}

// History Logs Actions & Infinite Scroll Pagination
function getLogTitle(log) {
  if (log.type === 'task') return log.manual ? '定时任务（手动运行）' : '定时任务';
  if (log.type === 'test') return '单站连通性测试';
  if (log.type === 'manual' || (log.manual && log.type !== 'test')) return '手动一键签到';
  return '自动定时签到';
}

/**
 * Collapse a value to a single short line.
 * Response bodies can be whole HTML pages or JSON documents, so the overview
 * flattens every run of whitespace before truncating.
 */
function abridge(text, limit = 120) {
  const flat = String(text ?? '').replace(/\s+/g, ' ').trim();
  return flat.length > limit ? `${flat.slice(0, limit)}…` : flat;
}

/** Derive overview counters from a log's per-site results. */
function summarizeLog(log) {
  const details = Array.isArray(log?.details) ? log.details : [];
  let okCount = 0;
  let totalQuota = 0;
  let hasQuota = false;
  const parts = [];

  details.forEach(item => {
    if (item?.success) okCount += 1;
    const quota = Number(item?.total_quota);
    if (Number.isFinite(quota) && quota > 0) {
      totalQuota += quota;
      hasQuota = true;
    }
    const name = item?.site_name || item?.site_id || '未命名站点';
    const message = abridge(item?.message, 40);
    parts.push(message ? `${name}: ${message}` : name);
  });

  return {
    okCount,
    total: details.length,
    totalQuota: hasQuota ? totalQuota : null,
    // Built from structured fields rather than log.report, which embeds the
    // raw station messages verbatim.
    preview: parts.length ? abridge(parts.join(' · '), 160) : abridge(log?.report, 160)
  };
}

function createLogTimelineItem(log) {
  const item = document.createElement('div');
  item.className = 'timeline-item';

  const details = Array.isArray(log?.details) ? log.details : [];
  const single = details.length === 1 ? details[0] : null;

  const header = document.createElement('div');
  header.className = 'timeline-header';
  const title = document.createElement('span');
  title.className = 'timeline-title';
  // One entry is one site, so lead with its name; the run type is secondary.
  title.textContent = single
    ? `${single.site_name || single.site_id || '未命名站点'} · ${getLogTitle(log)}`
    : getLogTitle(log);
  const time = document.createElement('span');
  time.className = 'timeline-time';
  time.textContent = log.timestamp || '';
  header.append(title, time);

  const stats = summarizeLog(log);
  const summary = document.createElement('div');
  summary.className = 'timeline-summary';
  if (single) {
    const status = document.createElement('span');
    if (single.success) {
      status.className = 'badge badge-success';
      status.textContent = '成功';
    } else if (single.expired) {
      status.className = 'badge badge-failure';
      status.textContent = 'Token 失效';
    } else {
      status.className = 'badge badge-failure';
      status.textContent = '失败';
    }
    summary.appendChild(status);
    const gained = Number(single.gained_quota);
    if (Number.isFinite(gained) && gained > 0) {
      const gain = document.createElement('span');
      gain.className = 'badge badge-success';
      gain.textContent = `+${formatBalance(gained)}`;
      summary.appendChild(gain);
    }
  } else if (stats.total > 0) {
    const counts = document.createElement('span');
    const allOk = stats.okCount === stats.total;
    counts.className = `badge ${allOk ? 'badge-success' : 'badge-warning'}`;
    counts.textContent = `成功 ${stats.okCount}/${stats.total}`;
    summary.appendChild(counts);
  } else {
    const empty = document.createElement('span');
    empty.className = 'badge badge-info';
    empty.textContent = log.success ? '已完成' : '无站点结果';
    summary.appendChild(empty);
  }
  if (stats.totalQuota !== null) {
    const balance = document.createElement('span');
    balance.className = 'badge badge-info';
    balance.textContent = single
      ? `余额 ${formatBalance(stats.totalQuota)}`
      : `总余额 ${formatBalance(stats.totalQuota)}`;
    summary.appendChild(balance);
  }

  const preview = document.createElement('div');
  preview.className = 'timeline-preview';
  // Abridged on purpose: a station message can be a whole HTML page or JSON
  // document, which belongs in the detail view, not the overview.
  preview.textContent = single
    ? (abridge(single.message, 160) || '无更多信息')
    : (stats.preview || '无更多信息');
  preview.title = '点击「查看详情」查看完整报文';

  const actions = document.createElement('div');
  actions.className = 'timeline-actions';
  actions.appendChild(
    createActionButton('查看详情', 'btn-primary-plain', () => openLogDetail(log), false)
  );

  item.append(header, summary, preview, actions);
  return item;
}

function createLogDetailBlock(labelText, value, className = '') {
  const block = document.createElement('div');
  block.className = `log-detail-block${className ? ` ${className}` : ''}`;
  const label = document.createElement('div');
  label.className = 'log-detail-label';
  label.textContent = labelText;
  const pre = document.createElement('pre');
  pre.className = 'log-detail-pre';
  if (className.includes('log-detail-report') || className.includes('summary')) {
    pre.classList.add('log-detail-summary');
  }
  pre.textContent = value || '';
  block.append(label, pre);
  return block;
}

function createLogAttemptElement(attempt, index) {
  const item = attempt || {};
  const attemptElement = document.createElement('div');
  attemptElement.className = `log-attempt ${item.success === true ? 'success' : 'failed'}`;

  const header = document.createElement('div');
  header.className = 'log-attempt-header';
  const step = document.createElement('span');
  step.className = 'log-attempt-step';
  step.textContent = item.step || `请求 ${index + 1}`;
  const status = document.createElement('span');
  status.className = 'log-attempt-status';
  status.textContent = item.status !== null && item.status !== undefined
    ? `HTTP ${item.status}`
    : '未收到 HTTP 响应';
  header.append(step, status);

  const url = document.createElement('div');
  url.className = 'log-attempt-url';
  url.textContent = `${item.method || ''} ${item.url || ''}`.trim();
  attemptElement.append(header, url);

  if (item.message) {
    const message = document.createElement('div');
    message.className = 'log-detail-message';
    message.textContent = item.message;
    attemptElement.appendChild(message);
  }
  if (item.error) {
    const error = document.createElement('div');
    error.className = 'log-detail-error';
    error.textContent = `异常：${item.error}`;
    attemptElement.appendChild(error);
  }
  if (item.response) {
    const responseLength = item.response_length ? `（${item.response_length} 字符）` : '';
    attemptElement.appendChild(
      createLogDetailBlock(`响应内容${responseLength}`, item.response)
    );
  }
  return attemptElement;
}

function createLogResultElement(result, index) {
  const item = result || {};
  const resultElement = document.createElement('section');
  resultElement.className = 'log-detail-result';

  const resultHeader = document.createElement('div');
  resultHeader.className = 'log-detail-result-header';
  const siteInfo = document.createElement('div');
  const site = document.createElement('div');
  site.className = 'log-detail-site';
  site.textContent = item.site_name || `站点 ${index + 1}`;
  const siteId = document.createElement('div');
  siteId.className = 'log-detail-site-id';
  siteId.textContent = `ID：${item.site_id || '未记录'}`;
  siteInfo.append(site, siteId);
  const resultStatus = document.createElement('div');
  resultStatus.className = `log-detail-status ${item.success ? 'success' : 'failed'}`;
  resultStatus.textContent = item.success ? '成功' : (item.expired ? '鉴权失败' : '失败');
  resultHeader.append(siteInfo, resultStatus);
  resultElement.appendChild(resultHeader);

  const message = document.createElement('div');
  message.className = 'log-detail-message';
  message.textContent = item.message || '未记录结果消息';
  resultElement.appendChild(message);

  const quota = Number(item.total_quota);
  if (Number.isFinite(quota) && quota > 0) {
    const balance = document.createElement('div');
    balance.className = 'log-detail-balance';
    balance.textContent = `余额：${formatBalance(quota)}`;
    resultElement.appendChild(balance);
  }

  if (item.error_detail) {
    resultElement.appendChild(
      createLogDetailBlock('请求摘要', item.error_detail, 'log-detail-summary-block')
    );
  }

  const attempts = Array.isArray(item.attempts) ? item.attempts : [];
  const attemptsLabel = document.createElement('div');
  attemptsLabel.className = 'log-detail-label log-detail-attempts-label';
  attemptsLabel.textContent = `请求链路（${attempts.length} 次）`;
  resultElement.appendChild(attemptsLabel);

  const attemptList = document.createElement('div');
  attemptList.className = 'log-attempt-list';
  if (attempts.length > 0) {
    attempts.forEach((attempt, attemptIndex) => {
      attemptList.appendChild(createLogAttemptElement(attempt, attemptIndex));
    });
  } else {
    const empty = document.createElement('div');
    empty.className = 'log-detail-empty';
    empty.textContent = '该条历史记录没有保存请求级详情（旧版本日志）。';
    attemptList.appendChild(empty);
  }
  resultElement.appendChild(attemptList);
  return resultElement;
}

function openLogDetail(log) {
  if (!log) return;
  const title = document.getElementById('log-detail-title');
  const body = document.getElementById('log-detail-body');
  if (!body) return;

  const details = Array.isArray(log.details) ? log.details : [];
  // One entry is normally one site, so name it in the title rather than making
  // the user hunt for it. Pre-split entries fall back to a neutral heading.
  const single = details.length === 1 ? details[0] : null;
  const siteName = single ? (single.site_name || single.site_id || '未命名站点') : '';
  if (title) {
    title.textContent = siteName
      ? `${siteName} · ${log.timestamp || ''}`
      : `签到日志详情 · ${log.timestamp || ''}`;
  }
  body.replaceChildren();

  const overview = document.createElement('div');
  overview.className = 'log-detail-overview';
  const fields = [['类型', getLogTitle(log)], ['时间', log.timestamp || '未记录']];
  if (!single && details.length > 1) {
    fields.push(['站点数', String(details.length)]);
  }
  fields.forEach(([labelText, value]) => {
    const field = document.createElement('div');
    const label = document.createElement('span');
    label.textContent = labelText;
    const strong = document.createElement('strong');
    strong.textContent = value;
    field.append(label, strong);
    overview.appendChild(field);
  });
  body.appendChild(overview);

  // No aggregate report block: an entry covers one site's task, and its status,
  // message and balance already appear in the section below. Older databases
  // may still hold pre-split entries with several sites, so the loop stays.
  if (details.length > 0) {
    details.forEach((result, resultIndex) => {
      body.appendChild(createLogResultElement(result, resultIndex));
    });
  } else {
    const empty = document.createElement('div');
    empty.className = 'log-detail-empty';
    empty.textContent = '这条日志没有站点详情。';
    body.appendChild(empty);
  }
  openModal('log-detail-modal');
}

function renderLogMessage(container, message) {
  if (!container) return;
  container.replaceChildren();
  const empty = document.createElement('div');
  empty.className = 'empty-text';
  empty.textContent = message;
  container.appendChild(empty);
}

function updateLogsFooter(isLoadingMore) {
  const container = document.getElementById('logs-body');
  if (!container) return;

  const existingLoading = container.querySelector('.logs-loading-more');
  if (existingLoading) existingLoading.remove();
  const existingEnd = container.querySelector('.logs-end-line');
  if (existingEnd) existingEnd.remove();

  if (logItems.length === 0) return;

  if (isLoadingMore) {
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'logs-loading-more';
    const spinner = document.createElement('div');
    spinner.className = 'spinner';
    const text = document.createElement('span');
    text.textContent = '正在加载更多历史记录...';
    loadingDiv.append(spinner, text);
    container.appendChild(loadingDiv);
  } else if (!logsHasMore) {
    const endDiv = document.createElement('div');
    endDiv.className = 'logs-end-line';
    const total = logsTotal || logItems.length;
    endDiv.textContent = logsStartDate || logsEndDate
      ? `筛选结果：共 ${total} 条日志`
      : `已加载全部日志 (共 ${total} 条)`;
    container.appendChild(endDiv);
  }
}

function syncLogTimeFilterFields() {
  const startInput = document.getElementById('logs-start-date');
  const endInput = document.getElementById('logs-end-date');
  if (startInput) startInput.value = logsStartDate;
  if (endInput) endInput.value = logsEndDate;
}

function applyLogTimeFilter() {
  const startInput = document.getElementById('logs-start-date');
  const endInput = document.getElementById('logs-end-date');
  const startDate = startInput?.value || '';
  const endDate = endInput?.value || '';

  if (startDate && endDate && startDate > endDate) {
    showToast('开始日期不能晚于结束日期', 'warning');
    return;
  }

  logsStartDate = startDate;
  logsEndDate = endDate;
  fetchLogsPage(true);
}

function resetLogTimeFilter() {
  logsStartDate = '';
  logsEndDate = '';
  syncLogTimeFilterFields();
  fetchLogsPage(true);
}

async function fetchLogsPage(isInitial = false) {
  const container = document.getElementById('logs-body');
  if (!container) return;
  if (logsLoading || (!isInitial && !logsHasMore)) return;

  logsLoading = true;

  if (isInitial) {
    logItems = [];
    logsNextBeforeId = null;
    logsHasMore = true;
    logsTotal = 0;
    renderLogMessage(container, '正在加载历史日志...');
  } else {
    updateLogsFooter(true);
  }

  try {
    const params = { limit: 20 };
    if (logsNextBeforeId !== null && logsNextBeforeId !== undefined) {
      params.before_id = logsNextBeforeId;
    }
    if (logsStartDate) params.start_date = logsStartDate;
    if (logsEndDate) params.end_date = logsEndDate;

    const data = await apiGet('/api/logs', params);
    let newItems = [];

    if (data && typeof data === 'object' && !Array.isArray(data)) {
      newItems = Array.isArray(data.items) ? data.items : [];
      logsHasMore = Boolean(data.has_more);
      logsTotal = typeof data.total === 'number' ? data.total : (logItems.length + newItems.length);
      logsNextBeforeId = data.next_before_id ?? (newItems.length > 0 ? newItems[newItems.length - 1].id : null);
    } else if (Array.isArray(data)) {
      newItems = data;
      logsHasMore = newItems.length === 20;
      logsNextBeforeId = newItems.length > 0 ? newItems[newItems.length - 1].id : null;
      logsTotal = logItems.length + newItems.length;
    }

    if (isInitial) {
      container.replaceChildren();
      if (newItems.length === 0) {
        renderLogMessage(
          container,
          logsStartDate || logsEndDate
            ? '该时间范围内没有签到记录'
            : '暂无签到历史记录'
        );
        logsLoading = false;
        return;
      }
      const timeline = document.createElement('div');
      timeline.className = 'timeline';
      timeline.id = 'logs-timeline';
      container.appendChild(timeline);
    }

    const timeline = document.getElementById('logs-timeline');
    if (timeline) {
      newItems.forEach(log => {
        logItems.push(log);
        timeline.appendChild(createLogTimelineItem(log));
      });
    }

    updateLogsFooter(false);
  } catch (e) {
    console.error('fetchLogsPage error:', e);
    if (isInitial) {
      renderLogMessage(container, '读取日志失败');
    }
  } finally {
    logsLoading = false;
  }
}

function handleLogsScroll() {
  const body = document.getElementById('logs-body');
  if (!body || logsLoading || !logsHasMore) return;
  if (body.scrollTop + body.clientHeight >= body.scrollHeight - 80) {
    fetchLogsPage(false);
  }
}

function openLogsDrawer() {
  openModal('logs-drawer');
  syncLogTimeFilterFields();
  fetchLogsPage(true);
}

async function loadLogs() {
  const drawer = document.getElementById('logs-drawer');
  if (drawer && drawer.classList.contains('active')) {
    await fetchLogsPage(true);
  }
}

function clearLogs() {
  showConfirm('确定要清空所有历史签到日志吗？此操作无法撤销。', async () => {
    try {
      await apiPost('/api/logs/clear', {});
      logItems = [];
      logsNextBeforeId = null;
      logsHasMore = false;
      logsTotal = 0;
      // Nothing is left to filter, so drop the range too.
      logsStartDate = '';
      logsEndDate = '';
      syncLogTimeFilterFields();
      const container = document.getElementById('logs-body');
      renderLogMessage(container, '暂无签到历史记录');
      showToast('历史日志已成功清空', 'success');
    } catch (e) {
      showToast('清空日志失败', 'error');
    }
  });
}

// Initial Loading
document.addEventListener('DOMContentLoaded', () => {
  loadVaultState();
  loadSites();
  loadSettings();
  const logsBody = document.getElementById('logs-body');
  if (logsBody) {
    logsBody.addEventListener('scroll', handleLogsScroll);
  }
  const unlockInput = document.getElementById('vault-unlock-key');
  if (unlockInput) {
    unlockInput.addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        submitUnlockVault();
      }
    });
  }

  // Unlocking happens in another tab, so re-sync on return. Only while locked,
  // to avoid a request every time the user switches tabs, and quietly, since
  // the user did not ask for this refresh.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && isVaultLocked()) {
      refreshVaultState({ quiet: true });
    }
  });
});
