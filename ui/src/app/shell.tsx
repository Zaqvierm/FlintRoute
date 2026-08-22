import type { ChangeSet, SessionInfo } from '../api';
import { useState } from 'preact/hooks';
import { formatDateTime, humanStatus, statusTone, textValue } from '../view-models';

export function SessionBar({ session, apiError, loading, lastUpdated, onRetry, onLogout }: {
  session: SessionInfo;
  apiError: string;
  loading: boolean;
  lastUpdated: string;
  onRetry: () => void;
  onLogout: () => void;
}) {
  return (
    <div class={`session-bar ${apiError ? 'warning' : ''}`}>
      <strong class="mobile-brand">FlintRoute</strong>
      <span>{apiError ? `API недоступен: ${apiError}` : loading ? 'Обновляю данные…' : `Обновлено: ${formatDateTime(lastUpdated, 'ещё не обновлялось')}`}</span>
      <div class="session-actions">{apiError && <button onClick={onRetry}>Повторить</button>}<span>{session.user}</span><button onClick={onLogout}>Выйти</button></div>
    </div>
  );
}

export function PrivacyBar({ hidden, onToggle }: { hidden: boolean; onToggle: () => void }) {
  return <div class={`privacy-bar ${hidden ? '' : 'revealed'}`}>
    <div><b>{hidden ? 'Адреса скрыты' : 'Адреса устройств видны'}</b><span>{hidden ? 'Скрытый режим не запрашивает raw IP и MAC. Раскрытие временное и автоматически отключится через 10 минут.' : 'Можно скрыть IP и MAC одним переключателем.'}</span></div>
    <button onClick={onToggle}>{hidden ? 'Показать адреса' : 'Скрыть адреса'}</button>
  </div>;
}

export function LoadingSkeleton() {
  return <section class="loading-grid" aria-label="Загрузка"><div /><div /><div /><div /><div /><div /></section>;
}

export function AlertCenter({ errors, onRetry }: { errors: Array<{ name: string; message: string }>; onRetry: () => void }) {
  if (!errors.length) return null;
  return <section class="alert-center" aria-live="polite">
    <b>Часть данных недоступна</b>
    <div>{errors.slice(0, 4).map((item) => <details key={item.name}><summary>{item.name}</summary><p>{item.message}</p></details>)}</div>
    <button onClick={onRetry}>Повторить всё</button>
  </section>;
}

export function OperationCenterSummary({ changes, navigate }: { changes: ChangeSet[]; navigate: (screen: string) => void }) {
  const active = changes.filter((change) => !['committed', 'rolled_back', 'failed'].includes(change.state));
  if (!active.length) return null;
  return <section class="operation-strip" aria-live="polite"><div><b>Активные изменения: {active.length}</b><span>{active.slice(0, 3).map((change) => `${humanStatus(change.state)} · ${textValue(change.title, 'правило')}`).join(' · ')}</span></div><button onClick={() => navigate('Операции')}>Открыть центр операций</button></section>;
}

export function TopBar({ overview, navigate }: { overview: any; navigate: (screen: string) => void }) {
  const candidates = [
    ['Интернет', overview.internet],
    ['Data plane', overview.data_plane],
    ['DNS', overview.dns],
    ['Маршрут', overview.current_route ?? overview.route],
    ['Ошибки', overview.critical_errors ?? overview.errors]
  ];
  const items = candidates.filter(([, value]) => value !== undefined && value !== null && value !== '');
  return (
    <header class="topbar">
      {items.map(([key, value]) => {
        const label = String(key);
        const tone = overview.freshness === 'stale' ? 'warn' : statusTone(value);
        const text = Array.isArray(value)
          ? (value.length ? `${value.length} критич. ${value.length === 1 ? 'ошибка' : 'ошибки'}` : 'Нет')
          : humanStatus(value);
        const actionable = ['Data plane', 'DNS', 'Ошибки'].includes(label) && (tone === 'bad' || tone === 'warn');
        return <div class={`status-pill ${tone}`} key={label}>
          <span>{label}</span>
          <b>{overview.freshness === 'stale' ? `${text} · данные устарели` : text}</b>
          {actionable && <button type="button" onClick={() => navigate('Диагностика')}>Проверить</button>}
        </div>;
      })}
      {!items.length && <div class="status-pill muted"><span>Состояние</span><b>Нет данных</b></div>}
    </header>
  );
}

export function BootScreen() {
  return <main class="auth-page"><section class="auth-card"><div class="mark">FR</div><h1>FlintRoute</h1><p>Проверка локальной сессии.</p></section></main>;
}

export function AuthShell({ error, onLogin, onSetup }: {
  error: string;
  onLogin: (username: string, password: string) => Promise<void>;
  onSetup: (username: string, password: string, setupToken: string) => Promise<void>;
}) {
  const [mode, setMode] = useState<'login' | 'setup'>('login');
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [setupToken, setSetupToken] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(ev: Event) {
    ev.preventDefault();
    setBusy(true);
    try {
      if (mode === 'login') await onLogin(username, password);
      else await onSetup(username, password, setupToken);
    } finally {
      setBusy(false);
    }
  }
  return <main class="auth-page"><form class="auth-card" onSubmit={submit}>
    <div class="mark">FR</div><h1>{mode === 'login' ? 'Вход' : 'Первичная настройка'}</h1>
    <label><span>Пользователь</span><input value={username} onInput={(event) => setUsername((event.target as HTMLInputElement).value)} autocomplete="username" /></label>
    <label><span>Пароль</span><input type="password" value={password} onInput={(event) => setPassword((event.target as HTMLInputElement).value)} autocomplete={mode === 'login' ? 'current-password' : 'new-password'} /></label>
    {mode === 'setup' && <label><span>Setup token</span><input value={setupToken} onInput={(event) => setSetupToken((event.target as HTMLInputElement).value)} autocomplete="one-time-code" /></label>}
    {error && <p class="auth-error">{error}</p>}
    <button class="primary" disabled={busy}>{busy ? 'Проверка…' : mode === 'login' ? 'Войти' : 'Создать администратора'}</button>
    <button type="button" onClick={() => setMode(mode === 'login' ? 'setup' : 'login')}>{mode === 'login' ? 'У меня setup token' : 'Вернуться ко входу'}</button>
  </form></main>;
}
