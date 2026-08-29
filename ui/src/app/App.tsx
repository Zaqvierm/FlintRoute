import { useEffect, useState } from 'preact/hooks';
import {
  APIError,
  login,
  logout,
  me,
  setupAdmin,
  type SessionInfo
} from '../api';
import { recoveryMutationAllowed, textValue } from '../view-models';
import {
  AlertCenter,
  AuthShell,
  BootScreen,
  LoadingSkeleton,
  OperationCenterSummary,
  PrivacyBar,
  ScreenErrorBoundary,
  SessionBar,
  TopBar
} from './shell';
import { Content as ScreenContent } from './content';
import { useNavigation } from './useNavigation';
import { useDashboardData } from './useDashboardData';
import { AppShell } from './AppShell';

export { type ContentProps } from './content';

function App() {
  const { screen, screenRef, mobileMoreOpen, setMobileMoreOpen, selectScreen } = useNavigation();
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authError, setAuthError] = useState('');
  const [privacyHidden, setPrivacyHidden] = useState(() => {
    // Address visibility is a UI preference only. It is never configuration
    // or dataplane evidence.
    try { return window.localStorage.getItem('flintroute-address-privacy') === 'hidden'; } catch { return false; }
  });
  const dashboard = useDashboardData({
    screen,
    screenRef,
    session,
    privacyHidden,
    navigate: selectScreen,
    onUnauthorized: () => setSession(null)
  });
  const { overview, onboarding, topology, devices, services, routes, discovery, events, changes, security, securitySummary, system, diagnostics, lifecycle, storage, settings, backups, revisions, configVersion, traffic, loading, refreshing, lastUpdated, apiError, sliceErrors, retryingSlice, refresh, retrySlice, clearPrivacySensitive, reset, updateOnboardingState } = dashboard;

  useEffect(() => {
    me()
      .then((next) => {
        setSession(next);
        setAuthChecked(true);
      })
      .catch((err) => {
        setAuthChecked(true);
        setSession(null);
        if (err instanceof APIError && err.code === 'setup_required') {
          setAuthError('Нужна первичная настройка администратора');
        }
      });
  }, []);

  async function togglePrivacy() {
    const next = !privacyHidden;
    if (next) clearPrivacySensitive();
    setPrivacyHidden(next);
    try { window.localStorage.setItem('flintroute-address-privacy', next ? 'hidden' : 'visible'); } catch { /* session state still works */ }
    await refresh(next);
  }

  async function handleLogin(username: string, password: string) {
    setAuthError('');
    try {
      const next = await login(username, password);
      setSession(next);
      selectScreen('Обзор');
    } catch (err) {
      if (err instanceof APIError && err.status === 428) {
        setAuthError('Администратор ещё не создан. Используй setup token.');
      } else {
        setAuthError('Вход отклонён');
      }
    }
  }

  async function handleSetup(username: string, password: string, setupToken: string) {
    setAuthError('');
    try {
      await setupAdmin(username, password, setupToken);
      const next = await login(username, password);
      setSession(next);
      selectScreen('Обзор');
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Настройка не удалась');
    }
  }

  async function handleLogout() {
    reset();
    await logout().catch(() => undefined);
    setSession(null);
  }

  if (!authChecked) return <BootScreen />;
  if (!session) return <AuthShell error={authError} onLogin={handleLogin} onSetup={handleSetup} />;

  return (
    <AppShell screen={screen} mobileMoreOpen={mobileMoreOpen} setMobileMoreOpen={setMobileMoreOpen} selectScreen={selectScreen} system={system}>
      <SessionBar session={session} apiError={apiError} loading={refreshing} lastUpdated={lastUpdated} onRetry={() => refresh()} onLogout={handleLogout} />
      <PrivacyBar hidden={privacyHidden} onToggle={togglePrivacy} />
      <TopBar overview={overview} navigate={selectScreen} />
      <AlertCenter errors={sliceErrors} onRetry={(name) => { void retrySlice(name); }} onRetryAll={() => { void refresh(); }} retrying={retryingSlice} />
      <RecoveryMutationBanner overview={overview} navigate={selectScreen} onRetry={() => refresh()} />
      <OperationCenterSummary changes={changes} navigate={selectScreen} />
      {loading ? <LoadingSkeleton /> : <ScreenErrorBoundary key={`${screen}:${privacyHidden ? 'hidden' : 'visible'}`}><ScreenContent screen={screen} session={session} configVersion={configVersion} overview={overview} mutationLocked={!recoveryMutationAllowed(overview)} onboarding={onboarding} topology={topology} devices={devices} services={services} discovery={discovery} routes={routes} traffic={traffic} events={events} changes={changes} security={security} securitySummary={securitySummary} system={system} diagnostics={diagnostics} lifecycle={lifecycle} storage={storage} settings={settings} backups={backups} revisions={revisions} privacyHidden={privacyHidden} onTogglePrivacy={togglePrivacy} refresh={refresh} onboardingAction={updateOnboardingState} navigate={selectScreen} /></ScreenErrorBoundary>}
    </AppShell>
  );
}

function RecoveryMutationBanner({ overview, navigate, onRetry }: { overview: any; navigate: (screen: string) => void; onRetry: () => void }) {
  if (overview?.recovery_status === undefined || recoveryMutationAllowed(overview)) return null;
  const status = textValue(overview.recovery_status, 'unknown');
  const reason = textValue(overview.recovery_reason, 'FlintRoute ещё не доказал безопасное состояние восстановления.');
  return <section class="warning-panel recovery-lock" role="alert">
    <div><b>Изменения временно заблокированы</b><p>{reason}</p><small>Интернет и просмотр данных остаются доступны. Новые правила и операции не запускаются, пока состояние роутера не подтверждено.</small></div>
    <div class="actions"><button onClick={onRetry}>Проверить снова</button><button onClick={() => navigate('Ревизии и recovery')}>Открыть восстановление</button><details><summary>Код</summary><span class="mono">{status} · {textValue(overview.recovery_reason_code, 'recovery_not_safe')}</span></details></div>
  </section>;
}

export { App };
