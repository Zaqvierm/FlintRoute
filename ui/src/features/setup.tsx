import { useEffect, useRef, useState } from 'preact/hooks';
import {
  getComponents,
  getSmartDNS,
  getTGWS,
  getVLESSPool,
  getZapret,
  setVLESSTariff
} from '../api';
import { asArray, asRecord, errorInfo, onboardingProgress, onboardingRouterReady, textValue } from '../view-models';
import { EntityCard, Grid, InfoGrid, PageHeader, StatusLine } from '../components/ui';

export function SetupScreen({ overview, services, routes, discovery, onboarding, onboardingAction, navigate, mutationLocked = false }: any) {
  const [state, setState] = useState<any>({ loading: true, components: [], pool: null, smartDNS: null, tgws: null, zapret: null, error: '' });
  const [tariff, setTariff] = useState(300);
  const requestRef = useRef<AbortController | null>(null);
  const [actionBusy, setActionBusy] = useState('');
  const [actionError, setActionError] = useState('');

  async function load() {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    setState((old: any) => ({ ...old, loading: true, error: '' }));
    const results = await Promise.allSettled([
      getComponents(controller.signal),
      getVLESSPool(controller.signal),
      getSmartDNS(controller.signal),
      getTGWS(controller.signal),
      getZapret(controller.signal)
    ]);
    if (controller.signal.aborted || requestRef.current !== controller) return;
    const value = (index: number, fallback: any) => results[index].status === 'fulfilled' ? (results[index] as PromiseFulfilledResult<any>).value : fallback;
    const failed = results.filter((item) => item.status === 'rejected');
    const pool = value(1, null);
    if (pool) setTariff(Number(pool.tariff_mbps) || 300);
    setState({
      loading: false,
      components: value(0, []),
      pool,
      smartDNS: value(2, null),
      tgws: value(3, null),
      zapret: value(4, null),
      error: failed.length ? 'Часть проверок недоступна. Повтори после восстановления соединения.' : ''
    });
  }

  useEffect(() => {
    // The setup screen owns its first-run data fetch.  Previously this effect
    // only installed the unmount cleanup, leaving a freshly opened wizard in
    // the permanent loading state until the user pressed Retry.
    void load();
    return () => {
      requestRef.current?.abort();
      requestRef.current = null;
    };
  }, []);

  const routerReady = onboardingRouterReady(onboarding, overview);
  const components = asArray(state.components).map(asRecord);
  const xray = components.find((item) => item.kind === 'xray');
  const zapretComponent = components.find((item) => item.kind === 'zapret');
  const tgwsComponent = components.find((item) => item.kind === 'tg_ws_proxy');
  const verifiedServers = asArray(state.pool?.servers).filter((raw) => Boolean(asRecord(raw).path_verified)).length;
  const smartReady = Number(state.smartDNS?.ready_resolvers ?? state.smartDNS?.ready ?? 0) > 0;
  const tgwsReady = Boolean(state.tgws?.client_path_verified);
  const zapretReady = Boolean(state.zapret?.ready ?? zapretComponent?.health_ready);
  const methodsStatus = textValue(onboarding?.steps?.methods?.status, 'pending');
  const sourcesStatus = textValue(onboarding?.steps?.sources?.status, 'pending');
  const servicesStatus = textValue(onboarding?.steps?.services?.status, 'pending');
  const progress = onboardingProgress({
    methodsStatus,
    sourcesStatus,
    servicesStatus,
    verifiedServers,
    smartReady,
    tgwsReady,
    zapretReady,
    canComplete: onboarding?.can_complete
  });
  const { methodsDone, sourcesDone, providerReady: providerChosen, serviceChoiceDone, setupReady } = progress;

  async function chooseDirect() {
    await onboardingAction('methods', 'skip');
    await onboardingAction('sources', 'skip');
  }
  async function chooseAutomatic() {
    await onboardingAction('services', 'automatic');
  }
  async function acceptSources() {
    await onboardingAction('sources', 'accept');
  }
  async function finish() {
    if (!setupReady) return;
    const result = await onboardingAction('complete', 'complete');
    if (result?.completed) navigate('Обзор');
  }
  async function runSetupAction(label: string, action: () => Promise<void>) {
    setActionBusy(label);
    setActionError('');
    try {
      await action();
    } catch (reason) {
      const info = errorInfo(reason);
      setActionError(`${info.code}: ${info.message}`);
    } finally {
      setActionBusy('');
    }
  }

  async function saveTariff() {
    if (mutationLocked) { setActionError('Изменение скорости временно заблокировано состоянием recovery.'); return; }
    if (!Number.isFinite(tariff) || tariff < 1 || tariff > 100000) { setActionError('Скорость должна быть от 1 до 100000 Мбит/с.'); return; }
    setActionBusy('tariff'); setActionError('');
    try { await setVLESSTariff(tariff); await load(); }
    catch (error) { const info = errorInfo(error); setActionError(`${info.code}: ${info.message}`); }
    finally { setActionBusy(''); }
  }

  return <section>
    <PageHeader title="Быстрая настройка" text="Пять шагов: проверить роутер, выбрать способы подключения, добавить источники, назначить сервисы и убедиться, что выбранные пути работают.">
      <button onClick={() => void load()} disabled={state.loading}>{state.loading ? 'Проверяю…' : 'Проверить снова'}</button>
      <button type="button" onClick={() => navigate('Компоненты')}>К компонентам без завершения</button>
    </PageHeader>
    {state.error && <div class="inline-error"><b>Не все проверки завершены</b><span>{state.error}</span><button onClick={() => void load()}>Повторить</button></div>}
    {actionError && <div class="inline-error" role="alert"><b>Шаг не сохранён</b><span>{actionError}</span><button onClick={() => setActionError('')}>Закрыть</button></div>}
    <div class="setup-progress">{[
      ['1', 'Роутер', routerReady],
       ['2', 'Маршруты', methodsDone],
       ['3', 'Источники', sourcesDone],
      ['4', 'Сервисы', serviceChoiceDone],
      ['5', 'Проверка', setupReady]
    ].map(([number, label, done]) => <div class={done ? 'done' : ''} key={String(number)}><b>{number}</b><span>{label}</span></div>)}</div>
    <Grid>
      <EntityCard title="1. Проверка роутера" status={routerReady ? 'ready' : 'unverified'} onOpen={() => navigate('Диагностика')}>
        <StatusLine label="Интернет" value={overview?.internet} /><StatusLine label="DNS" value={overview?.dns} />
        <p>{routerReady ? 'Базовая сеть работает. FlintRoute может переходить к настройке маршрутов.' : 'Базовая сеть не подтверждена. Открой диагностику и исправь проблему до применения правил.'}</p>
      </EntityCard>
      <EntityCard title="2. Способы подключения" status={methodsDone ? 'configured' : 'not_configured'} onOpen={() => navigate('Компоненты')}>
        <label><span>Скорость вашего тарифа, Мбит/с</span><input type="number" min="1" max="100000" value={tariff} onInput={(event) => setTariff(Number((event.target as HTMLInputElement).value))} /></label><div class="actions">{[100, 300, 500, 1000].map((value) => <button type="button" disabled={Boolean(actionBusy)} class={tariff === value ? 'active' : ''} onClick={() => setTariff(value)} key={value}>{value}</button>)}<button type="button" class="primary" disabled={actionBusy === 'tariff'} onClick={() => void saveTariff()}>{actionBusy === 'tariff' ? 'Сохраняю…' : 'Сохранить скорость'}</button></div>
        <StatusLine label="Zapret" value={zapretReady ? 'ready' : zapretComponent?.installed ? 'requires_config' : 'not_installed'} />
        <StatusLine label="Xray / VLESS" value={verifiedServers > 0 ? `${verifiedServers} verified` : xray?.installed ? 'requires_config' : 'not_installed'} />
        <StatusLine label="TG WS Proxy" value={tgwsReady ? 'verified' : tgwsComponent?.installed ? 'requires_config' : 'not_installed'} />
        {!providerChosen && <button disabled={Boolean(actionBusy)} onClick={() => void runSetupAction('methods', chooseDirect)}>Пока использовать только обычный интернет</button>}
      </EntityCard>
      <EntityCard title="3. Источники и проверка" status={sourcesDone ? 'ready' : 'not_configured'} onOpen={() => navigate(verifiedServers ? 'VLESS-серверы' : 'Компоненты')}>
        <StatusLine label="VLESS-серверы" value={verifiedServers ? `${verifiedServers} подтверждено` : 'не добавлены'} />
        <StatusLine label="Smart DNS" value={smartReady ? 'ready' : 'not_configured'} />
        <StatusLine label="Telegram proxy" value={tgwsReady ? 'verified' : 'not_configured'} />
        <p>Добавляй только нужные способы. FlintRoute не заставляет ставить всё подряд.</p>
        {providerChosen && !sourcesDone && <button disabled={Boolean(actionBusy)} onClick={() => void runSetupAction('sources', acceptSources)}>Подтвердить проверенные источники</button>}
      </EntityCard>
      <EntityCard title="4. Что нужно открыть" status={serviceChoiceDone ? 'configured' : 'not_configured'} onOpen={() => navigate('Сервисы')}>
        <p>{asArray(services).length ? `Настроено сервисов: ${asArray(services).length}.` : 'Можно закрепить Discord, ChatGPT, YouTube и другие сервисы за подходящими маршрутами.'}</p>
        {!serviceChoiceDone && <button disabled={Boolean(actionBusy)} onClick={() => void runSetupAction('services', chooseAutomatic)}>Пока выбирать автоматически</button>}
        <StatusLine label="Discovery" value={discovery?.mode ?? 'observe_only'} />
      </EntityCard>
      <EntityCard title="5. Финальная проверка" status={setupReady ? 'ready' : 'unverified'} onOpen={() => navigate('Маршруты')}>
        <StatusLine label="Обычный интернет" value={routerReady ? 'ready' : 'unverified'} />
        <StatusLine label="Выбранные маршруты" value={providerChosen ? 'configured' : 'not_configured'} />
        <StatusLine label="Правила сервисов" value={serviceChoiceDone ? 'configured' : 'not_configured'} />
        <button class="primary" disabled={!setupReady || Boolean(actionBusy)} onClick={() => void runSetupAction('complete', finish)}>Завершить настройку</button>
        {!setupReady && <p>Кнопка станет доступна, когда базовая сеть работает и выбран хотя бы Direct либо один проверенный управляемый путь.</p>}
      </EntityCard>
    </Grid>
    <details class="raw-disclosure"><summary>Что уже есть в системе</summary><InfoGrid items={[["Direct", routes?.find((r: any) => r.type === 'system_default')?.status ?? overview?.internet], ["Zapret", zapretReady ? 'ready' : 'not_configured'], ["VLESS", verifiedServers], ["Smart DNS", smartReady ? 'ready' : 'not_configured'], ["TG WS Proxy", tgwsReady ? 'verified' : 'not_configured']]} /></details>
  </section>;
}

