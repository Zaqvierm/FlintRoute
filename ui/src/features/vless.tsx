import { useEffect, useState } from 'preact/hooks';
import {
  addManualVLESSServer,
  getComponents,
  getManualVLESSServers,
  getSubscriptionHWID,
  getSubscriptionSecretStatus,
  getVLESSPool,
  prepareSubscription,
  removeSubscriptionSource,
  runVLESSSpeedTest,
  saveSubscriptionHWID,
  saveSubscriptionSecrets,
  setVLESSTariff,
  type ComponentStatus,
  type ManualVLESSServer,
  type SessionInfo,
  type SubscriptionHWIDSettings
} from '../api';
import {
  asArray,
  asRecord,
  errorInfo,
  formatDateTime,
  humanStatus,
  statusTone,
  textValue
} from '../view-models';
import {
  Card,
  DetailDrawer,
  EmptyState,
  EntityCard,
  Grid,
  InfoGrid,
  PageHeader,
  RawDisclosure,
  RouteBadge,
  StatusBadge,
  StatusLine,
  useConfirmDialog,
  statusWithFreshness
} from '../components/ui';

function formatBytes(value: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit++;
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function Vless({
  routes,
  configVersion,
  role,
  mutationLocked,
  refresh,
  navigate
}: {
  routes: any[];
  configVersion: number;
  role: SessionInfo['role'];
  mutationLocked: boolean;
  refresh: () => Promise<void>;
  navigate: (screen: string) => void;
}) {
  const defaultHappPresetHWID = 'a330268d-7d9d-4343-8672-f6191f80a25c';
  const vless = routes.filter((r) => r.type === 'vless');
  const [urls, setURLs] = useState<string[]>(['']);
  const [present, setPresent] = useState<boolean | null>(null);
  const [configuredCount, setConfiguredCount] = useState(0);
  const [sourceStatuses, setSourceStatuses] = useState<Array<{ source_masked: string; source_type: string; crypto_version?: string }>>([]);
  const [hwid, setHWID] = useState<SubscriptionHWIDSettings | null>(null);
  const [hwidMode, setHWIDMode] = useState('generated');
  const [hwidSource, setHWIDSource] = useState('composite');
  const [hwidPreset, setHWIDPreset] = useState('');
  const [hwidCustomSeed, setHWIDCustomSeed] = useState('');
  const [hwidOpen, setHWIDOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [checkedServers, setCheckedServers] = useState<any[]>([]);
  const [managedAvailable, setManagedAvailable] = useState(false);
  const [selectedServer, setSelectedServer] = useState<any>(null);
  const [manualServers, setManualServers] = useState<ManualVLESSServer[]>([]);
  const [manualURI, setManualURI] = useState('');
  const [manualEditorOpen, setManualEditorOpen] = useState(false);
  const [pool, setPool] = useState<any>({ tariff_mbps: 300, sources: [], servers: [], provider_matches: [] });
  const [tariff, setTariff] = useState(300);
  const [xrayAvailable, setXrayAvailable] = useState(false);
  const confirmDialog = useConfirmDialog();

  function forceHappPreset(value: SubscriptionHWIDSettings): SubscriptionHWIDSettings {
    const preview = (value.preview ?? []).map((row) => ({ ...row, selected: row.source === 'preset' }));
    const presetRow = {
      source: 'preset',
      label: 'Preset / вручную заданный HWID',
      value: defaultHappPresetHWID,
      hwid: defaultHappPresetHWID,
      available: true,
      selected: true
    };
    const withoutPreset = preview.filter((row) => row.source !== 'preset');
    return { ...value, mode: 'preset', preset: defaultHappPresetHWID, current_hwid: defaultHappPresetHWID, preview: [presetRow, ...withoutPreset] };
  }

  function sourceRequiresHappHWID(value: string): boolean {
    const normalized = value.trim().toLowerCase();
    return normalized.startsWith('happ://') || /[?&]subkey=(?:happ(?:%3a|:)\/\/|happ\\:\/\/)/i.test(normalized);
  }

  useEffect(() => {
    const controller = new AbortController();
    const requests: Promise<any>[] = [getVLESSPool(controller.signal), getComponents(controller.signal)];
    if (role === 'administrator') requests.push(getSubscriptionSecretStatus(controller.signal), getManualVLESSServers(controller.signal), getSubscriptionHWID(controller.signal));
    Promise.allSettled(requests).then(([poolResult, componentsResult, subscription, manual, hwidResult]) => {
      if (controller.signal.aborted) return;
      if (poolResult.status === 'fulfilled') {
        setPool(poolResult.value);
        setTariff(poolResult.value.tariff_mbps || 300);
      }
      if (componentsResult.status === 'fulfilled') {
        const xrayComponent = componentsResult.value.find((item: ComponentStatus) => item.kind === 'xray');
        setXrayAvailable(Boolean(xrayComponent?.installed || xrayComponent?.health_ready || xrayComponent?.service_state === 'running'));
      }
      if (!subscription || !manual) return;
      if (subscription.status === 'fulfilled') {
        setPresent(subscription.value.present);
        setConfiguredCount(subscription.value.count ?? 0);
        setSourceStatuses(subscription.value.sources ?? []);
      } else {
        setPresent(null);
        setSourceStatuses([]);
      }
      if (manual.status === 'fulfilled') setManualServers(manual.value.servers);
      if (hwidResult?.status === 'fulfilled') {
        const hasHappSource = subscription?.status === 'fulfilled' && (subscription.value.sources ?? []).some((source: any) => source.source_type === 'happ' || source.crypto_version);
        // Happ subscriptions require the provider-compatible stable identity.
        // Do not let an older generated/custom setting silently win when a
        // Happ source is present; the save flow persists this exact preset
        // before it starts provider preparation.
        const visibleHWID = hasHappSource ? forceHappPreset(hwidResult.value) : hwidResult.value;
        setHWID(visibleHWID);
        setHWIDMode(visibleHWID.mode || 'generated');
        setHWIDSource(hwidResult.value.source || 'composite');
        setHWIDPreset(visibleHWID.preset || '');
        setHWIDCustomSeed(hwidResult.value.custom_seed || '');
      }
    }).catch(() => {
      // Promise.allSettled itself does not reject; keep this guard for a
      // provider that returns a thenable with unexpected behavior.
    });
    return () => controller.abort();
  }, [role]);

  useEffect(() => {
    if (!hwid) return;
    const happRequired = sourceStatuses.some((source) => source.source_type === 'happ' || Boolean(source.crypto_version)) || urls.some(sourceRequiresHappHWID);
    if (!happRequired || (hwid.mode === 'preset' && hwid.current_hwid === defaultHappPresetHWID)) return;
    const forced = forceHappPreset(hwid);
    setHWID(forced);
    setHWIDMode('preset');
    setHWIDPreset(defaultHappPresetHWID);
    setHWIDCustomSeed('');
  }, [sourceStatuses, urls, hwid]);

  async function saveTariff() {
    if (mutationLocked) { setMessage('Скорость тарифа нельзя изменить до подтверждения recovery state.'); return; }
    setBusy(true);
    try {
      await setVLESSTariff(tariff);
      const refreshed = await getVLESSPool();
      setPool(refreshed);
      setMessage(`Тариф ${tariff} Мбит/с сохранён. Он ограничивает вклад speedtest в score, но не режет сам трафик.`);
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function saveHWIDSettings() {
    if (mutationLocked) { setMessage('HWID settings are temporarily locked by recovery fence.'); return; }
    setBusy(true);
    try {
      const happRequired = sourceStatuses.some((source) => source.source_type === 'happ' || Boolean(source.crypto_version)) || urls.some(sourceRequiresHappHWID);
      const settings = happRequired
        ? { mode: 'preset', source: hwidSource, preset: defaultHappPresetHWID, custom_seed: '' }
        : { mode: hwidMode, source: hwidSource, preset: hwidPreset, custom_seed: hwidCustomSeed };
      const result = await saveSubscriptionHWID(settings);
      setHWID(happRequired ? forceHappPreset(result) : result);
      if (happRequired) {
        setHWIDMode('preset');
        setHWIDPreset(defaultHappPresetHWID);
        setHWIDCustomSeed('');
      }
      setHWIDOpen(false);
      setMessage(`HWID сохранён: ${result.mode === 'preset' ? 'используется заданный UUID' : 'детерминированный источник'}.`);
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function prepareCandidates(messagePrefix = 'Проверка завершена') {
    const result = await prepareSubscription(configVersion, false);
    if (!result.preparation.ready || result.preparation.secrets_printed) {
      throw new Error('Backend не подтвердил безопасный VLESS bundle.');
    }
    setCheckedServers(result.preparation.servers);
    const refreshed = await getVLESSPool();
    setPool(refreshed);
    setTariff(refreshed.tariff_mbps || 300);
    setManagedAvailable(result.activation.managed_available);
    setMessage(`${messagePrefix}: ${result.preparation.servers.length} серверов. Маршруты пока не включены — managed Xray подтверждается отдельно.`);
  }

  async function saveAndPrepare() {
    if (mutationLocked) { setMessage('Подписка временно заблокирована recovery fence. Просмотр серверов доступен.'); return; }
    const values = urls.map((value) => value.trim()).filter(Boolean);
    if (!values.length) {
      setMessage('Вставь хотя бы одну HTTPS-ссылку подписки.');
      return;
    }
    setBusy(true);
    setMessage('Сохраняю секрет и проверяю серверы. Это может занять несколько минут.');
    try {
      const saved = await saveSubscriptionSecrets(values);
      setURLs(['']);
      setPresent(true);
      setConfiguredCount(saved.count);
      setSourceStatuses(saved.sources ?? []);
      // Happ providers require an explicit stable identity. Never let a
      // first-run generated UUID or a stale provider-specific preset silently
      // reach this Happ provider. This source is bound to the administrator's
      // requested compatibility identity for the current product flow.
      if (values.some(sourceRequiresHappHWID)) {
        const preset = defaultHappPresetHWID;
        if (hwidMode !== 'preset' || hwidPreset.trim() !== preset) {
          const savedHWID = await saveSubscriptionHWID({ mode: 'preset', source: hwidSource, preset, custom_seed: '' });
          setHWID(savedHWID);
          setHWIDMode('preset');
          setHWIDPreset(preset);
        }
      }
      await prepareCandidates('Подписки сохранены и проверены');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Не удалось проверить подписку.');
    } finally {
      setBusy(false);
    }
  }

  async function removeStoredSubscription(index: number) {
    if (mutationLocked) { setMessage('Subscription changes are temporarily locked by recovery fence.'); return; }
    if (!(await confirmDialog.ask('Remove this subscription source? Existing active VLESS configuration is kept until a new verified bundle is activated.'))) return;
    setBusy(true);
    try {
      const result = await removeSubscriptionSource(index);
      setPresent(result.present);
      setConfiguredCount(result.count);
      setSourceStatuses(result.sources ?? []);
      setMessage(result.count ? 'Subscription source removed. Active VLESS configuration was not changed.' : 'All subscription sources removed. Active VLESS configuration was not changed.');
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function addManualServer() {
    if (mutationLocked) { setMessage('Добавление сервера временно заблокировано recovery fence.'); return; }
    if (!manualURI.trim()) {
      setMessage('Вставь полный vless:// URI. UUID останется только в закрытом файле на роутере.');
      return;
    }
    setBusy(true);
    setMessage('Сохраняю ручной сервер и проверяю его реальный выход…');
    try {
      const inventory = await addManualVLESSServer(manualURI.trim());
      setManualServers(inventory.servers);
      setManualURI('');
      setManualEditorOpen(false);
      await prepareCandidates('Ручной сервер сохранён и проверен');
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function refreshVLESSHealth() {
    setBusy(true);
    setMessage('Обновляю задержку и проверяю внешний путь. Недавний speedtest переиспользуется и трафик повторно не скачивается.');
    try {
      await prepareCandidates('Health обновлён');
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function measureSelectedServer() {
    if (!selectedServer?.logical_id) {
      setMessage('Для этого сервера ещё нет logical ID. Сначала запусти проверку подписки.');
      return;
    }
    setBusy(true);
    setMessage('Измеряю скорость через конкретный VLESS server. Размер ограничен тарифом и пределом 16 MiB.');
    try {
      const result = await runVLESSSpeedTest(selectedServer.logical_id);
      const refreshed = await getVLESSPool();
      setPool(refreshed);
      setSelectedServer((current: any) => ({ ...current, ...result.server }));
      setMessage(`Скорость: ${result.measurement.measured_mbps.toFixed(0)} Мбит/с; использовано ${formatBytes(result.measurement.bytes_used)} за ${result.measurement.duration_ms} мс.`);
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function activateManaged() {
    if (mutationLocked) { setMessage('Включение managed Xray временно заблокировано recovery fence.'); return; }
    setBusy(true);
    setMessage('Создаю черновик включения managed Xray…');
    try {
      const result = await prepareSubscription(configVersion, true);
      if (!result.change) throw new Error('Backend не создал транзакцию managed Xray.');
      setManagedAvailable(false);
      setMessage('Черновик managed Xray создан. Проверь diff и запусти применение отдельно в очереди изменений.');
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Managed Xray не включён; транзакция откатилась или ждёт устройство.');
    } finally {
      setBusy(false);
    }
  }

  const candidateServers = checkedServers.length ? checkedServers : pool.servers.length ? pool.servers : vless;
  const checksByTag = new Map(candidateServers.map((server: any) => [server.tag, server]));
  const subscriptionServers = candidateServers.filter((server: any) => !String(server.tag ?? '').startsWith('manual-'));
  const manualServerViews = manualServers.map((server) => ({ ...server, tag: server.id, ...asRecord(checksByTag.get(server.id)) }));

  function addSubscriptionRow() {
    if (urls.length < 5) setURLs((current) => [...current, '']);
  }

  function removeSubscriptionRow(index: number) {
    setURLs((current) => {
      const next = current.filter((_, currentIndex) => currentIndex !== index);
      return next.length ? next : [''];
    });
  }

  async function copyHWID() {
    if (!hwid?.current_hwid || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(hwid.current_hwid);
      setMessage('Deterministic subscription HWID copied.');
    } catch {
      setMessage('Clipboard is unavailable; the HWID remains visible in Settings.');
    }
  }

  function selectHWIDSource(source: string) {
    if (sourceStatuses.some((item) => item.source_type === 'happ' || Boolean(item.crypto_version)) || urls.some(sourceRequiresHappHWID)) {
      setHWIDMode('preset');
      setHWIDPreset(defaultHappPresetHWID);
      return;
    }
    setHWIDMode('generated');
    setHWIDSource(source);
  }

  const happSourceConfigured = sourceStatuses.some((source) => source.source_type === 'happ' || Boolean(source.crypto_version)) || urls.some(sourceRequiresHappHWID);

  return (
    <section>
      <PageHeader title="VLESS-серверы" text="Подписки и ручные серверы разделены. Ping — задержка проверки, а не скорость канала." />
      <Card title="Выбор сервера">
        {candidateServers.find((server: any) => server.selected) ? (() => { const active = candidateServers.find((server: any) => server.selected); return <div class="row"><b>{textValue(active.name ?? active.tag, 'VLESS server')}</b><span>{active.latency_ms ? `${active.latency_ms} мс` : 'latency неизвестна'} · {active.measured_mbps ? `${active.measured_mbps.toFixed(0)} Мбит/с` : 'speedtest не запускался'}</span><small>{active.path_verified ? 'PathVerified' : 'путь не подтверждён'} · score {Number(active.score ?? 0).toFixed(1)}</small></div>; })() : <p>Активного проверенного сервера пока нет.</p>}
        <div class="smart-dns-editor">
          <label><span>Скорость интернет-тарифа, Мбит/с</span><input type="number" min="1" max="100000" value={tariff} onInput={(event) => setTariff(Number((event.target as HTMLInputElement).value))} /></label>
          <div class="actions">{[100, 300, 500, 1000].map((value) => <button disabled={mutationLocked} class={tariff === value ? 'active' : ''} onClick={() => setTariff(value)} key={value}>{value}</button>)}<button class="primary" disabled={busy || mutationLocked || role !== 'administrator'} onClick={saveTariff}>Сохранить</button></div>
          <small>Для score используется min(измеренная скорость, тариф). Значение 850 Мбит/с при тарифе 300 даст эффективные 300.</small>
        </div>
      </Card>
      <Card title="VPN-подписки">
        <div class="row"><b>Источники</b><span>{present === true ? `${configuredCount} из 5` : present === false ? 'не заданы' : 'статус неизвестен'}</span></div>
        {role === 'administrator' ? (
          <div>
            <div class="subscription-source-list">
              {sourceStatuses.map((source, index) => <div class="subscription-source-status" key={`${source.source_masked}:${index}`}><b>#{index + 1}</b><span>{source.source_masked}</span><small>{source.source_type}{source.crypto_version ? ` / ${source.crypto_version}` : ''}</small><button type="button" class="icon-button" aria-label={`Remove stored source ${index + 1}`} onClick={() => void removeStoredSubscription(index)} disabled={busy || mutationLocked}>×</button></div>)}
              {urls.map((url, index) => (
                <label class="subscription-slot" key={index}>
                  <span>#{index + 1}</span>
                    <input
                     disabled={mutationLocked}
                    type="password"
                    value={url}
                    onInput={(event) => {
                      const next = [...urls];
                      next[index] = (event.target as HTMLInputElement).value;
                      setURLs(next);
                    }}
                    autocomplete="off"
                    placeholder="https://... or happ://crypt4/..."
                  />
                  <button type="button" class="icon-button" aria-label={`Remove source ${index + 1}`} onClick={() => removeSubscriptionRow(index)} disabled={busy || mutationLocked || urls.length === 1}>×</button>
                  <i>{busy ? 'checking' : 'new source'}</i>
                </label>
              ))}
            </div>
            <div class="actions"><button type="button" onClick={addSubscriptionRow} disabled={urls.length >= 5 || busy || mutationLocked}>+ Add subscription</button></div>
            <small>Original source is kept in the protected file. Happ payloads are resolved only for the provider request; the resolved credential is never returned.</small>
            <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={saveAndPrepare}>
              {busy ? 'Проверяю серверы…' : 'Сохранить и проверить'}
            </button>
            {managedAvailable && <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={activateManaged}>Явно включить managed Xray</button>}
            {managedAvailable && <small>Одна транзакция включит TPROXY, bypass mark и проверенные VLESS routes. Без успешной проверки она не будет подтверждена.</small>}
            <div class="hwid-settings hwid-compact">
              <div class="row"><span>Provider HWID</span><span>{hwidMode === 'preset' ? 'Preset UUID' : hwidMode === 'disabled' ? 'отключён' : 'детерминированный'}</span><button type="button" onClick={() => setHWIDOpen(true)} disabled={busy || role !== 'administrator'}>HWID</button></div>
              <small>Нужен только Happ-провайдеру. Источник и получающийся UUID — в компактном окне.</small>
            </div>
            {hwidOpen && <div class="modal-backdrop" role="presentation" onClick={() => setHWIDOpen(false)}><section class="confirm-dialog hwid-dialog" role="dialog" aria-modal="true" aria-labelledby="hwid-title" onClick={(event) => event.stopPropagation()}>
              <header class="modal-header"><h2 id="hwid-title">Источник HWID</h2><button type="button" class="icon-button" aria-label="Закрыть" onClick={() => setHWIDOpen(false)}>×</button></header>
              <p>Выбери стабильный источник. Один и тот же источник даёт один и тот же UUID после перезагрузки.</p>
              <div class="form-grid">
                <label><span>Режим</span><select value={happSourceConfigured ? 'preset' : hwidMode} onChange={(event) => setHWIDMode((event.target as HTMLSelectElement).value)} disabled={busy || mutationLocked || happSourceConfigured}><option value="generated">Сгенерированный</option><option value="preset">Preset / вручную</option><option value="disabled">Отключён</option></select></label>
                {hwidMode === 'preset' && <label><span>UUID</span><input type="text" value={hwidPreset} onInput={(event) => setHWIDPreset((event.target as HTMLInputElement).value)} autocomplete="off" placeholder="xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx" /></label>}
                {hwidMode === 'generated' && hwidSource === 'custom_seed' && <label><span>Custom seed</span><input type="text" value={hwidCustomSeed} onInput={(event) => setHWIDCustomSeed((event.target as HTMLInputElement).value)} autocomplete="off" placeholder="задайте стабильную строку" /></label>}
              </div>
              {happSourceConfigured && <small class="source-note">Для Happ-подписки используется обязательный совместимый preset: {defaultHappPresetHWID}.</small>}
              <div class="hwid-table-wrap"><table class="hwid-table"><thead><tr><th>Источник</th><th>Значение</th><th>Будет HWID</th><th></th></tr></thead><tbody>{(hwid?.preview ?? []).map((row) => { const selected = (hwidMode === 'preset' && row.source === 'preset') || (hwidMode === 'generated' && row.source === hwidSource); return <tr key={row.source} class={selected ? 'selected' : undefined}><td><b>{row.label}</b>{selected && <small>выбран</small>}</td><td class="mono">{row.value || row.reason || 'недоступно'}</td><td class="mono">{row.hwid || '—'}</td><td>{row.available && row.source !== 'preset' && <button type="button" onClick={() => selectHWIDSource(row.source)} disabled={busy || mutationLocked}>Выбрать</button>}{row.source === 'preset' && <button type="button" onClick={() => setHWIDMode('preset')} disabled={busy || mutationLocked}>Использовать</button>}</td></tr>; })}</tbody></table></div>
              <div class="row"><span>Текущий HWID</span><code>{hwidMode === 'disabled' ? 'отключён' : hwid?.current_hwid || 'недоступен'}</code><button type="button" onClick={() => void copyHWID()} disabled={!hwid?.current_hwid || hwidMode === 'disabled'}>Копировать</button></div>
              <div class="actions"><button type="button" onClick={() => setHWIDOpen(false)}>Отмена</button><button class="primary" disabled={busy || mutationLocked || role !== 'administrator'} onClick={() => void saveHWIDSettings()}>Сохранить выбор</button></div>
            </section></div>}
            {message && <div class="action-status"><p>{message}</p>{message.includes('черновик') && <button type="button" onClick={() => navigate('Операции')}>Открыть центр операций</button>}</div>}
          </div>
        ) : <p>Импорт подписки доступен администратору.</p>}
      </Card>
      <section class="server-section"><h2>Источники доступа</h2><div class="server-checks">
        {(pool.sources ?? []).map((source: any) => <EntityCard title={textValue(source.provider_name, source.name)} status={source.manual ? 'manual' : 'subscription'} onOpen={() => setSelectedServer({ source_record: source })} key={source.id}>
          <InfoGrid items={[["Источник", source.name], ["Original source", source.original_source_masked], ["Resolved source", source.resolved_source_masked], ["Type", source.source_type], ["Crypto", source.crypto_version], ["Resolution", source.resolution_status], ["Серверов", source.server_count], ["Срок", source.expiry_known ? formatDateTime(source.expires_at) : 'не предоставлен провайдером']]} />
        </EntityCard>)}
        {!pool.sources?.length && <EmptyState title="Источников пока нет" text="Добавь HTTPS-подписку или собственный VLESS URI." />}
      </div>{(pool.provider_matches ?? []).map((match: any) => <p class="reason" key={`${match.left_provider_id}:${match.right_provider_id}`}>Пулы похожи: совпало {match.matched_servers}/{match.compared_servers}. Объединение требует подтверждения и не выполняется молча.</p>)}</section>
       {xrayAvailable && <section class="server-section"><div class="section-title"><div><h2>VLESS servers</h2><p>Server status, measured latency and optional throughput are shown separately.</p></div><div class="actions"><button disabled={busy || !configVersion || (!present && manualServers.length === 0)} onClick={refreshVLESSHealth}>Refresh health</button><button disabled={mutationLocked} onClick={() => setManualEditorOpen((open) => !open)}>+ Add server</button></div></div>
      {manualEditorOpen && <div class="service-editor manual-vless-editor">
        <label><span>VLESS URI</span><input type="password" value={manualURI} onInput={(event) => setManualURI((event.target as HTMLInputElement).value)} autocomplete="off" placeholder="vless://UUID@server:443?security=reality&…" /></label>
        <small>URI и UUID не возвращаются через API и хранятся в закрытом файле. До явного managed activation сервер не меняет маршрутизацию.</small>
         <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={addManualServer}>{busy ? 'Проверяю…' : 'Сохранить и проверить'}</button>
      </div>}
      <div class="server-checks">
        {subscriptionServers.map((server: any) => (
          <EntityCard title={textValue(server.name ?? server.tag, 'VLESS server')} status={statusWithFreshness(server.status ?? server.health, server)} onOpen={() => setSelectedServer({ source: 'subscription', ...server })} key={server.tag}>
            <InfoGrid items={[["Hostname", server.hostname ?? server.address], ["Resolved IP", (server.resolved_ips ?? []).join(', ')], ["Страна", server.country || 'не определена'], ["Protocol / security", `vless / ${textValue(server.security, 'не указано')}`], ["Ping", server.latency_ms ? `${server.latency_ms} мс` : null], ["Скорость", server.measured_mbps ? `${server.measured_mbps.toFixed(0)} Мбит/с` : 'не измерена'], ["Источников", server.source_count ?? 1], ["Роль", server.selected ? 'selected' : server.standby ? 'standby' : server.quarantined ? 'quarantined' : null]]} />
            {server.reason && <p class="reason">{server.reason}</p>}
          </EntityCard>
        ))}
        {!subscriptionServers.length && <EmptyState title="Серверов из подписок пока нет" text="Добавь HTTPS-подписку и запусти проверку либо используй ручной VLESS ниже." />}
      </div></section>}
      {xrayAvailable && <section class="server-section"><h2>Добавленные вручную</h2><div class="server-checks">
        {manualServerViews.map((server: any) => <EntityCard title={textValue(server.name, 'Свой VPS')} status={statusWithFreshness(server.status ?? 'configured', server)} onOpen={() => setSelectedServer({ source: 'manual', ...server, uri_masked: `vless://••••@${server.address}:${server.port}` })} key={server.id}>
          <InfoGrid items={[["Адрес", `${server.address}:${server.port}`], ["Транспорт", server.network], ["Security", server.security], ["Ping", server.latency_ms ? `${server.latency_ms} мс` : 'ещё не измерен'], ["Состояние", server.status ?? 'configured']]} />
          {server.reason && <p class="reason">{humanStatus(server.reason)}</p>}
        </EntityCard>)}
        {!manualServerViews.length && <EmptyState title="Ручных серверов нет" text="Нажми «Добавить свой VPS», вставь vless:// URI и дождись проверки пути." />}
      </div></section>}
      <DetailDrawer title={textValue(selectedServer?.name ?? selectedServer?.tag ?? selectedServer?.source_record?.provider_name, 'VLESS server')} open={Boolean(selectedServer)} onClose={() => setSelectedServer(null)}><InfoGrid items={[["Источник", selectedServer?.source ?? selectedServer?.source_record?.name], ["Provider", selectedServer?.source_record?.provider_name], ["Hostname", selectedServer?.hostname ?? selectedServer?.address], ["Resolved IP", (selectedServer?.resolved_ips ?? []).join(', ')], ["URI", selectedServer?.uri_masked], ["Страна", selectedServer?.country], ["Источник страны", selectedServer?.country_source], ["Security", selectedServer?.security], ["Транспорт", selectedServer?.transport ?? selectedServer?.network], ["Ping", selectedServer?.latency_ms ? `${selectedServer.latency_ms} мс` : null], ["Средний ping", selectedServer?.average_latency_ms ? `${selectedServer.average_latency_ms} мс` : null], ["Jitter", selectedServer?.jitter_ms ? `${selectedServer.jitter_ms} мс` : null], ["Скорость raw", selectedServer?.measured_mbps ? `${selectedServer.measured_mbps} Мбит/с` : null], ["Эффективная скорость", selectedServer?.effective_mbps ? `${selectedServer.effective_mbps} Мбит/с` : null], ["Трафик speedtest", selectedServer?.speed_bytes ? formatBytes(selectedServer.speed_bytes) : null], ["Длительность speedtest", selectedServer?.speed_duration_ms ? `${selectedServer.speed_duration_ms} мс` : null], ["Score", selectedServer?.score], ["Health", selectedServer?.health ?? selectedServer?.status], ["PathVerified", selectedServer?.path_verified ? 'Да' : 'Нет'], ["Источники", (selectedServer?.source_ids ?? []).join(', ')], ["Expires", selectedServer?.source_record?.expiry_known ? formatDateTime(selectedServer?.source_record?.expires_at) : 'не предоставлен провайдером'], ["Quarantine", selectedServer?.quarantine_reason ?? selectedServer?.reason], ["Последняя проверка", formatDateTime(selectedServer?.last_checked_at)], ["Xray tag", selectedServer?.tag], ["SOCKS port", selectedServer?.socks_port ?? selectedServer?.socks5]]} /><p class="source-note">Ping идёт через candidate VLESS path. Полный speedtest запускается отдельно и не должен крутиться каждые 30 секунд.</p>{role === 'administrator' && selectedServer?.logical_id && <button class="primary" disabled={busy || !selectedServer.path_verified} onClick={measureSelectedServer}>Измерить скорость через этот сервер</button>}<RawDisclosure value={selectedServer} /></DetailDrawer>
    {confirmDialog.dialog}
    </section>
  );
}
function RouteType({ title, type, routes }: { title: string; type: string; routes: any[] }) {
  const [selected, setSelected] = useState<any>(null);
  return <section><h2>{title}</h2><Grid>{routes.filter((r) => r.type === type).map((r) => <EntityCard title={r.tag} status={statusWithFreshness(r.status, r)} onOpen={() => setSelected(r)}><RouteBadge type={type} /><p>{humanStatus(r.status)}</p></EntityCard>)}</Grid><DetailDrawer title={selected?.tag ?? title} open={Boolean(selected)} onClose={() => setSelected(null)}><InfoGrid items={[["Тип", selected?.type], ["Состояние", selected?.status], ["Фактический путь", selected?.effective_path], ["Scope", selected?.scope], ["Health", selected?.health]]} /><RawDisclosure value={selected} /></DetailDrawer></section>;
}
