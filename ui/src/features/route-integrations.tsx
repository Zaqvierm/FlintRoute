import { useEffect, useState } from 'preact/hooks';
import {
  activateZapretSetup,
  cancelZapretCalibration,
  checkZapretSetup,
  componentAction,
  configureSmartDNS,
  getComponents,
  getSmartDNS,
  getZapret,
  getZapretCalibration,
  removeSmartDNS,
  reorderSmartDNS,
  startZapretCalibration,
  type ComponentStatus,
  type SessionInfo,
  type ZapretCalibrationStatus
} from '../api';
import {
  errorInfo,
  formatDateTime,
  humanStatus,
  parseResolverInput,
  textValue
} from '../view-models';
import {
  Card,
  DetailDrawer,
  EmptyState,
  EntityCard,
  Generic,
  Grid,
  InfoGrid,
  PageHeader,
  RawDisclosure,
  RouteBadge,
  StatusBadge,
  StatusLine,
  statusWithFreshness
} from '../components/ui';

function humanSmartDNSReason(reason?: string): string {
  const messages: Record<string, string> = {
    route_not_bound_to_verification_plan: 'DNS-сервер проверен, но пока не используется ни одним сервисом.',
    route_nft_counter_did_not_advance: 'DNS-сервер доступен, но FlintRoute пока не увидел трафик через новое правило.',
    smart_dns_socket_mark_or_policy_missing: 'DNS-сервер доступен, но правило маршрутизации не подтвердилось на роутере.',
    probe_adapter_revision_mismatch: 'Старая проверка относится к предыдущей конфигурации. Нужна свежая проверка пути.',
    dnsmasq_not_ready: 'dnsmasq не принял новую конфигурацию. FlintRoute восстановил предыдущую.',
    waf_or_rate_limit: 'DNS и TCP/TLS доступны, но application probe получил WAF или rate limit; маршрут не считается подтверждённым.'
  };
  return messages[reason ?? ''] ?? (reason ? `Проверка пути не пройдена: ${reason}.` : 'Конфигурация сохранена, но путь ещё не подтверждён.');
}

function smartDNSOperationLabel(operation: any): string {
  switch (textValue(operation?.state, '')) {
    case 'draft': return 'изменение поставлено в очередь';
    case 'validated': return 'кандидат проверен, применение запускается';
    case 'applying': return 'применяется к dataplane';
    case 'awaiting_confirmation': return 'путь проверен, завершается подтверждение';
    case 'committing': return 'фиксируется активная ревизия';
    case 'requires_device': return 'нужна проверка устройства перед применением';
    case 'recovery_required': return 'заблокировано: требуется recovery';
    case 'failed': return 'автоматическое применение не удалось';
    case 'rolled_back': return 'откачено после неудачной проверки';
    default: return 'обрабатывается';
  }
}

function smartDNSOperationActive(operation: any): boolean {
  return ['draft', 'validated', 'applying', 'awaiting_confirmation', 'committing'].includes(textValue(operation?.state, ''));
}

function resolverEndpointText(ip: unknown, port: unknown): string {
  const host = textValue(ip, '');
  const service = textValue(port, '53');
  return host.includes(':') ? `[${host}]:${service}` : `${host}:${service}`;
}

function resolverDraftsFromStatus(value: any): Array<{ name: string; primary: string; fallback: string }> {
  const configured = (value?.routes ?? [])
    .filter((route: any) => route.resolver_configured)
    .sort((left: any, right: any) => (left.order ?? 0) - (right.order ?? 0));
  const drafts = configured.map((route: any) => ({
    name: textValue(route.name, ''),
    primary: resolverEndpointText(route.resolver_ip, route.resolver_port),
    fallback: route.fallback_resolver_ip ? resolverEndpointText(route.fallback_resolver_ip, route.fallback_resolver_port) : ''
  }));
  if (drafts.length < 16) drafts.push({ name: '', primary: '', fallback: '' });
  return drafts.length ? drafts : [{ name: '', primary: '', fallback: '' }];
}

export function RouteType({ title, type, routes }: { title: string; type: string; routes: any[] }) {
  const [selected, setSelected] = useState<any>(null);
  return <section><h2>{title}</h2><Grid>{routes.filter((r) => r.type === type).map((r) => <EntityCard title={r.tag} status={statusWithFreshness(r.status, r)} onOpen={() => setSelected(r)}><RouteBadge type={type} /><p>{humanStatus(r.status)}</p></EntityCard>)}</Grid><DetailDrawer title={selected?.tag ?? title} open={Boolean(selected)} onClose={() => setSelected(null)}><InfoGrid items={[["Тип", selected?.type], ["Состояние", selected?.status], ["Фактический путь", selected?.effective_path], ["Scope", selected?.scope], ["Health", selected?.health]]} /><RawDisclosure value={selected} /></DetailDrawer></section>;
}

function zapretProfileLabel(value: { profile_name?: string; profile_id?: string } | null | undefined, fallback = 'Стратегия') {
  // Names come from the pinned catalog. Falling back to the opaque ID is
  // deliberately honest; the UI must not invent a preset name for a profile
  // that the backend did not describe.
  return textValue(value?.profile_name, textValue(value?.profile_id, fallback));
}

export function Zapret({ routes, configVersion, role, mutationLocked, refresh, navigate }: { routes: any[]; configVersion: number; role: SessionInfo['role']; mutationLocked: boolean; refresh: () => Promise<void>; navigate: (screen: string) => void }) {
  const [status, setStatus] = useState<any>(null);
  const [component, setComponent] = useState<ComponentStatus | null>(null);
  const [calibration, setCalibration] = useState<ZapretCalibrationStatus | null>(null);
  const [sourceURL, setSourceURL] = useState('');
  const [version, setVersion] = useState('');
  const [sha256, setSHA256] = useState('');
  const [testDomain, setTestDomain] = useState('example.com');
  const [report, setReport] = useState<any>(null);
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [showExhaustive, setShowExhaustive] = useState(false);
  async function load(signal?: AbortSignal) {
    const [zapretResult, componentsResult, calibrationResult] = await Promise.allSettled([getZapret(signal), getComponents(signal), getZapretCalibration(signal)]);
    if (signal?.aborted) return;
    const failures: string[] = [];
    if (zapretResult.status === 'fulfilled') setStatus(zapretResult.value);
    else { const info = errorInfo(zapretResult.reason); failures.push(`Zapret: ${info.code}: ${info.message}`); }
    if (componentsResult.status === 'fulfilled') {
      const managed = componentsResult.value.find((item) => item.kind === 'zapret') ?? null;
      setComponent(managed);
    } else { const info = errorInfo(componentsResult.reason); failures.push(`Компоненты: ${info.code}: ${info.message}`); }
    if (calibrationResult.status === 'fulfilled') setCalibration(calibrationResult.value);
    else { const info = errorInfo(calibrationResult.reason); failures.push(`Калибровка: ${info.code}: ${info.message}`); }
    if (failures.length) setMessage(failures.join(' · '));
    else setMessage('');
    const managed = componentsResult.status === 'fulfilled' ? componentsResult.value.find((item) => item.kind === 'zapret') ?? null : null;
    if (managed?.installed) {
      setSourceURL((value) => value || managed.pinned_asset_url || managed.source || '');
      setVersion((value) => value || managed.version || managed.latest_supported_version || '');
      setSHA256((value) => value || managed.binary_sha256 || managed.checksum || '');
    }
  }
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal).catch((error) => {
      if (error instanceof Error && error.name === 'AbortError') return;
      setMessage(error instanceof Error ? error.message : 'Zapret API недоступен');
    });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    if (calibration?.state !== 'running') return;
    const controller = new AbortController();
    let inFlight = false;
    const poll = () => {
      if (inFlight || controller.signal.aborted) return;
      inFlight = true;
      void getZapretCalibration(controller.signal)
        .then(setCalibration)
        .catch((error) => {
          if (error instanceof Error && error.name === 'AbortError') return;
          setMessage(error instanceof Error ? error.message : 'Не удалось обновить калибровку');
        })
        .finally(() => { inFlight = false; });
    };
    const timer = window.setInterval(poll,
      2000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [calibration?.state]);
  const input = { source_url: sourceURL.trim(), provider_version: version.trim(), binary_sha256: sha256.trim(), test_domain: testDomain.trim() };
  async function install() {
    if (mutationLocked) { setMessage('Установка Zapret заблокирована до подтверждения recovery state.'); return; }
    setBusy(true); setMessage('Определяю архитектуру, скачиваю закреплённый release и проверяю SHA-256…');
    try {
      const result = await componentAction('zapret', 'install');
      setMessage(result.changed ? 'Zapret установлен. Теперь можно запустить подбор стратегии.' : 'Zapret уже установлен и прошёл проверку.');
      await load();
    } catch (error) { const info = errorInfo(error); setMessage(`${info.code}: ${info.message}`); }
    finally { setBusy(false); }
  }
  async function startCalibration(mode: 'quick' | 'exhaustive') {
    if (mutationLocked) { setMessage('Калибровка Zapret заблокирована до подтверждения recovery state.'); return; }
    setBusy(true); setMessage(mode === 'quick'
      ? 'Запускаю быстрый curated-тест Zapret. Каждая стратегия должна доказать путь через nfqws/NFQUEUE; без такого доказательства PASS не будет.'
      : 'Запускаю полный подбор Zapret. Он может занять до 6 часов; найденный профиль не включается автоматически.');
    try {
      const result = await startZapretCalibration(testDomain.trim(), false, mode);
      setCalibration(result); setShowExhaustive(false); setMessage(mode === 'quick'
        ? 'Быстрый тест запущен. Если runtime не имеет curated evidence runner, FlintRoute остановит его без ложного PASS.'
        : 'Полный подбор запущен. Один worker сохраняет безопасное владение общими nft/NFQUEUE ресурсами.');
    } catch (error) { const info = errorInfo(error); setMessage(`${info.code}: ${info.message}`); }
    finally { setBusy(false); }
  }
  async function cancelCalibration() {
    if (mutationLocked) { setMessage('Управление калибровкой заблокировано до подтверждения recovery state.'); return; }
    setBusy(true);
    try { setCalibration(await cancelZapretCalibration()); setMessage('Остановка запрошена; test-run выполнит cleanup своих ресурсов.'); }
    catch (error) { const info = errorInfo(error); setMessage(`${info.code}: ${info.message}`); }
    finally { setBusy(false); }
  }
  async function check() {
    setBusy(true); setChecked(false); setMessage('Проверяю nfqws, архитектуру, NFQUEUE и dry-run…');
    try {
      const result = await checkZapretSetup(input, configVersion);
      setReport(result.report); setChecked(true); setMessage('Preflight пройден. Zapret ещё не включён.');
    } catch (error) { setReport(null); setMessage(error instanceof Error ? error.message : 'Zapret preflight провален.'); }
    finally { setBusy(false); }
  }
  async function activate() {
    setBusy(true); setMessage('Создаю черновик включения managed Zapret…');
    try {
      const result = await activateZapretSetup(input, configVersion);
      setChecked(false); setReport(result.report);
      setMessage(result.calibrated_profile_id
        ? `Создан черновик включения Zapret с профилем ${result.calibrated_profile_id}. Открой очередь, проверь diff и запусти применение отдельно.`
        : 'Создан черновик включения managed Zapret. Открой очередь, проверь diff и запусти применение отдельно.');
      await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Zapret не включён; транзакция откатилась или ждёт устройство.'); }
    finally { setBusy(false); }
  }
  return <section class="grid">
    <Card title="Zapret">
      <div class="row"><b>{component?.installed ? `Установлен ${component.version ?? ''}` : 'Не установлен'}</b><span>{component?.service_state ?? 'service unavailable'}</span><small>{component?.health_ready ? 'Health check пройден' : component?.health_reason ?? 'Готов к установке'}</small></div>
      {status?.active_profile?.profile_id && <div class="zapret-active-profile"><div class="row"><b>Настроено</b><span>{zapretProfileLabel(status.active_profile)}</span><small>{status.active_profile.available === false ? 'Профиль не найден в закреплённом каталоге' : 'Сейчас используется'}</small></div>{status?.fallback_profile?.profile_id && <div class="row"><b>Fallback</b><span>{zapretProfileLabel(status.fallback_profile)}</span><small>{status.fallback_profile.available === false ? 'Профиль не найден в закреплённом каталоге' : 'Следующий разрешённый профиль'}</small></div>}</div>}
      {role === 'administrator' && !component?.installed && <button class="primary" disabled={busy || mutationLocked} onClick={install}>{busy ? 'Устанавливаю…' : 'Установить Zapret'}</button>}
      {component?.installed && role === 'administrator' && <div class="change-editor">
        <label><span>Домен для подбора стратегии</span><input class="mono" value={testDomain} onInput={(event) => { setTestDomain((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
         {calibration?.state === 'running' ? <button disabled={busy || mutationLocked} onClick={cancelCalibration}>Остановить тест</button> : <div class="actions">
           <button class="primary" disabled={busy || mutationLocked || !testDomain.trim()} onClick={() => void startCalibration('quick')}>Быстрый тест Zapret</button>
           <button disabled={busy || mutationLocked || !testDomain.trim()} onClick={() => setShowExhaustive(true)}>Полный подбор стратегий</button>
        </div>}
        {showExhaustive && calibration?.state !== 'running' && <div class="warning-panel" role="alert">
          <b>Глубокий перебор — аварийно-длинная операция</b>
          <p>Будет проверено большое количество комбинаций upstream Zapret. Это может занять до 6 часов. Запускайте полный подбор только если быстрый тест не нашёл рабочую стратегию.</p>
           <div class="actions"><button class="primary" disabled={busy || mutationLocked} onClick={() => void startCalibration('exhaustive')}>Запустить полный подбор</button><button disabled={busy} onClick={() => setShowExhaustive(false)}>Отмена</button></div>
        </div>}
        <small>Параллельность: {textValue(calibration?.concurrency, '1')}. {textValue(calibration?.concurrency_reason, 'Общие nft/NFQUEUE ресурсы upstream требуют последовательного прогона.')}</small>
      </div>}
      {message && <div class="action-status"><p>{message}</p>{message.includes('черновик') && <button type="button" onClick={() => navigate('Операции')}>Открыть центр операций</button>}</div>}
    </Card>
    {calibration && calibration.state !== 'idle' && <Card title="Подбор стратегии">
      <div class="row"><b>{humanStatus(calibration.state)}</b><span>{calibration.mode === 'exhaustive' ? 'полный подбор' : 'быстрый тест'} · {textValue(calibration.scan_level, 'quick')}</span><small>{textValue(calibration.domain, 'домен не указан')} · {calibration.duration_ms ? `${Math.round(calibration.duration_ms / 1000)} сек` : 'идёт'}</small></div>
      {calibration.state === 'running' && <div class="row"><b>Проверено вариантов</b><span>{calibration.checks_completed ?? 0}{calibration.checks_total ? ` / ${calibration.checks_total}` : ''}</span><small>{calibration.mode === 'exhaustive' ? 'Upstream force scan; точное число зависит от версии и платформы.' : 'Curated-набор; каждая попытка должна вернуть path evidence и cleanup proof.'}</small></div>}
      {calibration.mode === 'quick' && calibration.state !== 'running' && <div class="row"><b>Доказательство пути</b><span>{calibration.path_verified ? 'Path verified' : 'Не подтверждено'}</span><small>{textValue(calibration.evidence_level, 'нет evidence')}</small></div>}
      {calibration.error && <p class="reason">{textValue(calibration.error_code, 'calibration_error')}: {textValue(calibration.error, 'Ошибка калибровки')}</p>}
      {(calibration.attempts ?? []).map((attempt, index) => <div class="row" key={`${attempt.profile_id}:${index}`}><b>{zapretProfileLabel(attempt, `Стратегия ${index + 1}`)}</b><span>{textValue(attempt.result, 'INFRA_ERROR')}</span><small>{textValue(attempt.target, 'target')} · {textValue(attempt.protocol, 'protocol')} · {attempt.path_verified ? 'path verified' : 'path не подтверждён'} · {attempt.cleanup_verified ? 'cleanup OK' : 'cleanup не подтверждён'}</small></div>)}
      <h4>Рабочие стратегии — появляются сразу</h4>
      {(calibration.working_strategies ?? []).length
        ? (calibration.working_strategies ?? []).map((strategy, index) => <div class="row" key={`${index}:${textValue(strategy, 'strategy')}`}><b>Рабочая #{index + 1}</b><span>{zapretProfileLabel({ profile_id: strategy })}</span></div>)
        : (calibration.candidates ?? []).length
          ? (calibration.candidates ?? []).map((candidate) => <div class="row" key={`verified:${candidate.profile_id}`}><b>Path verified</b><span>{zapretProfileLabel(candidate)}</span><small>Эта стратегия прошла проверку через собственную NFQUEUE и может быть включена отдельным черновиком.</small></div>)
          : <p>Пока ни одна стратегия не прошла проверку.</p>}
      {(calibration.candidates ?? []).map((candidate, index) => <div class="row" key={candidate.profile_id}><b>{zapretProfileLabel(candidate, `Кандидат ${index + 1}`)}</b><span>{candidate.provider} {candidate.provider_version}</span><small>{candidate.transports.join(' + ')} · {candidate.occurrences ?? 0} подтверждений</small></div>)}
      {calibration.recommended_profile_id && <p class="action-status">Рекомендован: <span>{zapretProfileLabel({ profile_id: calibration.recommended_profile_id })}</span> <span class="mono">({calibration.recommended_profile_id})</span>. Именно он будет привязан при явном включении ниже.</p>}
      <h4>Живой лог</h4>
      <pre>{(calibration.log_tail ?? []).join('\n') || 'blockcheck ещё не успел вывести данные'}</pre>
      {calibration.activation_required && <p>Профили записаны в проверенный каталог. Выбор не применяется молча: создай отдельный черновик, проверь diff и запусти транзакцию в центре операций.</p>}
    </Card>}
    {component?.installed && <Card title="Явное включение маршрута">
      <p>Установка бинарника и включение маршрута — разные операции. Apply проверит NFQUEUE, data path и подтвердится только через штатную транзакцию.</p>
       {role === 'administrator' && <div class="actions"><button disabled={busy || !configVersion} onClick={check}>{busy ? 'Проверяю…' : 'Проверить перед черновиком'}</button><button class="primary" disabled={busy || mutationLocked || !checked || !configVersion} onClick={activate}>Создать черновик Zapret</button></div>}
      <details><summary>Advanced · закреплённый источник</summary><div class="change-editor">
        <label><span>HTTPS source</span><input class="mono" value={sourceURL} onInput={(event) => { setSourceURL((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
        <label><span>Версия</span><input class="mono" value={version} onInput={(event) => { setVersion((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
        <label><span>SHA-256</span><input class="mono" value={sha256} onInput={(event) => { setSHA256((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
      </div></details>
    </Card>}
    {report && <Card title="Результат preflight"><div class="row"><b>{report.dry_run ? 'dry-run OK' : 'dry-run FAIL'}</b><span>{report.architecture}</span><small>NFQUEUE: {report.kernel_support}</small></div><div class="row"><b>{report.provider_version}</b><span>{report.test_domain}</span><small>{report.source_pinned ? 'immutable source pinned' : 'source не закреплён'}</small></div></Card>}
    <RouteType title="Zapret route" type="zapret" routes={routes} />
  </section>;
}

export function SmartDNS({
  configVersion,
  role,
  mutationLocked,
  refresh,
  navigate
}: {
  configVersion: number;
  role: SessionInfo['role'];
  mutationLocked: boolean;
  refresh: () => Promise<void>;
  navigate: (screen: string) => void;
}) {
  const [status, setStatus] = useState<any>(null);
  const [error, setError] = useState('');
  const [addMode, setAddMode] = useState<'single' | 'pair'>('single');
  const [resolvers, setResolvers] = useState([{ name: '', primary: '', fallback: '' }]);
  const [testDomain, setTestDomain] = useState('example.com');
  const [validations, setValidations] = useState<any[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [removeConfirm, setRemoveConfirm] = useState('');
  const [draftInitialized, setDraftInitialized] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    getSmartDNS(controller.signal)
      .then(setStatus)
      .catch((reason) => {
        if (reason instanceof Error && reason.name === 'AbortError') return;
        setError(reason instanceof Error ? reason.message : 'Smart DNS недоступен');
      });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    if (!status || draftInitialized) return;
    setResolvers(resolverDraftsFromStatus(status));
    setDraftInitialized(true);
  }, [status, draftInitialized]);
  useEffect(() => {
    if (!smartDNSOperationActive(status?.automatic_operation)) return;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      getSmartDNS(controller.signal)
        .then(setStatus)
        .catch((reason) => {
          if (reason instanceof Error && reason.name === 'AbortError') return;
          setError(reason instanceof Error ? reason.message : 'Smart DNS недоступен');
        });
    }, 1000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [status?.automatic_operation?.id, status?.automatic_operation?.state]);
  async function save() {
    if (mutationLocked) { setMessage('Smart DNS нельзя изменить до подтверждения recovery state.'); return; }
    let values;
    try {
      if (addMode === 'pair' && resolvers.some((value) => value.primary.trim() && !value.fallback.trim())) {
        setMessage('В режиме «Связка» у каждой карточки должны быть основной и запасной резолверы.');
        return;
      }
      values = resolvers
        .filter((value) => value.primary.trim())
        .map((value) => {
          const primary = parseResolverInput(value.primary);
          const fallback = addMode === 'pair' && value.fallback.trim() ? parseResolverInput(value.fallback) : undefined;
          return {
            name: value.name.trim() || undefined,
            ...primary,
            ...(fallback ? { fallback_ip: fallback.ip, fallback_port: fallback.port } : {})
          };
        });
    } catch (reason) {
      const info = errorInfo(reason);
      setMessage(`${info.code}: Проверь IP и необязательный порт.`);
      return;
    }
    if (!values.length) {
      setMessage('Укажи хотя бы один публичный IP резолвера и порт.');
      return;
    }
    if (!testDomain.trim()) {
      setMessage('Укажи домен для DNS и HTTP/TLS проверки.');
      return;
    }
    setBusy(true);
    setMessage('Создаю проверяемое изменение Smart DNS…');
    try {
      const result = await configureSmartDNS(values, testDomain.trim(), configVersion, true);
      setValidations(result.validations ?? []);
      const nextStatus = await getSmartDNS();
      setStatus(nextStatus);
      setResolvers(resolverDraftsFromStatus(nextStatus));
      setMessage(result.auto_apply_started
        ? `Smart DNS проверен. Автоматическое применение для ${result.endpoint_count} резолверов запущено в фоне; результат появится в центре операций.`
        : `Smart DNS проверен. Создан черновик для ${result.endpoint_count} резолверов; автоматическое продолжение не запущено.`);
      await refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : 'Smart DNS не прошёл проверку. Предыдущая конфигурация сохранена.');
    } finally {
      setBusy(false);
    }
  }
  async function removeResolver(routeTag: string) {
    if (removeConfirm !== routeTag) {
      setRemoveConfirm(routeTag);
      return;
    }
    if (mutationLocked) { setMessage('Smart DNS нельзя изменить до подтверждения recovery state.'); return; }
    setBusy(true);
    setMessage('Удаляю карточку Smart DNS через безопасную транзакцию…');
    try {
      const result = await removeSmartDNS(routeTag, configVersion);
      setRemoveConfirm('');
      setMessage(result.auto_apply_started ? 'Карточка удалена. Изменение применяется в фоне.' : 'Карточка удалена из очереди, но автоматическое применение не запустилось.');
      setStatus(await getSmartDNS());
      await refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : 'Карточку Smart DNS не удалось удалить. Активная конфигурация сохранена.');
    } finally {
      setBusy(false);
    }
  }
  async function moveResolver(routeTag: string, direction: -1 | 1) {
    if (mutationLocked) { setMessage('Smart DNS нельзя изменить до подтверждения recovery state.'); return; }
    const ordered = (status.routes ?? []).filter((route: any) => route.resolver_configured).sort((left: any, right: any) => (left.order ?? 0) - (right.order ?? 0));
    const index = ordered.findIndex((route: any) => route.tag === routeTag);
    const nextIndex = index + direction;
    if (index < 0 || nextIndex < 0 || nextIndex >= ordered.length) return;
    [ordered[index], ordered[nextIndex]] = [ordered[nextIndex], ordered[index]];
    setBusy(true);
    setMessage('Обновляю порядок failover…');
    try {
      const result = await reorderSmartDNS(ordered.map((route: any) => route.tag), configVersion);
      setMessage(result.auto_apply_started ? 'Порядок обновляется в фоне.' : 'Порядок поставлен в очередь.');
      setStatus(await getSmartDNS());
      await refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : 'Порядок Smart DNS не удалось изменить.');
    } finally {
      setBusy(false);
    }
  }
  if (error) return <Generic title="Smart DNS" text={error} />;
  if (!status) return <Generic title="Smart DNS" text="Загружаю состояние…" />;
  return (
    <section class="grid">
      <Card title="Состояние Smart DNS">
        <div class="row"><b>{status.configured_count ?? 0}</b><span>DNS-серверов настроено</span><small>{status.ready ?? 0} готовы к выбору для GEO-сервисов</small></div>
        {status.automatic_operation && smartDNSOperationActive(status.automatic_operation) && <p class="action-status">Smart DNS проверяется и применяется автоматически: {smartDNSOperationLabel(status.automatic_operation)}. Подробности появятся в центре операций.</p>}
        {status.configured && !status.ready && !smartDNSOperationActive(status.automatic_operation) && <p class="action-status">DNS-серверы сохранены, но маршрут пока не подтверждён. {humanSmartDNSReason(status.routes?.[0]?.health?.last_reason)}</p>}
        {status.automatic_operation && !smartDNSOperationActive(status.automatic_operation) && status.automatic_operation.state !== 'committed' && <p class="action-status">Последнее автоматическое применение: {smartDNSOperationLabel(status.automatic_operation)}. Текущая активная конфигурация не заменялась без подтверждённой транзакции.</p>}
        <h4>Проверка успеха</h4>
        <div class="chips">{(status.success_contract ?? []).map((item: string) => <span class="chip">{item}</span>)}</div>
        {role === 'administrator' && (
          <div class="smart-dns-editor">
            <div class="resolver-mode" role="group" aria-label="Режим добавления DNS">
              <button type="button" class={addMode === 'single' ? 'selected' : ''} onClick={() => setAddMode('single')}>Один DNS-сервер</button>
              <button type="button" class={addMode === 'pair' ? 'selected' : ''} onClick={() => setAddMode('pair')}>Связка DNS-серверов</button>
            </div>
            {resolvers.map((resolver, index) => <div class="resolver-draft" key={index}>
              <label><span>Имя карточки</span><input value={resolver.name} placeholder={`Smart DNS #${index + 1}`} onInput={(event) => {
                const next = [...resolvers]; next[index] = { ...next[index], name: (event.target as HTMLInputElement).value }; setResolvers(next);
              }} /></label>
              <label><span>{addMode === 'pair' ? 'Основной резолвер' : 'DNS-сервер'}</span><input class="mono" value={resolver.primary} placeholder="1.1.1.1" onInput={(event) => {
                const next = [...resolvers]; next[index] = { ...next[index], primary: (event.target as HTMLInputElement).value }; setResolvers(next);
              }} /></label>
              {addMode === 'pair' && <label><span>Запасной резолвер</span><input class="mono" value={resolver.fallback} placeholder="8.8.4.4" onInput={(event) => {
                const next = [...resolvers]; next[index] = { ...next[index], fallback: (event.target as HTMLInputElement).value }; setResolvers(next);
              }} /></label>}
              {index > 0 && <button type="button" onClick={() => setResolvers((items) => items.filter((_, itemIndex) => itemIndex !== index))}>Убрать карточку</button>}
            </div>)}
            {resolvers.length < 16 && <button type="button" onClick={() => setResolvers((items) => [...items, { name: '', primary: '', fallback: '' }])}>Добавить DNS-карточку</button>}
            <small>Порт необязателен: по умолчанию 53. В режиме «Связка» основной адрес проверяется первым, затем резервный.</small>
            <label><span>Домен для DNS + HTTP/TLS</span><input class="mono" value={testDomain} placeholder="example.com" onInput={(event) => setTestDomain((event.target as HTMLInputElement).value)} /></label>
            <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={save}>
              {busy ? 'Проверяю…' : 'Добавить и проверить endpoint'}
            </button>
            {mutationLocked && <p class="action-status">Настройка Smart DNS временно заблокирована recovery fence.</p>}
            {message && <div class={message.includes('применён') ? 'action-status ok' : 'action-status'}><p>{message}</p>{message.includes('черновик') && <button type="button" onClick={() => navigate('Операции')}>Открыть центр операций</button>}</div>}
          </div>
        )}
      </Card>
      {validations.map((validation: any) => <Card title={`Проверка ${validation.endpoint}`} key={validation.endpoint}>
        <div class="row"><b>{validation.udp?.safe ? 'UDP OK' : 'UDP FAIL'}</b><b>{validation.tcp?.safe ? 'TCP OK' : 'TCP FAIL'}</b><b>{validation.tls_ok ? 'TLS OK' : 'TLS FAIL'}</b><b>{validation.http_ok ? `HTTP ${validation.http_status}` : 'HTTP FAIL'}</b></div>
        <div class="chips">{(validation.addresses ?? []).map((address: string) => <span class="chip mono">{address}</span>)}</div>
        <small>Соединение: {validation.connected_ip || 'не установлено'} · Host/SNI: {validation.domain}</small>
      </Card>)}
      <Card title="Резолверы и порядок failover">
        <div class="resolver-table" role="table" aria-label="Smart DNS резолверы">
          {(status.routes ?? []).filter((route: any) => route.resolver_configured).map((route: any, index: number, configured: any[]) => <div class="resolver-table-row" role="row" key={route.tag}>
            <b role="cell">#{index + 1}</b>
            <strong role="cell">{textValue(route.name, textValue(route.tag, `Smart DNS #${index + 1}`))}</strong>
            <span role="cell" class="mono">{resolverEndpointText(route.resolver_ip, route.resolver_port)}</span>
            {route.fallback_resolver_ip && <span role="cell" class="mono">→ {resolverEndpointText(route.fallback_resolver_ip, route.fallback_resolver_port)}</span>}
            <StatusBadge value={statusWithFreshness(route.status || 'не проверен', route)} />
            <span class="resolver-actions">
              <button type="button" disabled={busy || mutationLocked || index === 0} onClick={() => moveResolver(route.tag, -1)} aria-label={`Поднять ${textValue(route.name, route.tag)}`}>↑</button>
              <button type="button" disabled={busy || mutationLocked || index === configured.length - 1} onClick={() => moveResolver(route.tag, 1)} aria-label={`Опустить ${textValue(route.name, route.tag)}`}>↓</button>
              <button type="button" disabled={busy || mutationLocked} onClick={() => removeResolver(route.tag)}>{removeConfirm === route.tag ? 'Подтвердить удаление' : 'Удалить'}</button>
            </span>
          </div>)}
        </div>
        <small>Сначала используется верхняя карточка. Если её проверка недоступна, FlintRoute переходит к следующей; порядок не меняет глобальный выбор между Smart DNS, VLESS и другими типами маршрутов.</small>
      </Card>
      {(status.routes ?? []).filter((route: any) => route.resolver_configured).map((route: any, index: number) => (
        <Card title={textValue(route.name, textValue(route.tag, `Smart DNS #${index + 1}`))} key={textValue(route.tag, 'smart-dns-route')}>
          <div class="row"><RouteBadge type="smart_dns" /><StatusBadge value={statusWithFreshness(route.status || 'не проверен', route)} /><span>приоритет #{index + 1}</span></div>
          <small>Основной: <span class="mono">{resolverEndpointText(route.resolver_ip, route.resolver_port)}</span></small>
          {route.fallback_resolver_ip && <small>Запасной: <span class="mono">{resolverEndpointText(route.fallback_resolver_ip, route.fallback_resolver_port)}</span></small>}
          {route.last_validation && <div class="row"><b>{route.last_validation.result?.udp?.safe ? 'UDP OK' : 'UDP FAIL'}</b><b>{route.last_validation.result?.tcp?.safe ? 'TCP OK' : 'TCP FAIL'}</b><b>{route.last_validation.result?.tls_ok ? 'TLS OK' : 'TLS FAIL'}</b><b>{route.last_validation.result?.http_ok ? `HTTP ${route.last_validation.result.http_status}` : 'HTTP FAIL'}</b></div>}
          {route.fallback_validation && <div class="row"><b>Запасной UDP {route.fallback_validation.result?.udp?.safe ? 'OK' : 'FAIL'}</b><b>TCP {route.fallback_validation.result?.tcp?.safe ? 'OK' : 'FAIL'}</b></div>}
          {route.status === 'validated_idle' && <p>Карточка проверена и готова к автоматическому failover.</p>}
          {route.status !== 'validated_idle' && route.health?.last_reason && <p>{humanSmartDNSReason(textValue(route.health.last_reason, 'Причина не указана'))}</p>}
          <small>{route.connect_to_resolved_ip ? 'HTTP/TLS проверяется по адресу из ответа DNS' : 'Маршрут выключен: резолвер ещё не проверен'}</small>
          <small>Conditional DNS, не VPN.</small>
        </Card>
      ))}
    </section>
  );
}
