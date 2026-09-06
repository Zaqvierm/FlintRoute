import { useEffect, useRef, useState } from 'preact/hooks';
import type { EventItem } from '../api';
import { asArray, asRecord, formatDateTime, groupServices, isDecisionEvent, textValue, toDecisionCard } from '../view-models';
import {
  Card,
  DetailDrawer,
  DisabledActions,
  EmptyState,
  EntityCard,
  EventRow,
  Grid,
  InfoGrid,
  PageHeader,
  RawDisclosure,
  StatusBadge,
  StatusLine,
  statusWithFreshness
} from '../components/ui';

export function OverviewScreen({ overview, topology, devices, system, services, events }: any) {
  const decisions: Array<ReturnType<typeof toDecisionCard>> = events.filter(isDecisionEvent).slice(-4).reverse().map(toDecisionCard);
  return (
    <section class="dashboard overview-screen">
      <NetworkMap topology={topology} devices={devices} system={system} />
      <div class="right-panel overview-summary">
        <Card title="Сейчас в сети">
          <div class="metric"><b>{devices.filter((device: any) => device.connected).length}</b><span>активных устройств</span></div>
          <div class="metric"><b>{groupServices(services).length}</b><span>известных сервисов</span></div>
        </Card>
        <Card title="Маршрутизация">
          <StatusLine label="Интернет" value={overview.internet} />
          <StatusLine label="Data plane" value={overview.data_plane} />
          <StatusLine label="DNS" value={overview.dns} />
        </Card>
        <Card title="Последние решения">
          {decisions.map((decision) => <div class="compact-decision" key={decision.id}><b>{decision.domain}</b><span>{decision.device}</span><StatusBadge value={decision.route} /></div>)}
          {!decisions.length && <EmptyState title="Решений пока нет" text="Они появятся после наблюдения за DNS и маршрутизацией." />}
        </Card>
      </div>
    </section>
  );
}

export function NetworkMap({ topology, devices, system, expanded = false }: { topology: any; devices: any[]; system: any; expanded?: boolean }) {
  const [selected, setSelected] = useState<any>(null);
  const [viewportWidth, setViewportWidth] = useState(0);
  const viewportRef = useRef<HTMLDivElement>(null);
  const nodes = asArray(topology?.nodes).map(asRecord);
  const router = nodes.find((n: any) => n.type === 'router');
  const topologyStatus = textValue(topology?.status, 'unavailable').toLowerCase();
  const topologyUnavailable = !router || topologyStatus === 'unavailable' || topologyStatus === 'error';
  const internet = nodes.find((node: any) => node.type === 'internet');
  const wan = nodes.filter((node: any) => node.type === 'wan');
  const ports = nodes.filter((node: any) => node.type === 'ethernet');
  const radios = nodes.filter((node: any) => node.type === 'wifi');
  const online = devices.filter((device) => device.connected);
  const offline = devices.filter((device) => !device.connected);
  const ethernet = online.filter((device) => device.kind === 'ethernet');
  const wifi = online.filter((device) => device.kind === 'wifi');
  const unknown = online.filter((device) => !['ethernet', 'wifi'].includes(device.kind));
  const portCards = buildPortCards(ports, ethernet);
  const branchCount = Math.max(portCards.length, 1);
  const canvasWidth = Math.min(1600, Math.max(1000, branchCount * 190 + 140, viewportWidth));
  const portGap = canvasWidth / (branchCount + 1);
  const portCardWidth = Math.max(110, Math.min(162, portGap - 12));
  const wifiPositions = wifi.map((device, index) => {
    const side = index % 2 === 0 ? -1 : 1;
    const row = Math.floor(index / 2);
    return { device, x: canvasWidth / 2 + side * (310 + (row % 2) * 115), y: 205 + row * 105 };
  });
  const mapHeight = Math.max(650, 360 + Math.ceil(wifi.length / 2) * 105);
  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const updateWidth = () => setViewportWidth(Math.floor(viewport.clientWidth));
    updateWidth();
    const observer = new ResizeObserver(updateWidth);
    observer.observe(viewport);
    return () => observer.disconnect();
  }, []);
  const wanLabel = wan.length
    ? wan.map((node) => `${textValue(node.interface, 'WAN')} · ${formatLinkSpeed(node.speed_mbps)}`).join(' / ')
    : 'WAN не определён';
  return (
    <section class={`network-map ${expanded ? 'expanded' : ''}`}>
      <PageHeader title="Карта сети" text="Связи строятся по DHCP, neighbour table, bridge FDB и данным Wi‑Fi станций. Неизвестное не угадывается." />
      {topologyUnavailable && <div class="warning-panel" role="status"><b>Карта сети пока недоступна</b><p>{textValue(topology?.reason, 'Backend не вернул topology snapshot. Повтори загрузку после восстановления platform provider.')}</p><small>Источник: {textValue(topology?.source, 'неизвестен')} · состояние: {textValue(topology?.status, 'unavailable')}</small></div>}
      <div class="network-map-scroll" ref={viewportRef}>
        <div class="topology-canvas" style={{ width: `${canvasWidth}px`, height: `${mapHeight}px` }}>
          <svg class="topology-wires" viewBox={`0 0 ${canvasWidth} ${mapHeight}`} aria-hidden="true">
            <path class="map-wire wan-wire" d={`M ${canvasWidth / 2} 91 L ${canvasWidth / 2} 154`} />
            {portCards.length > 0 && <>
              <path class="map-wire" d={`M ${canvasWidth / 2} 286 L ${canvasWidth / 2} 365`} />
              <path class="map-wire" d={`M ${portGap} 365 L ${canvasWidth - portGap} 365`} />
              {portCards.map((card, index) => <path class="map-wire" key={`port-wire-${card.id}`} d={`M ${portGap * (index + 1)} 365 L ${portGap * (index + 1)} 410`} />)}
            </>}
            {wifiPositions.map(({ device, x, y }) => {
              const fromX = canvasWidth / 2 + (x < canvasWidth / 2 ? -66 : 66);
              const controlX = (fromX + x) / 2;
              return <path class="map-wire wifi-wire" key={`wifi-wire-${device.id}`} d={`M ${fromX} 220 C ${controlX} 220, ${controlX} ${y}, ${x} ${y}`} />;
            })}
          </svg>
          <div class="map-node map-internet" style={{ left: `${canvasWidth / 2}px`, top: '54px' }}>
            <span class="map-icon"><TopologyIcon kind="globe" /></span><div><b>Интернет</b><small>{wanLabel}</small></div><StatusBadge value={internet?.status ?? topology.status} />
          </div>
          <button class="map-node map-router" style={{ left: `${canvasWidth / 2}px`, top: '220px' }} onClick={() => setSelected({ type: 'router', ...router, ...system })}>
            <span class="router-glyph"><TopologyIcon kind="router" /></span>
            <b>{textValue(system?.hostname ?? router?.hostname ?? router?.label, 'OpenWrt router')}</b>
            <small>{textValue(system?.model ?? router?.model, 'Модель не определена')}</small>
          </button>
          {portCards.map((card, index) => <button class="map-node map-port" key={card.id} style={{ left: `${portGap * (index + 1)}px`, top: '468px', width: `${portCardWidth}px` }} onClick={() => setSelected(card.device ?? { type: 'interface', ...card.port })}>
            <div class="map-port-chips"><span>{textValue(card.port.interface, 'Ethernet')}</span><em>{formatLinkSpeed(card.port.speed_mbps)}</em></div>
            <span class="port-glyph"><TopologyIcon kind={card.device ? topologyDeviceIcon(card.device) : 'ethernet'} /></span>
            <b>{card.device ? textValue(card.device.name, 'Неизвестное устройство') : 'Свободно'}</b>
            <small>{card.device ? deviceAddress(card.device, 'ip') : textValue(card.port.status)}</small>
            {card.extra > 0 && <small>Ещё устройств: {card.extra}</small>}
          </button>)}
          {wifiPositions.map(({ device, x, y }, index) => <button class="map-node map-wifi" key={device.id} style={{ left: `${x}px`, top: `${y}px`, animationDelay: `${(index % 5) * -0.7}s` }} onClick={() => setSelected(device)}>
            <span class="wifi-glyph"><TopologyIcon kind={topologyDeviceIcon(device)} /></span>
            <em>{wifiBandLabel(device, radios)}</em>
            <b>{textValue(device.name, 'Wi‑Fi устройство')}</b>
            <small>{device.rssi ? `${device.rssi} dBm` : textValue(device.ssid ?? device.interface, 'Сигнал не определён')}</small>
          </button>)}
          {unknown.length > 0 && <div class="map-unknown" style={{ left: '18px', bottom: '44px' }}>
            <b>Тип подключения не определён</b>
            {unknown.slice(0, 6).map((device) => <button key={device.id} onClick={() => setSelected(device)}>{textValue(device.name, 'Устройство')}</button>)}
          </div>}
          <div class="map-legend"><span><i />Ethernet</span><span class="wifi"><i />Wi‑Fi</span></div>
          <div class="map-stamp">Обновлено: <span class="mono">{formatDateTime(topology.collected_at)}</span></div>
        </div>
      </div>
      <div class="network-map-mobile">
        <div class="topology-mobile-node"><TopologyIcon kind="globe" /><div><b>Интернет</b><small>{wanLabel}</small></div><StatusBadge value={internet?.status ?? topology.status} /></div>
        <div class="topology-mobile-link" />
        <button class="topology-mobile-node router" onClick={() => setSelected({ type: 'router', ...router, ...system })}>
          <TopologyIcon kind="router" /><div><b>{textValue(system?.hostname ?? router?.hostname ?? router?.label, 'OpenWrt router')}</b><small>{textValue(system?.model ?? router?.model, 'Модель не определена')}</small></div><StatusBadge value={topology.status} />
        </button>
        <div class="topology-mobile-groups">
          <section class="topology-mobile-group"><h3>Проводные устройства <small>{ethernet.length}</small></h3>{ethernet.length ? ethernet.map((device) => <button class="topology-mobile-device" key={device.id} onClick={() => setSelected(device)}><TopologyIcon kind={topologyDeviceIcon(device)} /><span><b>{textValue(device.name, 'Устройство')}</b><small>{deviceAddress(device, 'ip')} · {textValue(device.interface, 'Интерфейс не определён')}</small></span><StatusBadge value={device.connected ? 'online' : 'offline'} /></button>) : <EmptyState title="Нет проводных устройств" text="Когда FDB и DHCP подтвердят устройство, оно появится здесь." />}</section>
          <section class="topology-mobile-group wifi-group"><h3>Wi‑Fi устройства <small>{wifi.length}</small></h3>{wifi.length ? wifi.map((device) => <button class="topology-mobile-device" key={device.id} onClick={() => setSelected(device)}><TopologyIcon kind={topologyDeviceIcon(device)} /><span><b>{textValue(device.name, 'Wi‑Fi устройство')}</b><small>{deviceAddress(device, 'ip')} · {wifiBandLabel(device, radios)}</small></span><StatusBadge value={device.connected ? 'online' : 'offline'} /></button>) : <EmptyState title="Нет Wi‑Fi устройств" text="Данные появятся после подключения станции." />}</section>
          {unknown.length > 0 && <section class="topology-mobile-group"><h3>Тип подключения неизвестен <small>{unknown.length}</small></h3>{unknown.map((device) => <button class="topology-mobile-device unknown" key={device.id} onClick={() => setSelected(device)}><TopologyIcon kind="desktop" /><span><b>{textValue(device.name, 'Устройство')}</b><small>{deviceAddress(device, 'ip')} · тип не определён</small></span><StatusBadge value={device.connected ? 'online' : 'offline'} /></button>)}</section>}
        </div>
      </div>
      {offline.length > 0 && <div class="recent-offline"><b>Недавно отключились</b>{offline.slice(0, 6).map((device) => <button key={device.id} onClick={() => setSelected(device)}>{textValue(device.name, 'Устройство')}</button>)}</div>}
      <p class="source-note">Источник: {textValue(topology.source)} · данные {topology.freshness === 'live' ? 'с роутера' : textValue(topology.freshness)}</p>
      <DetailDrawer title={selected?.type === 'router' ? 'Роутер' : 'Устройство'} open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected?.type === 'router' ? <RouterDetails router={selected} /> : selected?.type === 'interface' ? <InterfaceDetails value={selected} /> : <DeviceDetails device={selected} />}
      </DetailDrawer>
    </section>
  );
}

export type TopologyIconKind = 'globe' | 'router' | 'ethernet' | 'desktop' | 'laptop' | 'phone' | 'tablet' | 'tv' | 'nas' | 'speaker';

export function topologyDeviceIcon(device: any): TopologyIconKind {
  const declared = textValue(device?.device_type ?? device?.icon, '').toLowerCase();
  if (['desktop', 'laptop', 'phone', 'tablet', 'tv', 'nas', 'speaker'].includes(declared)) return declared as TopologyIconKind;
  return 'desktop';
}

export function TopologyIcon({ kind }: { kind: TopologyIconKind }) {
  const common = { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true };
  switch (kind) {
    case 'globe': return <svg {...common}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.6 2.7 2.6 15.3 0 18M12 3c-2.6-2.7-2.6-15.3 0 18" /></svg>;
    case 'router': return <svg {...common}><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7.5 13V8.5M16.5 13V6.5M7 16.5h.01M10.5 16.5h.01" /></svg>;
    case 'phone': return <svg {...common}><rect x="8" y="3.5" width="8" height="17" rx="2" /><path d="M11 17.5h2" /></svg>;
    case 'tablet': return <svg {...common}><rect x="5.5" y="4" width="13" height="16" rx="2" /><path d="M11 17.2h2" /></svg>;
    case 'tv': return <svg {...common}><rect x="3.5" y="6" width="17" height="11" rx="1.5" /><path d="M9 20.5h6" /></svg>;
    case 'nas': return <svg {...common}><rect x="4" y="4.5" width="16" height="7" rx="1.5" /><rect x="4" y="12.5" width="16" height="7" rx="1.5" /><path d="M7.5 8h.01M7.5 16h.01" /></svg>;
    case 'speaker': return <svg {...common}><rect x="7" y="4" width="10" height="16" rx="2" /><circle cx="12" cy="14" r="2.5" /><circle cx="12" cy="8" r="1" /></svg>;
    case 'ethernet': return <svg {...common}><path d="M5 4h14v7H5zM8 11v4m8-4v4M5 15h14v5H5z" /><path d="M8 17.5h.01M11 17.5h.01" /></svg>;
    case 'laptop': return <svg {...common}><rect x="5" y="5" width="14" height="9.5" rx="1.5" /><path d="M3 18.5h18" /></svg>;
    default: return <svg {...common}><rect x="4" y="5" width="16" height="11" rx="1.5" /><path d="M12 16v4M8.5 20h7" /></svg>;
  }
}

function buildPortCards(ports: any[], devices: any[]): Array<{ id: string; port: any; device: any | null; extra: number }> {
  const byInterface = new Map<string, any[]>();
  devices.forEach((device) => {
    const key = textValue(device.interface, '');
    byInterface.set(key, [...(byInterface.get(key) ?? []), device]);
  });
  const cards = ports.map((port) => {
    const key = textValue(port.interface, '');
    const attached = byInterface.get(key) ?? [];
    byInterface.delete(key);
    return { id: textValue(port.id, port.interface), port, device: attached[0] ?? null, extra: Math.max(0, attached.length - 1) };
  });
  byInterface.forEach((attached, interfaceName) => cards.push({ id: `inferred-${interfaceName}`, port: { type: 'interface', interface: interfaceName, status: 'detected', speed_mbps: null }, device: attached[0] ?? null, extra: Math.max(0, attached.length - 1) }));
  return cards;
}

function formatLinkSpeed(raw: unknown): string {
  const speed = Number(raw ?? 0);
  if (!Number.isFinite(speed) || speed <= 0) return 'скорость неизвестна';
  if (speed >= 1000) return `${Number.isInteger(speed / 1000) ? speed / 1000 : (speed / 1000).toFixed(1)} Гбит/с`;
  return `${speed} Мбит/с`;
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${Math.round(value)} Б`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} КБ`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} МБ`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(1)} ГБ`;
}

function wifiBandLabel(device: any, radios: any[]): string {
  const radio = radios.find((item) => item.interface === device.interface);
  return textValue(radio?.ssid ?? device.ssid ?? radio?.radio, 'Wi‑Fi');
}

function deviceAddress(device: any, kind: 'ip' | 'mac'): string {
  if (!device) return 'Адрес отсутствует';
  const raw = device[kind];
  const display = device[`${kind}_display`];
  return textValue(raw ?? display, device.simulation ? 'Simulation: адрес отсутствует' : 'Адрес отсутствует');
}

function InterfaceDetails({ value }: { value: any }) {
  return <><InfoGrid items={[["Интерфейс", value.interface], ["Тип", value.type], ["Master", value.master], ["Статус", value.status], ["Link", formatLinkSpeed(value.speed_mbps)], ["Duplex", value.duplex], ["RX", formatBytes(Number(value.rx_bytes ?? 0))], ["TX", formatBytes(Number(value.tx_bytes ?? 0))]]} /><RawDisclosure value={value} /></>;
}

export function Devices({ devices, events }: { devices: any[]; events: EventItem[] }) {
  const [selected, setSelected] = useState<any>(null);
  const [filter, setFilter] = useState('all');
  const visible = devices.filter((device) => filter === 'all' || (filter === 'online' ? device.connected : device.kind === filter));
  return <section><PageHeader title="Устройства" text="Privacy mode скрывает адреса, но не мешает открыть карточку и понять состояние подключения.">
    <select value={filter} onChange={(event) => setFilter(event.currentTarget.value)}><option value="all">Все</option><option value="online">Только в сети</option><option value="ethernet">Ethernet</option><option value="wifi">Wi‑Fi</option><option value="unknown">Неизвестный тип</option></select>
  </PageHeader><Grid>{visible.map((device) => <DeviceCard device={device} onOpen={() => setSelected(device)} key={device.id} />)}</Grid>
  {!visible.length && <EmptyState title="Устройства не найдены" text="Проверь фильтр или дождись обновления topology data." />}
  <DetailDrawer title={textValue(selected?.name, 'Устройство')} open={Boolean(selected)} onClose={() => setSelected(null)}><DeviceDetails device={selected} events={events} /></DetailDrawer></section>;
}

export function DeviceCard({ device, onOpen }: { device: any; onOpen?: () => void }) {
  if (!device) return <EmptyState title="Устройство не выбрано" text="Открой устройство из списка или карты." />;
  return <EntityCard title={textValue(device.name, 'Неизвестное устройство')} status={statusWithFreshness(device.connected ? 'online' : 'offline', device)} onOpen={onOpen}>
    <div class="entity-summary"><span>{device.kind === 'wifi' ? 'Wi‑Fi' : device.kind === 'ethernet' ? 'Ethernet' : 'Тип не определён'}</span><b class="mono">{deviceAddress(device, 'ip')}</b></div>
    <small>{textValue(device.ssid ?? device.interface, 'Интерфейс не определён')}</small>
    <StatusLine label="Маршрут" value={device.active_route ?? device.policy} />
  </EntityCard>;
}

function DeviceDetails({ device, events = [] }: { device: any; events?: EventItem[] }) {
  if (!device) return null;
  const recent = events.filter((event) => event.device_id === device.id).slice(-5).reverse();
  return <><InfoGrid items={[
    ['Hostname', device.name], ['IP', deviceAddress(device, 'ip')], ['MAC', deviceAddress(device, 'mac')], ['Vendor', device.vendor],
    ['Подключение', device.kind], ['Interface', device.interface], ['SSID', device.ssid], ['RSSI', device.rssi ? `${device.rssi} dBm` : null],
    ['Впервые замечено', formatDateTime(device.first_seen)], ['Последняя активность', formatDateTime(device.last_seen ?? device.collected_at)],
    ['Policy', device.policy], ['Активный маршрут', device.active_route], ['RX', formatBytes(Number(device.rx_bytes ?? 0))], ['TX', formatBytes(Number(device.tx_bytes ?? 0))]
  ]} /><h3>Последние решения</h3>{recent.map((event) => <EventRow event={event} key={event.id} />)}{!recent.length && <EmptyState title="Решений нет" text="Для этого устройства события пока не зарегистрированы." />}<DisabledActions labels={['Переименовать', 'Закрепить IP', 'Лимит', 'Отключить интернет']} /><RawDisclosure value={device} /> </>;
}

function RouterDetails({ router }: { router: any }) {
  return <><InfoGrid items={[["Hostname", router.hostname ?? router.label], ["Модель", router.model], ["Firmware", router.firmware], ["Kernel", router.kernel], ["Platform", router.platform], ["Uptime", router.uptime_seconds ? `${router.uptime_seconds} с` : null]]} /><RawDisclosure value={router} /></>;
}
