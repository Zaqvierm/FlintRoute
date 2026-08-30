import type {
  ChangeSet,
  DiscoveryStatus,
  EventItem,
  OnboardingState,
  RevisionSummary,
  SessionInfo
} from '../api';
import { Generic } from '../components/ui';
import { DeviceCard, Devices, NetworkMap, OverviewScreen } from '../features/network';
import { Changes, Policies, Routes, ServiceGroup, Services } from '../features/rules';
import { SmartDNS, Zapret } from '../features/route-integrations';
import {
  Components,
  DecisionFlow,
  Diagnostics,
  Discovery,
  ExternalSOCKS,
  LoginScreen,
  Recovery,
  Security,
  Settings,
  TGWS,
  Telegram,
  Traffic,
  type TrafficView
} from '../features/system';
import { Vless } from '../features/vless';
import { SetupScreen } from '../features/setup';
import { notFoundScreen } from './routes';

export type ContentProps = {
  screen: string;
  session: SessionInfo;
  configVersion: number;
  overview: Record<string, unknown>;
  mutationLocked: boolean;
  onboarding: OnboardingState | null;
  topology: Record<string, unknown>;
  devices: Array<Record<string, unknown>>;
  services: Array<Record<string, unknown>>;
  discovery: DiscoveryStatus | null;
  routes: Array<Record<string, unknown>>;
  traffic: TrafficView;
  events: EventItem[];
  changes: ChangeSet[];
  security: unknown;
  securitySummary: unknown;
  system: unknown;
  diagnostics: unknown;
  lifecycle: unknown;
  storage: unknown;
  settings: unknown;
  backups: unknown;
  revisions: RevisionSummary | null;
  privacyHidden: boolean;
  onTogglePrivacy: () => Promise<void>;
  refresh: (hideAddresses?: boolean) => Promise<void>;
  onboardingAction: (step: string, action: 'skip' | 'accept' | 'automatic' | 'complete') => Promise<OnboardingState>;
  navigate: (screen: string) => void;
};

export function Content(props: ContentProps) {
  switch (props.screen) {
    case 'Вход':
      return <LoginScreen />;
    case 'Первичная настройка':
    case 'Быстрая настройка':
      return <SetupScreen {...props} />;
    case 'Обзор':
      return <OverviewScreen {...props} />;
    case 'Карта сети':
      return <NetworkMap topology={props.topology} devices={props.devices} system={props.system} expanded />;
    case 'Трафик':
      return <Traffic data={props.traffic} />;
    case 'Устройства':
      return <Devices devices={props.devices} events={props.events} />;
    case 'Карточка устройства':
      return <DeviceCard device={props.devices[0]} />;
    case 'Сервисы':
      return <Services services={props.services} configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'Discovery':
      return <Discovery data={props.discovery} configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} />;
    case 'Группа сервиса':
      return <ServiceGroup service={props.services[0]} />;
    case 'Политики: таблица':
      return <Policies mode="table" />;
    case 'Политики: доска':
      return <Policies mode="board" />;
    case 'Advanced':
      return <Changes changes={props.changes} refresh={props.refresh} role={props.session.role} configVersion={props.configVersion} mutationLocked={props.mutationLocked} navigate={props.navigate} mode="developer" />;
    case 'Операции':
      return <Changes changes={props.changes} refresh={props.refresh} role={props.session.role} configVersion={props.configVersion} mutationLocked={props.mutationLocked} navigate={props.navigate} mode="operations" />;
    case 'Маршруты':
      return <Routes routes={props.routes} navigate={props.navigate} />;
    case 'Компоненты':
      return <Components role={props.session.role} mutationLocked={props.mutationLocked} navigate={props.navigate} />;
    case 'VLESS-серверы':
      return <Vless routes={props.routes} configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'Smart DNS':
      return <SmartDNS configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'Zapret':
      return <Zapret routes={props.routes} configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'External SOCKS':
      return <ExternalSOCKS configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'TG WS Proxy':
      return <TGWS role={props.session.role} mutationLocked={props.mutationLocked} navigate={props.navigate} />;
    case 'Telegram':
      return <Telegram role={props.session.role} mutationLocked={props.mutationLocked} events={props.events} />;
    case 'Поток решений':
      return <DecisionFlow events={props.events} discovery={props.discovery} />;
    case 'Диагностика':
      return <Diagnostics system={props.system} diagnostics={props.diagnostics} lifecycle={props.lifecycle} storage={props.storage} />;
    case 'Безопасность':
      return <Security data={props.security} summary={props.securitySummary} />;
    case 'Ревизии и recovery':
      return <Recovery revisions={props.revisions} backups={props.backups} lifecycle={props.lifecycle} />;
    case 'Удалённые клиенты':
      return <Generic title="Удалённые клиенты" text="Профили удалённого доступа, лимиты, срок действия и политика маршрутизации." />;
    case 'Настройки':
      return <Settings data={props.settings} privacyHidden={props.privacyHidden} onTogglePrivacy={props.onTogglePrivacy} mutationLocked={props.mutationLocked} role={props.session.role} />;
    case 'Обновление':
      return <Generic title="Обновление" text="Проверка версии, подпись выпуска, checksum, staged install и rollback." />;
    case 'Резервное копирование':
      return <Generic title="Резервное копирование и откат" text="Резервные копии конфигурации, секретов по явному выбору, nft/dnsmasq/fw4 snapshots." />;
    case notFoundScreen:
      return <Generic title="Страница не найдена" text="Такого раздела FlintRoute нет. Вернись в обзор или выбери раздел в меню." />;
    default:
      return <OverviewScreen {...props} />;
  }
}
