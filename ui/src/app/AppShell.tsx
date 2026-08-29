import type { ComponentChildren } from 'preact';
import { navigation } from './routes';
import type { AppNavigation } from './useNavigation';
import { textValue } from '../view-models';

type AppShellProps = Pick<AppNavigation, 'screen' | 'mobileMoreOpen' | 'setMobileMoreOpen' | 'selectScreen'> & {
  system: { hostname?: unknown; model?: unknown } | null;
  children: ComponentChildren;
};

const primaryMobileScreens: Array<[string, string]> = [
  ['Обзор', 'Обзор'],
  ['Карта сети', 'Сеть'],
  ['Сервисы', 'Правила'],
  ['Поток решений', 'Активность']
];

export function AppShell({ screen, mobileMoreOpen, setMobileMoreOpen, selectScreen, system, children }: AppShellProps) {
  return (
    <div class="shell">
      <aside class="side">
        <div class="brand">
          <div class="mark">FR</div>
          <div>
            <strong>{textValue(system?.hostname, 'FlintRoute')}</strong>
            <span>{textValue(system?.model, 'OpenWrt router')}</span>
          </div>
        </div>
        <nav>
          {navigation.map((group) => <section class="nav-group" key={group.title}>
            <span class="nav-title">{group.title}</span>
            {group.screens.map((item) => (
              <button class={screen === item ? 'active' : ''} aria-current={screen === item ? 'page' : undefined} title={item} onClick={() => selectScreen(item)} key={item}>
                <span class="nav-dot" />{item}
              </button>
            ))}
          </section>)}
        </nav>
        <nav class="mobile-nav" aria-label="Основная навигация">
          {primaryMobileScreens.map(([target, label]) => <button class={screen === target ? 'active' : ''} aria-current={screen === target ? 'page' : undefined} title={target} onClick={() => selectScreen(target)} key={target}><span class="nav-dot" />{label}</button>)}
          <button class={mobileMoreOpen ? 'active' : ''} aria-expanded={mobileMoreOpen} onClick={() => setMobileMoreOpen((open) => !open)}><span class="nav-dot" />Ещё</button>
        </nav>
        {mobileMoreOpen && <div class="mobile-more-backdrop" role="presentation" onClick={() => setMobileMoreOpen(false)}><section class="mobile-more" role="dialog" aria-modal="true" aria-label="Дополнительные разделы" onClick={(event) => event.stopPropagation()}><header><b>Дополнительные разделы</b><button class="icon-button" aria-label="Закрыть" onClick={() => setMobileMoreOpen(false)}>×</button></header>{navigation.flatMap((group) => group.screens).filter((item) => !primaryMobileScreens.some(([target]) => target === item)).map((item) => <button class={screen === item ? 'active' : ''} aria-current={screen === item ? 'page' : undefined} onClick={() => selectScreen(item)} key={item}>{item}</button>)}</section></div>}
      </aside>
      <main>{children}</main>
    </div>
  );
}
