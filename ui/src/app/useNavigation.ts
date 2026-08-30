import { useEffect, useRef, useState } from 'preact/hooks';
import { availableScreens, screenFromLocation } from './routes';

export type AppNavigation = {
  screen: string;
  screenRef: { current: string };
  mobileMoreOpen: boolean;
  setMobileMoreOpen: (open: boolean | ((current: boolean) => boolean)) => void;
  selectScreen: (next: string) => void;
};

/**
 * Owns URL/local-preference navigation state for the application shell.
 *
 * The URL wins over the remembered screen. localStorage is used only as a
 * convenience for the last view; it is never used as backend/configuration
 * evidence. Keeping this state outside App also prevents refresh orchestration
 * from becoming the owner of browser history.
 */
export function useNavigation(): AppNavigation {
  const [screen, setScreen] = useState(() => {
    try {
      const fromURL = screenFromLocation();
      if (fromURL) return fromURL;
      const stored = window.localStorage.getItem('flintroute-screen');
      return stored && availableScreens.has(stored) ? stored : 'Обзор';
    } catch {
      return 'Обзор';
    }
  });
  const [mobileMoreOpen, setMobileMoreOpen] = useState(false);
  const screenRef = useRef(screen);

  useEffect(() => {
    screenRef.current = screen;
  }, [screen]);

  function selectScreen(next: string) {
    if (!availableScreens.has(next)) return;
    setScreen(next);
    setMobileMoreOpen(false);
    try {
      window.localStorage.setItem('flintroute-screen', next);
      const url = new URL(window.location.href);
      url.searchParams.set('screen', next);
      window.history.pushState({ screen: next }, '', url);
    } catch {
      // Storage/history may be disabled; in-memory navigation still works.
    }
  }

  useEffect(() => {
    const onPopState = () => setScreen(screenFromLocation() ?? 'Обзор');
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  return { screen, screenRef, mobileMoreOpen, setMobileMoreOpen, selectScreen };
}
