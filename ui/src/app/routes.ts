export const navigation = [
  { title: 'Обзор', screens: ['Быстрая настройка', 'Обзор'] },
  { title: 'Сеть', screens: ['Карта сети', 'Устройства', 'Трафик'] },
  { title: 'Правила', screens: ['Сервисы', 'Маршруты', 'Компоненты', 'VLESS-серверы', 'Smart DNS', 'Zapret', 'TG WS Proxy', 'Discovery'] },
  { title: 'Активность', screens: ['Поток решений', 'Операции', 'Telegram', 'Ревизии и recovery'] },
  { title: 'Система', screens: ['Диагностика', 'Безопасность', 'Настройки', 'Резервное копирование', 'Advanced', 'External SOCKS'] }
] as const;

export const notFoundScreen = 'Страница не найдена';
export const availableScreens = new Set([...navigation.flatMap((group) => group.screens), 'External SOCKS', notFoundScreen]);

export function screenFromLocation(): string | null {
  if (typeof window === 'undefined') return null;
  const raw = new URLSearchParams(window.location.search).get('screen');
  if (raw === null) return null;
  return availableScreens.has(raw) ? raw : notFoundScreen;
}
