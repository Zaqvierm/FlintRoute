import { type ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import type { EventItem } from '../api';
import { asRecord, humanStatus, statusTone, textValue } from '../view-models';

export function Generic({ title, text }: { title: string; text: string }) {
  return <section><PageHeader title={title} text={text} /><EmptyState title="Пока не реализовано" text="Экран не притворяется рабочим: активных API-действий здесь нет." /></section>;
}

export function PageHeader({ title, text, children }: { title: string; text: string; children?: ComponentChildren }) {
  return <header class="page-header"><div><h1>{title}</h1><p>{text}</p></div>{children && <div class="page-actions">{children}</div>}</header>;
}

export function EntityCard({ title, status, children, onOpen }: { title: string; status?: unknown; children: ComponentChildren; onOpen?: () => void }) {
  return <article class="entity-card"><header><h2>{title}</h2>{status !== undefined && <StatusBadge value={status} />}</header><div class="entity-body">{children}</div>{onOpen && <footer><button onClick={onOpen}>Открыть</button></footer>}</article>;
}

export function StatusBadge({ value }: { value: unknown }) {
  const stale = textValue(asRecord(value).freshness, '').toLowerCase() === 'stale';
  return <span class={`status-badge ${stale ? 'warn' : statusTone(value)}`}>{stale ? `${humanStatus(value)} · данные устарели` : humanStatus(value)}</span>;
}

export function statusWithFreshness(status: unknown, record: unknown): unknown {
  const freshness = textValue(asRecord(record).freshness, '').trim().toLowerCase();
  if (freshness !== 'stale') return status;
  if (status !== null && typeof status === 'object' && !Array.isArray(status)) {
    return { ...(status as Record<string, unknown>), freshness: 'stale' };
  }
  return { status, freshness: 'stale' };
}

export function StatusLine({ label, value }: { label: string; value: unknown }) {
  return <div class="status-line"><span>{label}</span><StatusBadge value={value} /></div>;
}

export function InfoGrid({ items }: { items: Array<[string, unknown]> }) {
  const visible = items.filter(([, value]) => value !== null && value !== undefined && value !== '');
  return <dl class="info-grid">{visible.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{textValue(value)}</dd></div>)}</dl>;
}

export function DetailDrawer({ title, open, onClose, children, wide = false }: { title: string; open: boolean; onClose: () => void; children: ComponentChildren; wide?: boolean }) {
  const drawerRef = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusable = () => Array.from(drawerRef.current?.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])') ?? []).filter((item) => !item.hasAttribute('disabled'));
    window.setTimeout(() => focusable()[0]?.focus(), 0);
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { onClose(); return; }
      if (event.key !== 'Tab') return;
      const items = focusable();
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    window.addEventListener('keydown', handleKey);
    return () => {
      window.removeEventListener('keydown', handleKey);
      previous?.focus?.();
    };
  }, [open, onClose]);
  if (!open) return null;
  return <div class="drawer-backdrop" role="presentation" onClick={onClose}><aside ref={drawerRef} class={`detail-drawer ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title} onClick={(event) => event.stopPropagation()}><header><h2>{title}</h2><button class="icon-button" aria-label="Закрыть" onClick={onClose}>×</button></header><div class="drawer-content">{children}</div></aside></div>;
}

export function RawDisclosure({ value }: { value: unknown }) {
  return <details class="raw-disclosure"><summary>Открыть сырые данные</summary><pre>{JSON.stringify(value ?? {}, null, 2)}</pre></details>;
}

export function useConfirmDialog() {
  const [request, setRequest] = useState<string | null>(null);
  const resolver = useRef<((accepted: boolean) => void) | null>(null);
  const ask = (message: string): Promise<boolean> => new Promise((resolve) => {
    resolver.current = resolve;
    setRequest(message);
  });
  const answer = (accepted: boolean) => {
    resolver.current?.(accepted);
    resolver.current = null;
    setRequest(null);
  };
  const dialog = request ? <div class="modal-backdrop" role="presentation"><section class="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-title" onClick={(event) => event.stopPropagation()}><h2 id="confirm-title">Подтвердить действие</h2><p>{request}</p><div class="actions"><button autoFocus onClick={() => answer(false)}>Отмена</button><button class="primary" onClick={() => answer(true)}>Продолжить</button></div></section></div> : null;
  return { ask, dialog };
}

export function EmptyState({ title, text }: { title: string; text: string }) {
  return <div class="empty-state"><b>{title}</b><p>{text}</p></div>;
}

export function DisabledActions({ labels }: { labels: string[] }) {
  return <div class="not-available-actions" role="note">
    <b>Управление устройством пока недоступно</b>
    <span>Эти действия не притворяются рабочими кнопками и не меняют роутер.</span>
    <small>{labels.join(' · ')} — будет добавлено через безопасный ChangeSet.</small>
  </div>;
}

export function EvidenceList({ values, empty }: { values: unknown[]; empty: string }) {
  if (!values.length) return <EmptyState title="Нет данных" text={empty} />;
  return <div class="evidence-list">{values.map((value, index) => { const record = asRecord(value); return <article key={index}><b>{textValue(record.name ?? record.route ?? record.step, `Шаг ${index + 1}`)}</b><span>{humanStatus(record.status ?? record.result)}</span><p>{textValue(record.reason ?? record.message, 'Без дополнительного объяснения')}</p></article>; })}</div>;
}

export function EventRow({ event }: { event: EventItem }) {
  return <div class={`event ${statusTone(event.severity)}`}><b>{new Date(event.time).toLocaleTimeString()}</b><span>{event.device_id ?? 'system'} · {event.domain ?? event.type} · {event.route ?? 'n/a'}</span><small class="mono">{event.reason_code}</small></div>;
}

export function RouteBadge({ type }: { type: string }) {
  const normalized = String(type).toLowerCase().replace(/_/g, '-');
  return <span class={`badge ${normalized}`}><i />{type}</span>;
}

export function Card({ title, children }: { title: string; children: ComponentChildren }) {
  return <section class="card"><h2>{title}</h2>{children}</section>;
}

export function Grid({ children }: { children: ComponentChildren }) {
  return <section class="grid">{children}</section>;
}
