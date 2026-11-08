import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';

interface Props<T> {
  rows: readonly T[];
  rowHeight: (row: T) => number;
  renderRow: (row: T, index: number) => ReactNode;
  getKey: (row: T) => string;
  resetKey: string;
  label: string;
  overscanPx?: number;
}

export function VirtualList<T>({ rows, rowHeight, renderRow, getKey, resetKey, label, overscanPx = 400 }: Props<T>) {
  const containerRef = useRef<HTMLDivElement>(null);
  const frameRef = useRef(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(600);

  const { offsets, total } = useMemo(() => {
    const list: number[] = new Array<number>(rows.length + 1);
    list[0] = 0;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i] as T;
      list[i + 1] = (list[i] ?? 0) + rowHeight(row);
    }
    return { offsets: list, total: list[rows.length] ?? 0 };
  }, [rows, rowHeight]);

  const [start, end] = useMemo(() => {
    const y0 = Math.max(0, scrollTop - overscanPx);
    const y1 = scrollTop + viewport + overscanPx;
    let lo = 0;
    let hi = rows.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((offsets[mid + 1] ?? 0) > y0) hi = mid;
      else lo = mid + 1;
    }
    let last = lo;
    while (last < rows.length && (offsets[last] ?? 0) < y1) last += 1;
    return [lo, last] as const;
  }, [offsets, rows.length, scrollTop, viewport, overscanPx]);

  const onScroll = useCallback((): void => {
    if (frameRef.current) return;
    frameRef.current = requestAnimationFrame(() => {
      frameRef.current = 0;
      const el = containerRef.current;
      if (el) setScrollTop(el.scrollTop);
    });
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return undefined;
    setViewport(el.clientHeight);
    if (typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(() => setViewport(el.clientHeight));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(
    () => () => {
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    },
    [],
  );

  useLayoutEffect(() => {
    if (containerRef.current) containerRef.current.scrollTop = 0;
    setScrollTop(0);
  }, [resetKey]);

  const items: ReactNode[] = [];
  for (let i = start; i < end; i += 1) {
    const row = rows[i] as T;
    items.push(
      <div
        key={getKey(row)}
        role="listitem"
        aria-posinset={i + 1}
        aria-setsize={rows.length}
        className="vrow"
        style={{ top: offsets[i] ?? 0, height: rowHeight(row) }}
      >
        {renderRow(row, i)}
      </div>,
    );
  }

  return (
    <div ref={containerRef} className="vlist" role="list" aria-label={label} tabIndex={0} onScroll={onScroll}>
      <div role="presentation" className="vspacer" style={{ height: total }}>
        {items}
      </div>
    </div>
  );
}
