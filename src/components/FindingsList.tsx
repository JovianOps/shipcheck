import { useMemo, useRef, useState } from "react";
import type { Finding, FindingCategory } from "../types";

type Filter = "all" | FindingCategory;
const FILTERS: Filter[] = ["all", "secrets", "pii", "readiness"];
const ROW = 132;
const VIEW = 560;
const OVERSCAN = 4;

function Row({ f }: { f: Finding }) {
  const [copied, setCopied] = useState(false);
  const loc = `${f.file}:${f.line}`;
  const copy = async () => {
    try { await navigator.clipboard.writeText(loc); setCopied(true); setTimeout(() => setCopied(false), 1200); } catch { /* ignore */ }
  };
  return (
    <div className="sc-finding" role="listitem">
      <div className="sc-finding-head">
        <span className={`sc-badge sc-sev-${f.severity}`}>{f.severity}</span>
        <span className="sc-finding-type">{f.type}</span>
        <span className="sc-cat">{f.category}</span>
        <code className="sc-loc" title={loc}>{loc}</code>
        <button type="button" className="sc-btn sc-btn-ghost sc-btn-sm" onClick={copy} aria-label={`Copy path ${loc}`}>
          {copied ? "Copied" : "Copy path"}
        </button>
      </div>
      <code className="sc-preview">{f.preview}</code>
      <p className="sc-remediation">{f.remediation}</p>
    </div>
  );
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<Filter>("all");
  const [scrollTop, setScrollTop] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const counts = useMemo(() => {
    const c: Record<Filter, number> = { all: findings.length, secrets: 0, pii: 0, readiness: 0 };
    findings.forEach((f) => c[f.category]++);
    return c;
  }, [findings]);
  const list = useMemo(() => (filter === "all" ? findings : findings.filter((f) => f.category === filter)), [findings, filter]);

  const start = Math.max(0, Math.floor(scrollTop / ROW) - OVERSCAN);
  const end = Math.min(list.length, Math.ceil((scrollTop + VIEW) / ROW) + OVERSCAN);

  const select = (f: Filter) => { setFilter(f); setScrollTop(0); if (ref.current) ref.current.scrollTop = 0; };
  const onKey = (e: React.KeyboardEvent, i: number) => {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!d) return;
    const n = (i + d + FILTERS.length) % FILTERS.length;
    select(FILTERS[n] ?? "all");
    (e.currentTarget.parentElement?.children[n] as HTMLElement | undefined)?.focus();
  };

  return (
    <section className="sc-card" aria-labelledby="findings-h">
      <div className="sc-card-head">
        <h2 id="findings-h">Findings</h2>
        <div className="sc-tabs" role="tablist" aria-label="Filter findings">
          {FILTERS.map((f, i) => (
            <button key={f} role="tab" type="button" aria-selected={filter === f} tabIndex={filter === f ? 0 : -1}
              className="sc-tab" onClick={() => select(f)} onKeyDown={(e) => onKey(e, i)}>
              {f} <span className="sc-tab-count">{counts[f]}</span>
            </button>
          ))}
        </div>
      </div>
      {list.length === 0 ? (
        <p className="sc-empty">No findings in this category.</p>
      ) : (
        <div ref={ref} className="sc-virtual" style={{ height: Math.min(VIEW, list.length * ROW) }}
          onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)} role="list" aria-label={`${list.length} findings`} tabIndex={0}>
          <div style={{ height: list.length * ROW, position: "relative" }}>
            {list.slice(start, end).map((f, i) => (
              <div key={f.id} style={{ position: "absolute", top: (start + i) * ROW, left: 0, right: 0, height: ROW }}>
                <Row f={f} />
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
