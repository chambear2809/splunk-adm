import { useEffect, useRef, useState } from "react";
import {
  Ban,
  Box,
  BrickWall,
  DoorOpen,
  Eye,
  Globe,
  HardDrive,
  Network,
  Server,
  ShieldCheck,
  Unplug,
  X,
} from "lucide-react";
import { fitText } from "./MapView";
import type { CandidatePath, Stage } from "./topology";

const FAMILY = 'system-ui, -apple-system, "Segoe UI", sans-serif';
const TITLE_FONT = `650 13px ${FAMILY}`;
const CARD_TEXT_W = 152;

function StageIcon({ stage }: { stage: Stage }) {
  const p = { size: 16, strokeWidth: 1.8, "aria-hidden": true };
  if (stage.kind === "switch") return <Network {...p} />;
  if (stage.kind === "firewall") return <BrickWall {...p} />;
  if (stage.kind === "host") return <Server {...p} />;
  if (stage.kind === "gap") return <Unplug {...p} />;
  if (stage.kind === "handoff") return <DoorOpen {...p} />;
  if (stage.subtitle?.startsWith("VM")) return <HardDrive {...p} />;
  if (stage.subtitle?.startsWith("Pod") || stage.subtitle === "Service")
    return <Box {...p} />;
  return <Globe {...p} />;
}

const portText = (s: Stage) =>
  [s.ports?.in, s.ports?.out].filter(Boolean).join(" → ");
const HANDOFF_CHIP = {
  observed: "Determined",
  inferred: "Inferred",
  undetermined: "Not determined",
} as const;
const POLICY_ICON = {
  intent: ShieldCheck,
  observed: Eye,
  blocked: Ban,
  neutral: ShieldCheck,
} as const;

export function PathStrip({
  path,
  title,
  onClose,
  onBackend,
}: {
  path: CandidatePath;
  title: string;
  onClose: () => void;
  onBackend?: (id: string) => void;
}) {
  const scroller = useRef<HTMLOListElement>(null);
  const [fade, setFade] = useState({ left: false, right: false });
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const update = () =>
      setFade({
        left: el.scrollLeft > 2,
        right: el.scrollLeft + el.clientWidth < el.scrollWidth - 2,
      });
    update();
    el.addEventListener("scroll", update, { passive: true });
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => {
      el.removeEventListener("scroll", update);
      ro.disconnect();
    };
  }, [path]);
  let n = 0;
  return (
    <section className="path-strip" aria-label={`Candidate path: ${title}`}>
      <header>
        <h3>Candidate path</h3>
        <p title={title}>
          {title} · from inventory; observations mark where traffic was seen,
          not packet order.
        </p>
        <div className="path-legend" aria-hidden="true">
          <span>
            <i className="seen" /> Seen
          </span>
          <span>
            <i className="unseen" /> Not seen
          </span>
          <span>
            <i className="gap" /> No collected link
          </span>
        </div>
        <button
          className="icon-button"
          aria-label="Close path"
          onClick={onClose}
        >
          <X size={16} />
        </button>
      </header>
      {path.backends.length > 1 && onBackend && (
        <label className="path-backend">
          <span>Backend</span>
          <select
            value={path.backend}
            onChange={(e) => onBackend(e.target.value)}
          >
            {path.backends.map((b) => (
              <option key={b.id} value={b.id}>
                {b.label}
                {b.state === "inferred" ? " (inferred)" : ""}
              </option>
            ))}
          </select>
          <small className="muted">
            {path.backends.length} pods served this frontend
          </small>
        </label>
      )}
      {path.policy.length > 0 && (
        <div className="path-policy">
          {path.policy.map((p) => {
            const Icon = POLICY_ICON[p.tone];
            return (
              <span key={p.text} className={`policy-chip ${p.tone}`}>
                <Icon size={13} aria-hidden /> {p.text}
              </span>
            );
          })}
        </div>
      )}
      <ol
        ref={scroller}
        className={`stages ${fade.left ? "fade-left" : ""} ${fade.right ? "fade-right" : ""}`}
        tabIndex={0}
        aria-label="Path stages"
      >
        {path.stages.map((s, i) => {
          const next = path.stages[i + 1];
          const connector =
            !next || s.kind === "gap" || next.kind === "gap"
              ? "none"
              : s.observed !== false && next.observed !== false
                ? "seen"
                : "unseen";
          const status =
            s.kind === "gap"
              ? "gap"
              : s.handoff
                ? s.handoff.state
                : s.kind === "entity"
                  ? "endpoint"
                  : s.observed
                    ? "seen"
                    : "unseen";
          return (
            <li key={i} className={`stage ${status} ${s.kind}`}>
              {s.kind === "gap" ? (
                <div className="gap-card">
                  <StageIcon stage={s} />
                  <span>{s.title}</span>
                </div>
              ) : (
                <div
                  className="stage-card"
                  title={[
                    s.title,
                    s.subtitle,
                    s.seenInterfaces.length
                      ? `Seen on ${s.seenInterfaces.join(", ")}`
                      : "",
                    s.handoff?.text ?? "",
                  ]
                    .filter(Boolean)
                    .join("\n")}
                >
                  <div className="stage-top">
                    <span className="stage-num">{++n}</span>
                    <StageIcon stage={s} />
                    <span className={`seen-chip ${status}`}>
                      {s.handoff
                        ? HANDOFF_CHIP[s.handoff.state]
                        : s.kind === "entity"
                          ? "Endpoint"
                          : s.observed
                            ? "Seen"
                            : "Not seen"}
                    </span>
                  </div>
                  <strong>{fitText(s.title, CARD_TEXT_W, TITLE_FONT)}</strong>
                  <small>{s.subtitle ?? " "}</small>
                  {s.handoff ? (
                    <small className="handoff-text">{s.handoff.text}</small>
                  ) : (
                    <>
                      <code>{portText(s) || " "}</code>
                      <small className="seen-by">
                        {s.observed ? s.observedBy.join(" · ") : " "}
                      </small>
                    </>
                  )}
                </div>
              )}
              {connector !== "none" && (
                <span className={`connector ${connector}`} aria-hidden />
              )}
            </li>
          );
        })}
      </ol>
      {path.notes.map((n) => (
        <p key={n} className="path-note">
          {n}
        </p>
      ))}
      {(path.sameHost || path.unplaced.length > 0) && (
        <p className="path-note">
          {path.sameHost &&
            "Both pods run on the same Kubernetes node; this traffic does not reach the fabric. "}
          {path.unplaced.length > 0 &&
            `Also seen at: ${path.unplaced
              .map(
                (d) =>
                  `${d.label}${d.interfaces.length ? ` (${d.interfaces.join(", ")})` : ""} · ${d.sources.join(", ")}`,
              )
              .join("; ")}`}
        </p>
      )}
    </section>
  );
}
