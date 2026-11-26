import { FileSpreadsheet, FileJson, X } from "lucide-react";
export function ExportMenu({
  close,
  onCsv,
  onContextEvidenceCsv,
  hasContextEvidence,
  onPolicy,
  onJson,
  onPng,
  onPrint,
  pngDisabled,
  busy,
  error,
}: {
  close: () => void;
  onCsv: () => void;
  onContextEvidenceCsv: () => void;
  hasContextEvidence: boolean;
  onPolicy?: () => void;
  onJson: () => void;
  onPng: () => void;
  onPrint: () => void;
  pngDisabled: boolean;
  busy: boolean;
  error: string;
}) {
  return (
    <section className="popover export" aria-label="Export">
      <div className="popover-head">
        <h2>Export</h2>
        <button
          className="icon-button"
          aria-label="Close export"
          onClick={close}
        >
          <X size={16} />
        </button>
      </div>
      <button className="menu-item" onClick={onPng} disabled={pngDisabled}>
        <span>
          <b>{busy ? "Preparing image…" : "Map image (PNG)"}</b>
          <small>Current map with filters and focus.</small>
        </span>
      </button>
      <button className="menu-item" onClick={onPrint} disabled={pngDisabled}>
        <span>
          <b>Print / PDF</b>
        </span>
      </button>
      {error && <p role="alert">{error}</p>}
      <button className="menu-item" onClick={onCsv}>
        <FileSpreadsheet size={17} aria-hidden />
        <span>
          <b>Required flows (CSV)</b>
          <small>One row per conversation for firewall and ACI requests.</small>
        </span>
      </button>
      {hasContextEvidence && (
        <button className="menu-item" onClick={onContextEvidenceCsv}>
          <FileSpreadsheet size={17} aria-hidden />
          <span>
            <b>Context evidence (CSV)</b>
            <small>Per-edge attachment, traffic, and NAT evidence.</small>
          </span>
        </button>
      )}
      {onPolicy && (
        <button className="menu-item" onClick={onPolicy}>
          <FileJson size={17} aria-hidden />
          <span>
            <b>Cilium policy draft (YAML)</b>
            <small>
              L3/L4 observed conversations. Apply with per-endpoint
              PolicyAuditMode; never daemon-wide audit.
            </small>
          </span>
        </button>
      )}
      <button className="menu-item" onClick={onJson}>
        <FileJson size={17} aria-hidden />
        <span>
          <b>Map data (JSON)</b>
          <small>Full graph before filters.</small>
        </span>
      </button>
    </section>
  );
}
