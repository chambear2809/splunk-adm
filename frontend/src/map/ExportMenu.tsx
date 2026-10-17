import { FileSpreadsheet, FileJson, X } from "lucide-react";
export function ExportMenu({
  close,
  onCsv,
  onContextEvidenceCsv,
  hasContextEvidence,
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
          <small>
            Current Network or Services map, including visible filters and
            focus.
          </small>
        </span>
      </button>
      <button className="menu-item" onClick={onPrint} disabled={pngDisabled}>
        <span>
          <b>Print / PDF</b>
          <small>Open the browser print dialog to print or save as PDF.</small>
        </span>
      </button>
      {error && <p role="alert">{error}</p>}
      <button className="menu-item" onClick={onCsv}>
        <FileSpreadsheet size={17} aria-hidden />
        <span>
          <b>Required flows (CSV)</b>
          <small>
            One row per conversation: client, server, EPG, namespace, port,
            identity and seen-by. For firewall rule and ACI contract requests.
          </small>
        </span>
      </button>
      {hasContextEvidence && (
        <button className="menu-item" onClick={onContextEvidenceCsv}>
          <FileSpreadsheet size={17} aria-hidden />
          <span>
            <b>Context evidence (CSV)</b>
            <small>
              Original per-edge attachment and traffic observation records, kept
              separate from merged client summaries.
            </small>
          </span>
        </button>
      )}
      <button className="menu-item" onClick={onJson}>
        <FileJson size={17} aria-hidden />
        <span>
          <b>Map data (JSON)</b>
          <small>The full loaded graph, before filters and focus.</small>
        </span>
      </button>
    </section>
  );
}
