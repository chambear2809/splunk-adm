import { FileSpreadsheet, FileJson, X } from "lucide-react";
export function ExportMenu({
  close,
  onCsv,
  onJson,
}: {
  close: () => void;
  onCsv: () => void;
  onJson: () => void;
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
