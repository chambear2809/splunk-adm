import { isRawIfIndex } from "./ifIndex";
import { outLabel, type ObserverInterfaceRow } from "./data/observerInterfaces";
import "./observerInterfaces.css";

const INFERRED = / \(inferred[^)]*\)$/;

function Iface({ name }: { name?: string }) {
  if (!name) return <span className="muted">—</span>;
  const m = INFERRED.exec(name);
  const base = m ? name.slice(0, m.index) : name;
  return (
    <>
      <code className={isRawIfIndex(base) ? "raw" : undefined}>{base}</code>
      {m && <small className="atlas-ifs-inferred">{m[0].trim()}</small>}
    </>
  );
}

function Rows({ rows }: { rows: ObserverInterfaceRow[] }) {
  return (
    <>
      {rows.map((r, i) => {
        const first = i === 0 || rows[i - 1].device !== r.device;
        const span = first
          ? rows.slice(i).findIndex((x) => x.device !== r.device)
          : 0;
        return (
          <tr key={`${r.device}|${r.in ?? ""}|${r.out ?? ""}`}>
            {first && (
              <th scope="row" rowSpan={span < 0 ? rows.length - i : span}>
                {r.label}
              </th>
            )}
            <td>
              <Iface name={r.in} />
            </td>
            <td>
              <Iface name={outLabel(r.out)} />
            </td>
            <td className="num">
              {r.records === undefined ? "—" : r.records.toLocaleString()}
            </td>
            <td>
              {r.sources.join(", ")}
              {r.inferredOut && (
                <small className="atlas-ifs-inferred">out inferred</small>
              )}
            </td>
          </tr>
        );
      })}
    </>
  );
}

const Head = () => (
  <thead>
    <tr>
      <th scope="col">Device</th>
      <th scope="col">In</th>
      <th scope="col">Out</th>
      <th scope="col" className="num">
        Records
      </th>
      <th scope="col">Evidence</th>
    </tr>
  </thead>
);

/** Device · In · Out · Records · Evidence, one row group per observer device. */
export function ObserverInterfaces({
  rows,
  title = "Interfaces",
}: {
  rows: ObserverInterfaceRow[];
  title?: string;
}) {
  if (!rows.length) return null;
  return (
    <section aria-label={title}>
      <h3>
        {title}{" "}
        <span className="count">{new Set(rows.map((r) => r.device)).size}</span>
      </h3>
      <table className="atlas-table atlas-ifs" aria-label={title}>
        <Head />
        <tbody>
          <Rows rows={rows} />
        </tbody>
      </table>
    </section>
  );
}

/** The links one card-pair line groups, each with its observer interfaces. */
export function BundleInterfaces({
  links,
  more,
}: {
  links: { id: string; title: string; rows: ObserverInterfaceRow[] }[];
  more: number;
}) {
  const shown = links.filter((l) => l.rows.length);
  if (!shown.length) return null;
  return (
    <section aria-label="Interfaces by link">
      <h3>
        Interfaces by link <span className="count">{shown.length}</span>
      </h3>
      <table className="atlas-table atlas-ifs" aria-label="Interfaces by link">
        <Head />
        {shown.map((l) => (
          <tbody key={l.id}>
            <tr className="atlas-ifs-link">
              <th scope="rowgroup" colSpan={5}>
                {l.title}
              </th>
            </tr>
            <Rows rows={l.rows} />
          </tbody>
        ))}
      </table>
      {more > 0 && (
        <p className="muted small">
          {more.toLocaleString()} more links in the Table view
        </p>
      )}
    </section>
  );
}
