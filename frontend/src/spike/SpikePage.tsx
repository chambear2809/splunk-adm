import { useEffect, useRef, useState } from "react";
import styled from "styled-components";
import ButtonExport from "@splunk/react-ui/Button";
import TableExport from "@splunk/react-ui/SimpleTable";
import useSplunkThemeExport from "@splunk/themes/useSplunkTheme";
import SearchJobExport from "@splunk/search-job/SearchJob";
import { username } from "@splunk/splunk-utils/config";
import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { MAX_ROWS, type Row } from "../rows";
import { exportSpikePng } from "./export";
import { spikeRows, spikeSearch } from "./settings";
import { toolkitDefault } from "./interop";

const Button = toolkitDefault(ButtonExport);
const Table = toolkitDefault(TableExport);
const useSplunkTheme = toolkitDefault(useSplunkThemeExport);
const SearchJob = toolkitDefault(SearchJobExport);

// Classic dashboard HTML-panel rules colour headings and paragraphs; the
// repeated class outranks them so text follows the Toolkit theme.
const Container = styled.main<{ $background: string; $foreground: string }>`
  background: ${(p) => p.$background};
  color: ${(p) => p.$foreground};
  min-height: 100vh;
  padding: 24px;
  &&& :is(h1, h2, h3, p) {
    color: inherit;
  }
`;

export function SpikePage({ preference }: { preference: string }) {
  const theme = useSplunkTheme();
  const [rows, setRows] = useState<Row[]>([]);
  const [status, setStatus] = useState("Searching…");
  const [timezone, setTimezone] = useState("Reading user timezone…");
  const [png, setPng] = useState("PNG export has not run.");
  const svg = useRef<SVGSVGElement>(null);
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    let cleanup = () => {};
    try {
      if (!username) throw new Error("Splunk user context is unavailable.");
      const init = getDefaultFetchInit();
      // Use the current token from splunk-utils, including for search-job's
      // nested v3 utilities. No manual cookie parsing or hardcoded form key.
      SearchJob.setBaseFetchInit(init);
      const job = SearchJob.create(
        spikeSearch(new URLSearchParams(location.search)),
        { app: "splunk_adm", owner: username, cancelOnUnload: true },
      );
      const timer = setTimeout(() => {
        if (active) setStatus("Search timed out after 120 seconds.");
        subscription.unsubscribe();
        job.cancel();
      }, 120000);
      const subscription = job
        .getResults({ count: MAX_ROWS + 1, output_mode: "json" })
        .subscribe({
          next: (payload) => {
            if (!active) return;
            clearTimeout(timer);
            try {
              const found = spikeRows(payload);
              setRows(found);
              setStatus(`Returned ${found.length} graph rows.`);
            } catch (error) {
              setStatus(String(error));
            }
          },
          error: (error) => {
            clearTimeout(timer);
            if (active) setStatus(`Search failed: ${error.message}`);
          },
        });
      cleanup = () => {
        clearTimeout(timer);
        subscription.unsubscribe();
        job.cancel();
      };
      void fetch(
        createRESTURL(`authentication/users/${encodeURIComponent(username)}`, {
          sharing: "system",
        }) + "?output_mode=json",
        { ...init, signal: controller.signal },
      )
        .then((response) => {
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          return response.json();
        })
        .then((data) => {
          const tz = data.entry?.[0]?.content?.tz;
          if (typeof tz !== "string" || !tz)
            throw new Error(
              "User timezone is unset; no explicit zone returned.",
            );
          if (active) setTimezone(tz);
        })
        .catch((error: Error) => {
          if (active) setTimezone(`Timezone read failed: ${error.message}`);
        });
    } catch (error) {
      setStatus(String(error));
    }
    return () => {
      active = false;
      controller.abort();
      cleanup();
    };
  }, []);

  return (
    <Container
      $background={theme.backgroundColorPage}
      $foreground={theme.contentColorDefault}
      data-theme={theme.colorScheme}
    >
      <h1>Application Atlas — Toolkit spike</h1>
      <p>
        Splunk preference: {preference}; rendered theme: {theme.colorScheme}.
      </p>
      <p>User timezone: {timezone}</p>
      <p role="status">{status}</p>
      <svg
        ref={svg}
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 480 100"
        width="480"
        height="100"
        aria-label="Export probe"
      >
        <rect width="480" height="100" fill={theme.backgroundColorPage} />
        <text x="16" y="45" fill={theme.contentColorDefault}>
          Application Atlas: {rows.length} graph rows
        </text>
        <path d="M16 70 H464" stroke={theme.contentColorDefault} />
      </svg>
      <div>
        <Button
          label="Export PNG"
          onClick={() => {
            if (!svg.current) return;
            setPng("Exporting…");
            void exportSpikePng(svg.current).then(
              (bytes) => setPng(`PNG export passed: ${bytes} bytes.`),
              (error: Error) => setPng(`PNG export failed: ${error.message}`),
            );
          }}
        />
        <p>{png}</p>
      </div>
      <h2>First ten graph rows</h2>
      <Table>
        <Table.Head>
          <Table.Row>
            <Table.HeadCell>Type</Table.HeadCell>
            <Table.HeadCell>ID</Table.HeadCell>
          </Table.Row>
        </Table.Head>
        <Table.Body>
          {rows.slice(0, 10).map((row, i) => (
            <Table.Row key={i}>
              <Table.Cell>{String(row.row_type ?? "")}</Table.Cell>
              <Table.Cell>{String(row.id ?? "")}</Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table>
    </Container>
  );
}
