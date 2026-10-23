import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import styled from "styled-components";
import useSplunkThemeExport from "@splunk/themes/useSplunkTheme";
import { toolkitDefault } from "./interop";
import { PAGES, pageURL, URL_STATE_CHANGED, type Page } from "./urlState";
import type { SearchClient } from "../data/searchClient";
import { healthIndicator, useHealthStatus } from "../data/healthStatus";

const useSplunkTheme = toolkitDefault(useSplunkThemeExport);
const Root = styled.div`
  background: var(--adm-page);
  color: var(--adm-ink);
  min-height: 600px;
  font-family: inherit;
  &&& :is(h1, h2, h3, h4, p, label, legend, th, td) {
    color: inherit;
  }
  &&& :is(h1, h2, h3, h4, p) {
    font-family: inherit;
  }
`;
const labels: Record<Page, string> = {
  applications: "Applications",
  map: "Map",
  endpoints: "Endpoints",
  data_health: "Data health",
  setup: "Setup",
  help: "Help",
};

/** Toolkit theme values also feed the existing SVG map's scoped CSS tokens. */
export function Shell({
  page,
  children,
  live,
}: {
  page: Page;
  children: ReactNode;
  client?: SearchClient;
  live?: boolean;
}) {
  const [search, setSearch] = useState(() =>
    typeof location === "undefined" ? "" : location.search,
  );
  useEffect(() => {
    const sync = () => setSearch(location.search);
    window.addEventListener(URL_STATE_CHANGED, sync);
    window.addEventListener("popstate", sync);
    sync();
    return () => {
      window.removeEventListener(URL_STATE_CHANGED, sync);
      window.removeEventListener("popstate", sync);
    };
  }, []);
  const t = useSplunkTheme();
  const tokens = {
    fontFamily: t.fontFamily,
    fontSize: t.fontSize,
    "--adm-page": t.backgroundColorPage,
    "--adm-surface": t.backgroundColorSection,
    "--adm-card": t.backgroundColorSection,
    "--adm-card-head": t.backgroundColorPage,
    "--adm-card-border": t.borderColor,
    "--adm-line": t.borderColorWeak,
    "--adm-ink": t.contentColorDefault,
    "--adm-ink-2": t.contentColorMuted,
    "--adm-muted": t.contentColorMuted,
    "--adm-link": t.contentColorLink,
    "--adm-focus": t.contentColorLink,
    "--adm-select-ring": t.contentColorDefault,
  } as CSSProperties;
  const health = useHealthStatus();
  const indicator = healthIndicator(
    health?.report,
    // A background refresh keeps showing the last completed assessment.
    !!health?.busy && !health.report,
    health?.error,
    live ?? false,
  );
  const indicatorLabel = {
    unknown: "Health status unknown",
    loading: "Checking pipeline health",
    error: "Pipeline health check failed",
    healthy: "Pipeline health available",
    attention: "Pipeline health needs review",
  }[indicator];
  return (
    <Root className="atlas" data-atlas-theme={t.colorScheme} style={tokens}>
      <nav className="atlas-nav" aria-label="Application Atlas">
        <strong>Application Atlas</strong>
        {PAGES.map((p) => (
          <a
            key={p}
            href={pageURL(
              p,
              p === "endpoints"
                ? new URLSearchParams(
                    [...new URLSearchParams(search)].filter(([key]) =>
                      [
                        "endpoint_ip",
                        "endpoint_scope",
                        "endpoint_start",
                        "endpoint_end",
                      ].includes(key),
                    ),
                  )
                : new URLSearchParams(search),
            )}
            aria-current={p === page ? "page" : undefined}
          >
            {labels[p]}
          </a>
        ))}
        <a
          className={`health-status health-${indicator}`}
          href={pageURL("data_health", new URLSearchParams(search))}
          title={indicatorLabel}
          aria-label={indicatorLabel}
        >
          <span aria-hidden="true">●</span> Health
        </a>
      </nav>
      {children}
    </Root>
  );
}
