import { createRoot } from "react-dom/client";
import { App } from "./App";
import type { SearchConstructor } from "./provider";
import "./styles.css";
interface MVC {
  Components?: {
    getInstance?: (id: string) => unknown;
    revokeInstance?: (id: string) => void;
  };
}
declare global {
  interface Window {
    require?: (
      deps: string[],
      callback: (SearchManager: SearchConstructor, mvc: MVC) => void,
      error?: (error: Error) => void,
    ) => void;
  }
}
type DemoData = Parameters<typeof App>[0]["demoData"];
function mount(
  SearchManager?: SearchConstructor,
  mvc?: MVC,
  demoData?: DemoData,
) {
  const root = document.getElementById("adm-root");
  if (!root || root.dataset.mounted) return;
  root.dataset.mounted = "true";
  const releaseManager = (id: string) => {
    if (mvc?.Components?.getInstance?.(id)) mvc.Components.revokeInstance?.(id);
  };
  createRoot(root).render(
    <App
      SearchManager={SearchManager}
      releaseManager={releaseManager}
      inSplunk={root.dataset.splunk === "true"}
      demoData={demoData}
    />,
  );
}
if (__ADM_SPLUNK_BUILD__) {
  const failed = () => {
    const root = document.getElementById("adm-root");
    if (root)
      root.textContent =
        "Unable to load Splunk search integration. Check dashboard JavaScript permissions and reload.";
  };
  if (window.require)
    window.require(
      [
        "splunkjs/mvc/searchmanager",
        "splunkjs/mvc",
        "splunkjs/mvc/simplexml/ready!",
      ],
      mount,
      failed,
    );
  else failed();
} else if (
  import.meta.env.DEV &&
  new URLSearchParams(location.search).get("data") === "aci-unit"
) {
  // Development harness: renders the unit-test ACI rows, never shipped.
  void Promise.all([
    import("./testdata/aci"),
    import("./rows"),
    import("./topology"),
  ]).then(([d, rows, topo]) =>
    mount(undefined, undefined, {
      graph: () => rows.rowsToGraph(d.aciGraphRows, d.aciArgs, { demo: true }),
      topology: () => topo.rowsToTopology(d.aciTopologyRows),
    }),
  );
} else mount();
