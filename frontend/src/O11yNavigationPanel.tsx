import { useState } from "react";
import {
  buildO11yNavigation,
  type O11yNavigationInput,
} from "./data/o11yNavigation";

/** Manual Observability Cloud destinations with exact context kept visible. */
export function O11yNavigationPanel(props: O11yNavigationInput) {
  const model = buildO11yNavigation(props);
  const [copyStatus, setCopyStatus] = useState("");

  const copyContext = async () => {
    try {
      await navigator.clipboard.writeText(model.copyText);
      setCopyStatus("Investigation context copied.");
    } catch {
      setCopyStatus(
        "Could not copy context. Check clipboard access and copy the values shown below.",
      );
    }
  };

  return (
    <section
      className="o11y-navigation"
      aria-label="Observability Cloud product navigation"
    >
      <h3>Explore in Splunk Observability Cloud</h3>
      <p>
        Product links open the configured organization home. Splunk does not
        document stable product URLs for these selected identity and time
        filters, so review the exact context below and set filters in each
        product.
      </p>
      <dl>
        <div>
          <dt>Organization</dt>
          <dd>
            <code>{model.organizationId}</code>
          </dd>
        </div>
        <div>
          <dt>Realm</dt>
          <dd>
            <code>{model.realm}</code>
          </dd>
        </div>
        <div>
          <dt>APM service</dt>
          <dd>
            <code>{model.service.name}</code>
          </dd>
        </div>
        <div>
          <dt>Environment</dt>
          <dd>
            <code>{model.service.environment}</code>
          </dd>
        </div>
        <div>
          <dt>Cluster</dt>
          <dd>
            <code>{model.service.cluster}</code>
          </dd>
        </div>
        <div>
          <dt>Kubernetes namespace</dt>
          <dd>
            <code>{model.service.namespace}</code>
          </dd>
        </div>
        <div>
          <dt>OTel service namespace</dt>
          <dd>
            <code>{model.service.serviceNamespace ?? "Not provided"}</code>
          </dd>
        </div>
        <div>
          <dt>APM MMS ID</dt>
          <dd>
            <code>{model.apmMmsId ?? "Not provided"}</code>
          </dd>
        </div>
        <div>
          <dt>Selected time window (UTC)</dt>
          <dd>
            <time dateTime={model.startUtc}>{model.startUtc}</time> to{" "}
            <time dateTime={model.endUtc}>{model.endUtc}</time>
          </dd>
        </div>
        <div>
          <dt>Selected workload pod UIDs</dt>
          <dd>
            {model.podUids.length ? (
              <ul>
                {model.podUids.map((podUid, index) => (
                  <li key={`${podUid}:${index}`}>
                    <code>{podUid}</code>
                  </li>
                ))}
              </ul>
            ) : (
              "Not provided"
            )}
          </dd>
        </div>
      </dl>
      <button className="secondary-button" type="button" onClick={copyContext}>
        Copy investigation context
      </button>
      <p role="status" aria-live="polite">
        {copyStatus}
      </p>
      <ol className="o11y-navigation-products">
        {model.actions.map((action) => (
          <li key={action.product}>
            <section aria-labelledby={`o11y-navigation-${action.product}`}>
              <h4 id={`o11y-navigation-${action.product}`}>{action.title}</h4>
              <p>
                <strong>In product:</strong> {action.location}
              </p>
              <p>{action.instructions}</p>
              {action.searchHint && (
                <p>
                  <strong>Search:</strong> <code>{action.searchHint}</code>
                </p>
              )}
              {action.ids.length > 0 && (
                <div>
                  <p>
                    <strong>
                      {action.product === "detectors" ? "Detector" : "Incident"}{" "}
                      IDs
                    </strong>
                  </p>
                  <ul>
                    {action.ids.map((id, index) => (
                      <li key={`${id}:${index}`}>
                        <code>{id}</code>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {action.ids.length === 0 && action.product === "detectors" && (
                <p>No detector IDs were supplied.</p>
              )}
              {action.ids.length === 0 && action.product === "incidents" && (
                <p>No incident IDs were supplied.</p>
              )}
              {action.href ? (
                <a
                  className="secondary-button"
                  href={action.href}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {action.linkLabel}
                </a>
              ) : (
                <p role="status">
                  No external link is available. Configure a valid HTTPS
                  Observability Cloud origin.
                </p>
              )}
            </section>
          </li>
        ))}
      </ol>
      <p>
        Detector and incident IDs are displayed for manual lookup only. Atlas
        does not query Observability Cloud alerts or infer that an event belongs
        to this service.
      </p>
    </section>
  );
}
