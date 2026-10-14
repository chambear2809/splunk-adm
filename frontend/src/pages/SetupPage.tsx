export function SetupPage() {
  return (
    <main className="atlas-page">
      <h1>Setup</h1>
      <p>Administrator access is required to configure Application Atlas.</p>
      <p>
        Set the index macros, populate the observer scope KV store with
        lower-case observer keys, and enable the builder searches using the
        operator setup guide. Prune searches must stay disabled until recovery
        policy is reviewed.
      </p>
      <p>On Splunk Cloud, create indexes through Admin Config Service (ACS).</p>
      <p>The interactive setup checklist will be added in the setup phase.</p>
    </main>
  );
}
