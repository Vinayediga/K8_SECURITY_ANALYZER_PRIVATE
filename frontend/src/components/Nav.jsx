const PANES = [
  ["overview", "🏠 Overview"],
  ["graph", "🕸️ Attack Graph"],
  ["findings", "🛡️ Findings"],
  ["paths", "🛣️ Attack Paths"],
  ["risk", "🎯 Risk & Impact"],
  ["mitigation", "🔧 Mitigation"],
];

export default function Nav({ pane, setPane, showClusters }) {
  const items = showClusters ? [["clusters", "🖥️ Clusters & Scans"], ...PANES] : PANES;
  return (
    <nav id="nav" aria-label="Main navigation">
      {items.map(([key, label]) => (
        <button key={key} className={`nav-btn ${pane === key ? "active" : ""}`} onClick={() => setPane(key)}>
          {label}
        </button>
      ))}
    </nav>
  );
}
