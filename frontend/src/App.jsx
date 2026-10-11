import { useCallback, useEffect, useRef, useState } from "react";
import { GraphProvider, useGraph } from "./context/GraphContext.jsx";
import { api, getToken, setToken, setUnauthorizedHandler } from "./lib/api.js";
import LoginScreen from "./components/LoginScreen.jsx";
import TopBar from "./components/TopBar.jsx";
import Nav from "./components/Nav.jsx";
import OverviewPane from "./components/OverviewPane.jsx";
import GraphPane from "./components/GraphPane.jsx";
import FindingsPane from "./components/FindingsPane.jsx";
import PathsPane from "./components/PathsPane.jsx";
import RiskPane from "./components/RiskPane.jsx";
import MitigationPane from "./components/MitigationPane.jsx";
import ClustersPane from "./components/ClustersPane.jsx";

function Shell() {
  const { loadSample, clearGraph } = useGraph();
  const [user, setUser] = useState(null);
  const [offline, setOffline] = useState(false);
  const [booting, setBooting] = useState(Boolean(getToken()));
  const [pane, setPane] = useState("overview");
  const [view, setView] = useState({ showSystem: true, showTopology: true, layout: "dagre" });
  const graphRef = useRef(null);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    setOffline(false);
    clearGraph();
  }, [clearGraph]);

  // Any 401 from the API (expired 15-minute token) lands here.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      clearGraph();
    });
  }, [clearGraph]);

  // Restore an existing session on page load.
  useEffect(() => {
    if (!getToken()) return;
    api.me()
      .then((me) => {
        setUser(me);
        setPane("clusters");
      })
      .catch(() => setToken(null))
      .finally(() => setBooting(false));
  }, []);

  const handleLoggedIn = (me) => {
    setUser(me);
    setPane("clusters");
  };

  const handleOffline = () => {
    setOffline(true);
    setPane("overview");
    loadSample();
  };

  if (booting) return <div className="grid h-screen place-items-center text-sm" style={{ color: "var(--text-dim)" }}>Restoring session…</div>;
  if (!user && !offline) return <LoginScreen onLoggedIn={handleLoggedIn} onOffline={handleOffline} />;

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <TopBar
        user={user}
        offline={offline}
        pane={pane}
        view={view}
        setView={setView}
        graphRef={graphRef}
        onLogout={logout}
      />
      <Nav pane={pane} setPane={setPane} showClusters={Boolean(user)} />
      <main id="app">
        {pane === "overview" && <OverviewPane />}
        {pane === "graph" && <GraphPane ref={graphRef} view={view} />}
        {pane === "findings" && <FindingsPane />}
        {pane === "paths" && <PathsPane goToGraph={() => setPane("graph")} />}
        {pane === "risk" && <RiskPane />}
        {pane === "mitigation" && <MitigationPane />}
        {pane === "clusters" && user && <ClustersPane onLoaded={() => setPane("overview")} />}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <GraphProvider>
      <Shell />
    </GraphProvider>
  );
}
