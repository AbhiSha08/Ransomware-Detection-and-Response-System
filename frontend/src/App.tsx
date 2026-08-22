import React, { useEffect, useState } from 'react';
import { useSSE } from './hooks/useSSE';
import { Header } from './components/Header';
import { ThreatGauge } from './components/ThreatGauge';
import { TelemetryCharts } from './components/TelemetryCharts';
import { AlertsFeed } from './components/AlertsFeed';
import { EventTimeline } from './components/EventTimeline';
import { ControlPanel } from './components/ControlPanel';
import { ArtifactSandbox } from './components/ArtifactSandbox';
import { fetchAlerts, fetchEvents } from './services/api';
import { Menu, X } from 'lucide-react';

export const App: React.FC = () => {
  const {
    score,
    severity,
    alerts,
    events,
    telemetryHistory,
    isConnected,
    setAlerts,
    setEvents,
    clearDashboard,
  } = useSSE();
  
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    let isMounted = true;
    const seedInitialData = async () => {
      try {
        const [aData, eData] = await Promise.all([
          fetchAlerts(20),
          fetchEvents(30),
        ]);
        if (!isMounted) return;
        if (aData.items?.length > 0) setAlerts(aData.items);
        if (eData.items?.length > 0) setEvents(eData.items);
      } catch (err) {
        if (isMounted) console.warn('Initial REST seed warning:', err);
      }
    };
    seedInitialData();

    return () => {
      isMounted = false;
    };
  }, [setAlerts, setEvents]);

  return (
    <div className="h-screen w-full bg-[#000000] text-soc-300 flex flex-col overflow-hidden relative">
      <Header isConnected={isConnected} />

      {/* ── Minimal Command Center Toggle ── */}
      <button 
        onClick={() => setDrawerOpen(true)}
        className="absolute left-0 top-1/2 -translate-y-1/2 bg-[#0A0A0A] border border-white/5 border-l-0 px-1 py-6 rounded-r cursor-pointer hover:bg-[#111111] z-40 group shadow-md"
      >
        <div className="writing-vertical-lr rotate-180 flex items-center justify-center gap-2 text-2xs font-mono tracking-widest text-soc-500 group-hover:text-[#8b5cf6] transition-colors">
          <Menu className="w-3 h-3 rotate-90" /> COMMAND CENTER
        </div>
      </button>

      {/* ── Slide-out SOAR Drawer ── */}
      {drawerOpen && (
        <div className="fixed inset-0 z-50 flex">
          <div 
            className="absolute inset-0 bg-black/60 backdrop-blur-sm" 
            onClick={() => setDrawerOpen(false)} 
          />
          <div className="relative w-80 h-full bg-[#0A0A0A] border-r border-white/5 shadow-2xl p-4 flex flex-col gap-4 overflow-y-auto transform transition-transform">
            <div className="flex items-center justify-between border-b border-white/5 pb-2">
              <span className="text-xs font-mono font-bold text-[#8b5cf6]">COMMAND CENTER</span>
              <button onClick={() => setDrawerOpen(false)} className="text-soc-500 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
            <ControlPanel onClear={clearDashboard} />
            <ArtifactSandbox />
          </div>
        </div>
      )}

      {/* ── Main Layout (100vh constraint) ── */}
      <main className="flex-1 flex flex-col p-3 gap-3 w-full h-full min-h-0 overflow-hidden mx-auto max-w-[1800px]">
        
        {/* Row 1: Threat Gauge + Telemetry Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-stretch min-h-[250px] h-1/3">
          <div className="lg:col-span-4 h-full">
            <ThreatGauge score={score} severity={severity} />
          </div>
          <div className="lg:col-span-8 h-full">
            <TelemetryCharts data={telemetryHistory} />
          </div>
        </div>

        {/* Row 2: Alerts Feed + Event Timeline */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 flex-1 min-h-0">
          <div className="lg:col-span-4 h-full min-h-0">
            <AlertsFeed alerts={alerts} />
          </div>
          <div className="lg:col-span-8 h-full min-h-0">
            <EventTimeline events={events} />
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;
