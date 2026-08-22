import React, { useEffect, useState } from 'react';
import { Activity, ShieldCheck, ShieldAlert, Shield, Clock, Wifi, WifiOff, Radio } from 'lucide-react';
import type { HealthStatus, SystemStatus } from '../types';
import { fetchHealth, fetchStatus } from '../services/api';

interface HeaderProps {
  isConnected: boolean;
}

export const Header: React.FC<HeaderProps> = ({ isConnected }) => {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [currentTime, setCurrentTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const loadSystemData = async () => {
      try {
        const [h, s] = await Promise.all([fetchHealth(), fetchStatus()]);
        setHealth(h);
        setStatus(s);
      } catch (err) {
        console.warn('System status poll warning:', err);
      }
    };
    loadSystemData();
    const pollTimer = setInterval(loadSystemData, 10000);
    return () => clearInterval(pollTimer);
  }, []);

  const responseMode = status?.response_mode || 'simulation';
  const isHealthy = health?.status === 'ok';

  return (
    <header className="
      sticky top-0 z-50
      bg-[#0B0F19]/90 backdrop-blur-glass
      border-b border-soc-800/80
      px-5 py-3
      flex flex-col md:flex-row items-center justify-between gap-3
    ">
      {/* ── Brand ── */}
      <div className="flex items-center gap-3">
        <div className="relative">
          <div className="p-2 bg-sky-950/60 border border-sky-500/30 rounded-lg shadow-nominal-glow">
            <ShieldAlert className="w-5 h-5 text-sky-400" />
          </div>
          {/* Pulse ring on icon */}
          <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-sky-400 animate-live-breathe" />
        </div>
        <div>
          <div className="flex items-baseline gap-2">
            <h1 className="text-base font-bold tracking-tight font-mono text-soc-100">
              RDRS
            </h1>
            <span className="text-sky-400 text-xs font-mono font-normal">v1.0.0</span>
            <span className="px-1.5 py-0.5 text-2xs uppercase font-mono font-bold tracking-wider rounded bg-soc-800/80 text-soc-400 border border-soc-700/60">
              SOC
            </span>
          </div>
          <p className="text-2xs text-soc-500 font-mono leading-none mt-0.5">
            Ransomware Detection &amp; Response System
          </p>
        </div>
      </div>

      {/* ── Center status indicators ── */}
      <div className="flex flex-wrap items-center gap-2 text-2xs font-mono">

        {/* SSE Stream connectivity */}
        <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-full border transition-all duration-300 ${
          isConnected
            ? 'bg-emerald-950/50 border-emerald-500/35 text-emerald-300'
            : 'bg-rose-950/50 border-rose-500/35 text-rose-300'
        }`}>
          {isConnected
            ? <Wifi className="w-3 h-3 animate-live-breathe" />
            : <WifiOff className="w-3 h-3" />
          }
          <span>{isConnected ? 'STREAM LIVE' : 'RECONNECTING'}</span>
        </div>

        {/* Backend health */}
        <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-full border transition-all duration-300 ${
          isHealthy
            ? 'bg-soc-900/60 border-soc-700 text-soc-300'
            : 'bg-amber-950/50 border-amber-500/35 text-amber-300'
        }`}>
          <Activity className={`w-3 h-3 ${isHealthy ? 'text-sky-400' : 'text-amber-400'}`} />
          <span>HEALTH: {health?.status?.toUpperCase() || 'PROBING'}</span>
        </div>

        {/* Response mode */}
        <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-full border transition-all duration-300 ${
          responseMode === 'simulation'
            ? 'bg-sky-950/50 border-sky-500/35 text-sky-300'
            : responseMode === 'alert'
            ? 'bg-amber-950/50 border-amber-500/35 text-amber-300'
            : 'bg-rose-950/50 border-rose-500/35 text-rose-300 animate-critical-pulse'
        }`}>
          {responseMode === 'simulation'
            ? <ShieldCheck className="w-3 h-3 text-sky-400" />
            : responseMode === 'alert'
            ? <Shield className="w-3 h-3 text-amber-400" />
            : <Radio className="w-3 h-3 text-rose-400" />
          }
          <span>MODE: {responseMode.toUpperCase()}</span>
        </div>
      </div>

      {/* ── UTC Clock ── */}
      <div className="flex items-center gap-2 text-2xs font-mono text-soc-500 bg-soc-900/70 border border-soc-800 px-3 py-1.5 rounded-lg">
        <Clock className="w-3 h-3 text-soc-600" />
        <span className="tabular-nums">{currentTime || 'Syncing...'}</span>
      </div>
    </header>
  );
};
