import React from 'react';
import type { AlertItem } from '../types';
import { AlertOctagon, ShieldAlert, Info, CheckCircle2, Bell, ShieldCheck } from 'lucide-react';

interface AlertsFeedProps {
  alerts: AlertItem[];
}

const ALERT_STYLES: Record<string, { icon: React.ReactNode; rowClass: string; labelClass: string }> = {
  CRITICAL_THREAT_DETECTED: {
    icon: <AlertOctagon className="w-3.5 h-3.5 text-[#ef4444] shrink-0" />,
    rowClass: 'border-[#ef4444]/20 bg-[#ef4444]/5 hover:border-[#ef4444]/35',
    labelClass: 'text-[#ef4444]',
  },
  NOMINAL_HEARTBEAT: {
    icon: <CheckCircle2 className="w-3.5 h-3.5 text-[#39ff14] shrink-0" />,
    rowClass: 'border-[#39ff14]/10 bg-[#39ff14]/5 hover:border-[#39ff14]/20',
    labelClass: 'text-[#39ff14]',
  },
  SCORE_THRESHOLD_CROSSED: {
    icon: <AlertOctagon className="w-3.5 h-3.5 text-[#ef4444] shrink-0" />,
    rowClass: 'border-[#ef4444]/20 bg-[#ef4444]/5 hover:border-[#ef4444]/35',
    labelClass: 'text-[#ef4444]',
  },
  SHADOW_COPY_DELETION: {
    icon: <AlertOctagon className="w-3.5 h-3.5 text-[#ef4444] shrink-0" />,
    rowClass: 'border-[#ef4444]/20 bg-[#ef4444]/5 hover:border-[#ef4444]/35',
    labelClass: 'text-[#ef4444]',
  },
  RANSOM_NOTE_CREATED: {
    icon: <AlertOctagon className="w-3.5 h-3.5 text-[#ef4444] shrink-0" />,
    rowClass: 'border-[#ef4444]/20 bg-[#ef4444]/5 hover:border-[#ef4444]/35',
    labelClass: 'text-[#ef4444]',
  },
  HIGH_ENTROPY_DETECTED: {
    icon: <ShieldAlert className="w-3.5 h-3.5 text-[#8b5cf6] shrink-0" />,
    rowClass: 'border-[#8b5cf6]/20 bg-[#8b5cf6]/5 hover:border-[#8b5cf6]/35',
    labelClass: 'text-[#8b5cf6]',
  },
  FILE_RENAME_SPIKE: {
    icon: <ShieldAlert className="w-3.5 h-3.5 text-[#8b5cf6] shrink-0" />,
    rowClass: 'border-[#8b5cf6]/20 bg-[#8b5cf6]/5 hover:border-[#8b5cf6]/35',
    labelClass: 'text-[#8b5cf6]',
  },
  SOAR_PLAYBOOK_EXECUTED: {
    icon: <ShieldCheck className="w-3.5 h-3.5 text-[#00e5ff] shrink-0" />,
    rowClass: 'border-[#00e5ff]/30 bg-[#00e5ff]/10 hover:border-[#00e5ff]/50',
    labelClass: 'text-[#00e5ff]',
  },
};

function getAlertStyle(type: string) {
  return ALERT_STYLES[type] ?? {
    icon: <Info className="w-3.5 h-3.5 text-[#39ff14] shrink-0" />,
    rowClass: 'border-white/5 bg-[#111111] hover:border-[#39ff14]/30',
    labelClass: 'text-[#39ff14]',
  };
}

export const AlertsFeed: React.FC<AlertsFeedProps> = ({ alerts }) => {
  return (
    <div className="soc-panel p-3 flex flex-col h-full min-h-0">

      {/* ── Panel header ── */}
      <div className="flex items-center justify-between pb-2 border-b border-white/5 shrink-0">
        <div className="flex items-center gap-1.5">
          <Bell className="w-3.5 h-3.5 text-[#39ff14]" />
          <h2 className="soc-heading">Live Security Alerts</h2>
        </div>
        <div className="flex items-center gap-2">
          {alerts.length > 0 && (
            <span className="w-1.5 h-1.5 rounded-full bg-[#ef4444] animate-live-breathe" />
          )}
          <span className="soc-badge bg-transparent border-white/5 text-soc-400">
            {alerts.length} Events
          </span>
        </div>
      </div>

      {/* ── Alerts list ── */}
      <div className="flex-1 overflow-y-auto space-y-1.5 pr-1 mt-2">
        {alerts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center py-6 gap-2 text-soc-600">
            <CheckCircle2 className="w-5 h-5 text-soc-700" />
            <p className="text-[0.75rem] font-mono">No alerts recorded.</p>
            <p className="text-[0.70rem] font-mono text-soc-700">Monitoring SSE stream...</p>
          </div>
        ) : (
          alerts.map((alert, idx) => {
            const style = getAlertStyle(alert.alert_type);
            return (
              <div
                key={alert.id || idx}
                className={`
                  flex items-start gap-2 p-2 rounded border transition-all duration-150 animate-slide-in-top
                  ${style.rowClass}
                `}
              >
                <div className="mt-0.5">{style.icon}</div>
                <div className="flex-1 min-w-0">
                  {/* Type + timestamp */}
                  <div className="flex items-center justify-between gap-2">
                    <span className={`text-[0.75rem] font-mono font-bold uppercase tracking-wide truncate ${style.labelClass}`}>
                      {alert.alert_type.replace(/_/g, ' ')}
                    </span>
                    <span className="text-[0.70rem] font-mono text-soc-600 shrink-0 tabular-nums">
                      {new Date(alert.timestamp).toLocaleTimeString([], {
                        hour: '2-digit', minute: '2-digit', second: '2-digit',
                      })}
                    </span>
                  </div>
                  {/* Message */}
                  <p className="text-[0.70rem] text-soc-400 mt-0.5 leading-tight font-mono">
                    {alert.message}
                  </p>
                  {/* Quarantine path badge */}
                  {alert.raw_context?.quarantine_path && (
                    <div className="mt-1 text-[0.70rem] font-mono text-[#ef4444] bg-[#ef4444]/10 border border-[#ef4444]/20 px-1 py-0.5 rounded truncate">
                      ⊠ {alert.raw_context.quarantine_path}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
