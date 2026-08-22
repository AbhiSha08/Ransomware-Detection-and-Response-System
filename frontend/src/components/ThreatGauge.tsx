import React, { useEffect, useRef } from 'react';
import { AlertTriangle, ShieldCheck, Activity, Zap, TrendingUp } from 'lucide-react';

interface ThreatGaugeProps {
  score: number;
  severity: string;
}

function getSeverityTheme(score: number, severity: string) {
  const isCritical = score >= 70 || severity === 'CRITICAL';
  const isWarning  = !isCritical && (score >= 40 || ['MEDIUM', 'HIGH', 'LOW'].includes(severity));

  if (isCritical) {
    return {
      panelBorder:   'border-[#ef4444]/60',
      panelBg:       'bg-[#ef4444]/10',
      scoreColor:    'text-[#ef4444]',
      labelColor:    'text-[#ef4444]',
      barColor:      'bg-[#ef4444]',
      badgeBg:       'bg-[#ef4444]/15 border-[#ef4444]/40 text-[#ef4444]',
      iconBg:        'bg-[#ef4444]/10 border-[#ef4444]/30',
      iconColor:     'text-[#ef4444]',
      label:         'CRITICAL THREAT',
      sublabel:      'Immediate response required',
      Icon:          AlertTriangle,
    } as const;
  }

  if (isWarning) {
    return {
      panelBorder:   'border-[#8b5cf6]/40',
      panelBg:       'bg-[#8b5cf6]/10',
      scoreColor:    'text-[#8b5cf6]',
      labelColor:    'text-[#8b5cf6]',
      barColor:      'bg-[#8b5cf6]',
      badgeBg:       'bg-[#8b5cf6]/15 border-[#8b5cf6]/40 text-[#8b5cf6]',
      iconBg:        'bg-[#8b5cf6]/10 border-[#8b5cf6]/30',
      iconColor:     'text-[#8b5cf6]',
      label:         'ELEVATED RISK',
      sublabel:      'Monitoring for escalation',
      Icon:          Activity,
    } as const;
  }

  return {
    panelBorder:   'border-white/5',
    panelBg:       'bg-transparent',
    scoreColor:    'text-[#39ff14]',
    labelColor:    'text-[#39ff14]',
    barColor:      'bg-[#39ff14]',
    badgeBg:       'bg-[#39ff14]/15 border-[#39ff14]/40 text-[#39ff14]',
    iconBg:        'bg-[#39ff14]/10 border-[#39ff14]/30',
    iconColor:     'text-[#39ff14]',
    label:         'NORMAL',
    sublabel:      'No active threat detected',
    Icon:          ShieldCheck,
  } as const;
}

function SegmentBar({ score }: { score: number }) {
  const totalSegments = 20;
  const filled = Math.round((score / 100) * totalSegments);
  return (
    <div className="flex gap-[1px] w-full mt-2">
      {Array.from({ length: totalSegments }).map((_, i) => {
        const pct = ((i + 1) / totalSegments) * 100;
        let color = 'bg-[#171717]';
        if (i < filled) {
          color = pct <= 40 ? 'bg-[#39ff14]' : pct <= 70 ? 'bg-[#8b5cf6]' : 'bg-[#ef4444]';
        }
        return (
          <div
            key={i}
            className={`h-3 flex-1 rounded-[1px] transition-colors duration-300 ${color}`}
          />
        );
      })}
    </div>
  );
}

export const ThreatGauge: React.FC<ThreatGaugeProps> = ({ score, severity }) => {
  const normalizedScore = Math.max(0, Math.min(100, score));
  const isCritical = normalizedScore >= 70 || severity === 'CRITICAL';
  const theme = getSeverityTheme(normalizedScore, severity);
  const { Icon } = theme;

  const audioCtxRef = useRef<AudioContext | null>(null);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (isCritical) {
      if (!audioCtxRef.current) {
        audioCtxRef.current = new (window.AudioContext || (window as any).webkitAudioContext)();
      }
      if (audioCtxRef.current.state === 'suspended') {
        audioCtxRef.current.resume();
      }

      if (!intervalRef.current) {
        intervalRef.current = setInterval(() => {
          if (!audioCtxRef.current) return;
          const osc = audioCtxRef.current.createOscillator();
          const gain = audioCtxRef.current.createGain();
          osc.type = 'sine';
          osc.frequency.setValueAtTime(880, audioCtxRef.current.currentTime);
          
          gain.gain.setValueAtTime(1, audioCtxRef.current.currentTime);
          gain.gain.exponentialRampToValueAtTime(0.001, audioCtxRef.current.currentTime + 0.15);
          
          osc.connect(gain);
          gain.connect(audioCtxRef.current.destination);
          
          osc.start();
          osc.stop(audioCtxRef.current.currentTime + 0.15);
        }, 500);
      }
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }
    
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [isCritical]);

  return (
    <div
      className={`
        relative overflow-hidden border p-4 flex flex-col h-full justify-between transition-colors duration-500
        ${theme.panelBg} ${theme.panelBorder}
        soc-panel
        ${isCritical ? 'animate-pulse shadow-[0_0_30px_rgba(239,68,68,0.4)]' : ''}
      `}
    >
      <div className="absolute -right-6 -bottom-6 opacity-[0.03] pointer-events-none select-none">
        <Icon className="w-48 h-48" />
      </div>

      <div className="flex items-center justify-between z-10 shrink-0">
        <div className="flex items-center gap-1.5">
          <div className={`p-1 rounded border ${theme.iconBg}`}>
            <Zap className={`w-3 h-3 ${theme.iconColor}`} />
          </div>
          <span className="soc-heading">Threat Score Index</span>
        </div>
        <span className={`soc-badge ${theme.badgeBg}`}>
          <span className="w-1 h-1 rounded-full bg-current animate-live-breathe" />
          {severity || 'NORMAL'}
        </span>
      </div>

      <div className="z-10 flex items-end justify-between flex-1 pb-4 pt-6">
        <div>
          <div className="flex items-baseline gap-1">
            <span className={`text-6xl font-black tracking-tighter font-mono leading-none ${theme.scoreColor}`}>
              {normalizedScore.toFixed(0)}
            </span>
            <span className="text-sm font-mono text-soc-600 mb-1">/100</span>
          </div>
          <p className={`text-[0.75rem] font-mono font-bold mt-1 tracking-wider ${theme.labelColor}`}>{theme.label}</p>
          <p className="text-[0.70rem] text-soc-500 font-mono mt-0.5">{theme.sublabel}</p>
        </div>

        <div className="flex flex-col items-end gap-1 text-[0.70rem] font-mono text-soc-500 pb-1">
          <div className="flex items-center gap-1">
            <TrendingUp className="w-2.5 h-2.5 text-[#ef4444]" />
            <span>≥70 = CRITICAL</span>
          </div>
          <div className="flex items-center gap-1">
            <TrendingUp className="w-2.5 h-2.5 text-[#8b5cf6]" />
            <span>≥40 = WARNING</span>
          </div>
          <div className="flex items-center gap-1">
            <TrendingUp className="w-2.5 h-2.5 text-[#39ff14]" />
            <span>&lt;40 = NORMAL</span>
          </div>
        </div>
      </div>

      <div className="z-10 shrink-0">
        <SegmentBar score={normalizedScore} />
        <div className="flex justify-between text-[0.70rem] font-mono text-soc-600 mt-1">
          <span>0</span>
          <span className="text-[#39ff14]">40</span>
          <span className="text-[#8b5cf6]">70</span>
          <span>100</span>
        </div>
      </div>
    </div>
  );
};
