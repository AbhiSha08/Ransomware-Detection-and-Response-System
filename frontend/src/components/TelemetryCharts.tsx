import React from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
} from 'recharts';
import type { TelemetryPoint } from '../types';
import { Cpu } from 'lucide-react';

interface TelemetryChartsProps {
  data: TelemetryPoint[];
}

const SocTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-[#000000] border border-white/10 rounded-sm p-2 text-[0.75rem] font-mono shadow-md">
      <p className="text-soc-500 mb-1 tabular-nums">{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: p.color }} />
          <span className="text-soc-400">{p.name}:</span>
          <span className="text-soc-200 font-bold">{p.value?.toFixed(2)}</span>
        </div>
      ))}
    </div>
  );
};

export const TelemetryCharts: React.FC<TelemetryChartsProps> = ({ data }) => {
  const safeData = data.length > 0 ? data : [
    { timeLabel: '-- : --', cpu_percent: 12, avg_entropy: 3.4, threat_score: 10 },
    { timeLabel: '-- : --', cpu_percent: 15, avg_entropy: 3.6, threat_score: 12 },
  ];

  return (
    <div className="soc-panel p-3 flex flex-col h-full">
      <div className="flex items-center justify-between mb-3 shrink-0 border-b border-white/5 pb-2">
        <div>
          <h2 className="soc-heading flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-soc-400" />
            Telemetry &amp; Shannon Entropy Window (60s)
          </h2>
        </div>
        <div className="flex items-center gap-3 text-[0.70rem] font-mono">
          <div className="flex items-center gap-1">
            <span className="w-3 h-0.5 bg-soc-500 rounded" />
            <span className="text-soc-500">CPU %</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-3 h-0.5 bg-[#8b5cf6] rounded" />
            <span className="text-soc-500">Entropy (0–8)</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-3 h-0.5 bg-[#ef4444] rounded border-t border-dashed border-[#ef4444]" />
            <span className="text-soc-500">H ≥ 7.0</span>
          </div>
        </div>
      </div>

      <div className="flex-1 w-full min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={safeData} margin={{ top: 5, right: 5, left: -25, bottom: -5 }}>
            <CartesianGrid
              strokeDasharray="2 4"
              stroke="rgba(255,255,255,0.05)"
              vertical={false}
            />
            <XAxis
              dataKey="timeLabel"
              stroke="#262626"
              tick={{ fill: '#525252', fontSize: 9, fontFamily: 'IBM Plex Mono, monospace' }}
              tickLine={false}
              axisLine={{ stroke: '#171717' }}
            />
            <YAxis
              yAxisId="left"
              domain={[0, 100]}
              stroke="#404040"
              tick={{ fill: '#525252', fontSize: 9, fontFamily: 'IBM Plex Mono, monospace' }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              yAxisId="right"
              orientation="right"
              domain={[0, 8.0]}
              stroke="#8b5cf6"
              tick={{ fill: '#525252', fontSize: 9, fontFamily: 'IBM Plex Mono, monospace' }}
              tickLine={false}
              axisLine={false}
            />
            <ReferenceLine
              yAxisId="right"
              y={7.0}
              stroke="rgba(239,68,68,0.4)"
              strokeDasharray="4 4"
              strokeWidth={1}
            />
            <Tooltip content={<SocTooltip />} />
            <Line
              yAxisId="left"
              type="monotone"
              dataKey="cpu_percent"
              name="CPU %"
              stroke="#525252"
              strokeWidth={1.5}
              dot={false}
              isAnimationActive={false}
            />
            <Line
              yAxisId="right"
              type="monotone"
              dataKey="avg_entropy"
              name="Entropy"
              stroke="#8b5cf6"
              strokeWidth={1.5}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
