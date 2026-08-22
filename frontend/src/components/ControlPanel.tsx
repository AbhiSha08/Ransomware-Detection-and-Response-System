import React, { useState, useCallback } from 'react';
import {
  Play,
  Loader2,
  CheckCircle2,
  XCircle,
  Terminal,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Shield,
  Clock,
  RotateCcw,
} from 'lucide-react';

interface SimulationResult {
  status: 'success' | 'error' | 'timeout';
  message: string;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  duration_seconds: number;
  timestamp: string;
}
type RunState = 'idle' | 'running' | 'success' | 'error';

async function triggerSimulation(): Promise<SimulationResult> {
  const res = await fetch('/api/v1/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  const data: SimulationResult = await res.json();
  if (!res.ok && data.status !== 'error' && data.status !== 'timeout') {
    throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  }
  return data;
}

interface OutputPanelProps {
  result: SimulationResult;
}
const OutputPanel: React.FC<OutputPanelProps> = ({ result }) => {
  const [showOutput, setShowOutput] = useState(false);
  const hasOutput = result.stdout.trim() || result.stderr.trim();

  return (
    <div
      className={`rounded border overflow-hidden transition-all duration-300 ${
        result.status === 'success'
          ? 'border-[#39ff14]/30 bg-[#39ff14]/5'
          : 'border-[#ef4444]/30 bg-[#ef4444]/5'
      }`}
    >
      <div className="flex items-center justify-between p-2">
        <div className="flex items-center gap-1.5">
          {result.status === 'success' ? (
            <CheckCircle2 className="w-3 h-3 text-[#39ff14] shrink-0" />
          ) : (
            <XCircle className="w-3 h-3 text-[#ef4444] shrink-0" />
          )}
          <div>
            <p className={`text-[0.75rem] font-mono font-bold ${
              result.status === 'success' ? 'text-[#39ff14]' : 'text-[#ef4444]'
            }`}>
              {result.message}
            </p>
            <div className="flex items-center gap-2 mt-0.5 text-[0.70rem] font-mono text-soc-500">
              <span className="flex items-center gap-0.5">
                <Clock className="w-2.5 h-2.5" />
                {result.duration_seconds.toFixed(2)}s
              </span>
              <span>exit={result.exit_code ?? 'N/A'}</span>
            </div>
          </div>
        </div>

        {hasOutput && (
          <button
            onClick={() => setShowOutput((v) => !v)}
            className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[0.70rem] font-mono text-soc-400 hover:text-soc-200 border border-white/5 hover:border-white/10 transition-colors"
          >
            <Terminal className="w-2.5 h-2.5" />
            <span>{showOutput ? 'Hide' : 'Log'}</span>
            {showOutput ? <ChevronUp className="w-2.5 h-2.5" /> : <ChevronDown className="w-2.5 h-2.5" />}
          </button>
        )}
      </div>

      {showOutput && hasOutput && (
        <div className="border-t border-white/5 bg-[#000000] p-2 space-y-1.5 max-h-48 overflow-y-auto">
          {result.stdout.trim() && (
            <div>
              <p className="text-[0.70rem] font-mono text-soc-600 uppercase tracking-widest mb-0.5">stdout</p>
              <pre className="text-[0.70rem] font-mono text-[#39ff14]/80 whitespace-pre-wrap break-all leading-tight">
                {result.stdout.trim()}
              </pre>
            </div>
          )}
          {result.stderr.trim() && (
            <div>
              <p className="text-[0.70rem] font-mono text-soc-600 uppercase tracking-widest mb-0.5">stderr</p>
              <pre className="text-[0.70rem] font-mono text-[#ef4444]/80 whitespace-pre-wrap break-all leading-tight">
                {result.stderr.trim()}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface ControlPanelProps {
  onClear: () => void;
}

export const ControlPanel: React.FC<ControlPanelProps> = ({ onClear }) => {
  const [runState, setRunState] = useState<RunState>('idle');
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [networkError, setNetworkError] = useState<string | null>(null);

  const handleSimulate = useCallback(async () => {
    if (runState === 'running') return;
    setRunState('running');
    setResult(null);
    setNetworkError(null);
    try {
      const data = await triggerSimulation();
      setResult(data);
      setRunState(data.status === 'success' ? 'success' : 'error');
    } catch (err: any) {
      setNetworkError(err.message || 'Network error.');
      setRunState('error');
    }
  }, [runState]);

  const isRunning = runState === 'running';

  return (
    <div className="soc-panel p-3 flex flex-col gap-3">
      <div className="flex items-center justify-between pb-2 border-b border-white/5">
        <div className="flex items-center gap-1.5">
          <Shield className="w-3 h-3 text-[#ef4444]" />
          <h2 className="soc-heading text-[#ef4444]/80">SOAR Console</h2>
        </div>
        <span className="soc-badge bg-soc-800/50 border-white/5 text-soc-500">
          Sandbox
        </span>
      </div>

      <div className="bg-[#111111] border border-white/5 rounded px-2 py-1.5 flex items-start gap-1.5">
        <AlertTriangle className="w-3 h-3 text-[#8b5cf6] shrink-0 mt-0.5" />
        <p className="text-[0.70rem] font-mono text-soc-400 leading-tight">
          Exec <code className="text-soc-300">simulate_attack.py</code> via <code className="text-soc-300">/sandbox</code>. Scored in real-time.
        </p>
      </div>

      <button
        id="soar-simulate-btn"
        onClick={handleSimulate}
        disabled={isRunning}
        className={`
          w-full flex items-center justify-center gap-1.5
          px-2 py-1.5 rounded
          font-mono font-semibold text-xs tracking-wide
          border transition-colors cursor-pointer
          ${isRunning
            ? 'bg-[#111111] border-white/5 text-soc-500 cursor-not-allowed'
            : 'bg-[#111111] border-[#ef4444]/30 text-[#ef4444] hover:bg-[#ef4444]/10 active:scale-[0.99]'
          }
        `}
      >
        {isRunning ? (
          <>
            <Loader2 className="w-3.5 h-3.5 animate-spin text-[#ef4444]/60" />
            <span>Executing...</span>
          </>
        ) : (
          <>
            <Play className="w-3.5 h-3.5" />
            <span>Run Simulation</span>
          </>
        )}
      </button>

      <button
        onClick={onClear}
        className="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 rounded font-mono font-semibold text-xs tracking-wide bg-[#111111] border border-white/5 text-soc-500 hover:text-amber-500/80 hover:border-amber-500/20 hover:bg-amber-500/5 transition-colors cursor-pointer active:scale-[0.99]"
      >
        <RotateCcw className="w-3 h-3" />
        <span>Reset Dashboard</span>
      </button>

      {networkError && !result && (
        <div className="flex items-start gap-1.5 p-2 rounded bg-[#ef4444]/10 border border-[#ef4444]/20">
          <XCircle className="w-3 h-3 text-[#ef4444] shrink-0 mt-0.5" />
          <p className="text-[0.75rem] font-mono text-[#ef4444]">{networkError}</p>
        </div>
      )}

      {result && <OutputPanel result={result} />}
    </div>
  );
};
