import React, { useState, useCallback, useRef, DragEvent } from 'react';
import {
  Upload,
  FileSearch,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Shield,
  AlertTriangle,
  Hash,
  Info,
  X,
} from 'lucide-react';

// ─── Types ─────────────────────────────────────────────────────────────────

interface AnalysisResult {
  analysis_id: string;
  timestamp: string;
  filename: string;
  file_size_bytes: number;
  file_extension: string;
  entropy_score: number;
  entropy_class: string;
  is_likely_encrypted: boolean;
  is_suspicious_extension: boolean;
  risk_level: 'HIGH' | 'MEDIUM' | 'LOW';
  quarantine_path: string;
}

type DropState = 'idle' | 'hover' | 'uploading' | 'done' | 'error';

// ─── Utilities ──────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

async function uploadForAnalysis(file: File): Promise<AnalysisResult> {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch('/api/v1/analyze', { method: 'POST', body: form });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Server error ${res.status}`);
  }
  return data as AnalysisResult;
}

// ─── Risk theme factory ─────────────────────────────────────────────────────

function getRiskTheme(risk: 'HIGH' | 'MEDIUM' | 'LOW') {
  if (risk === 'HIGH') return {
    panelBorder:  'border-rose-500/50',
    panelBg:      'bg-rose-950/15',
    badgeBg:      'bg-rose-500/15 border-rose-500/40 text-rose-300',
    scoreColor:   'text-rose-400',
    Icon:          ShieldAlert,
    iconColor:    'text-rose-400',
    iconBg:       'bg-rose-950/60 border-rose-500/30',
    label:        'HIGH RISK',
    labelColor:   'text-rose-400',
    glow:         'shadow-critical-glow',
  } as const;

  if (risk === 'MEDIUM') return {
    panelBorder:  'border-amber-500/40',
    panelBg:      'bg-amber-950/10',
    badgeBg:      'bg-amber-500/15 border-amber-500/40 text-amber-300',
    scoreColor:   'text-amber-400',
    Icon:          Shield,
    iconColor:    'text-amber-400',
    iconBg:       'bg-amber-950/60 border-amber-500/30',
    label:        'MEDIUM RISK',
    labelColor:   'text-amber-400',
    glow:         'shadow-warning-glow',
  } as const;

  return {
    panelBorder:  'border-sky-500/30',
    panelBg:      'bg-sky-950/10',
    badgeBg:      'bg-sky-500/15 border-sky-500/40 text-sky-300',
    scoreColor:   'text-sky-400',
    Icon:          ShieldCheck,
    iconColor:    'text-sky-400',
    iconBg:       'bg-sky-950/60 border-sky-500/30',
    label:        'LOW RISK',
    labelColor:   'text-sky-400',
    glow:         'shadow-nominal-glow',
  } as const;
}

// ─── Entropy bar ────────────────────────────────────────────────────────────

function EntropyBar({ score }: { score: number }) {
  const pct = (score / 8.0) * 100;
  const color = score >= 7.0 ? 'bg-rose-500' : score >= 5.5 ? 'bg-amber-400' : 'bg-sky-400';
  return (
    <div className="space-y-1">
      <div className="h-1.5 w-full bg-soc-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex justify-between text-2xs font-mono text-soc-700">
        <span>0.0</span>
        <span className="text-sky-700">5.5</span>
        <span className="text-amber-700">7.0</span>
        <span>8.0</span>
      </div>
    </div>
  );
}

// ─── Result card ────────────────────────────────────────────────────────────

interface ResultCardProps {
  result: AnalysisResult;
  onReset: () => void;
}

const ResultCard: React.FC<ResultCardProps> = ({ result, onReset }) => {
  const theme = getRiskTheme(result.risk_level);
  const { Icon } = theme;

  const rows: [string, React.ReactNode][] = [
    ['Filename',     <span className="truncate max-w-[200px] block" title={result.filename}>{result.filename}</span>],
    ['Extension',    <span className={result.is_suspicious_extension ? 'text-rose-400 font-bold' : ''}>{result.file_extension}</span>],
    ['File Size',    formatBytes(result.file_size_bytes)],
    ['Entropy Class',result.entropy_class],
    ['Encrypted?',   result.is_likely_encrypted
      ? <span className="text-rose-400 font-bold">YES — Likely Encrypted</span>
      : <span className="text-emerald-400">No</span>
    ],
    ['Susp. Ext?',   result.is_suspicious_extension
      ? <span className="text-rose-400 font-bold">YES — IOC Match</span>
      : <span className="text-emerald-400">No</span>
    ],
    ['Quarantine',   <span className="text-soc-600 text-2xs truncate max-w-[200px] block" title={result.quarantine_path}>{result.quarantine_path}</span>],
  ];

  return (
    <div className={`rounded-xl border overflow-hidden transition-all duration-300 ${theme.panelBg} ${theme.panelBorder} ${theme.glow}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-soc-800/60">
        <div className="flex items-center gap-2.5">
          <div className={`p-1.5 rounded-lg border ${theme.iconBg}`}>
            <Icon className={`w-4 h-4 ${theme.iconColor}`} />
          </div>
          <div>
            <p className={`text-sm font-mono font-bold ${theme.labelColor}`}>{theme.label}</p>
            <p className="text-2xs font-mono text-soc-500 tabular-nums">
              {new Date(result.timestamp).toLocaleTimeString()}
            </p>
          </div>
        </div>
        <button
          onClick={onReset}
          title="Analyze another file"
          className="p-1.5 rounded-lg border border-soc-700/50 text-soc-500 hover:text-soc-200 hover:border-soc-600 transition-colors cursor-pointer"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Entropy score */}
      <div className="px-4 pt-4 pb-2">
        <div className="flex items-baseline gap-2 mb-2">
          <Hash className="w-3.5 h-3.5 text-soc-500 shrink-0 mb-0.5" />
          <span className="text-2xs font-mono text-soc-500 uppercase tracking-wider">
            Shannon Entropy
          </span>
        </div>
        <div className={`text-4xl font-black font-mono tracking-tighter ${theme.scoreColor}`}>
          {result.entropy_score.toFixed(4)}
          <span className="text-base font-mono text-soc-600 ml-1">/ 8.0</span>
        </div>
        <div className="mt-3">
          <EntropyBar score={result.entropy_score} />
        </div>
      </div>

      {/* Detail rows */}
      <div className="px-4 pb-4 mt-3 space-y-1.5">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-center justify-between gap-4">
            <span className="text-2xs font-mono text-soc-600 shrink-0">{label}</span>
            <span className="text-2xs font-mono text-soc-300 text-right">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ─── Drop zone ──────────────────────────────────────────────────────────────

interface DropZoneProps {
  dropState: DropState;
  onFiles: (files: FileList) => void;
}

const DropZone: React.FC<DropZoneProps> = ({ dropState, onFiles }) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDraggingOver, setIsDraggingOver] = useState(false);

  const handleDragOver = (e: DragEvent) => { e.preventDefault(); setIsDraggingOver(true); };
  const handleDragLeave = () => setIsDraggingOver(false);
  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setIsDraggingOver(false);
    if (e.dataTransfer.files.length > 0) onFiles(e.dataTransfer.files);
  };
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) onFiles(e.target.files);
  };

  const isUploading = dropState === 'uploading';

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={() => !isUploading && inputRef.current?.click()}
      className={`
        relative flex flex-col items-center justify-center gap-3
        min-h-[180px] rounded-xl border-2 border-dashed
        transition-all duration-200 cursor-pointer select-none
        ${isUploading
          ? 'border-sky-500/40 bg-sky-950/10 cursor-not-allowed'
          : isDraggingOver
          ? 'border-sky-400/70 bg-sky-950/20 scale-[1.01]'
          : 'border-soc-700/60 bg-soc-900/30 hover:border-sky-500/40 hover:bg-sky-950/10'
        }
      `}
    >
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        onChange={handleInputChange}
        disabled={isUploading}
      />

      {isUploading ? (
        <>
          <Loader2 className="w-8 h-8 text-sky-400 animate-spin" />
          <div className="text-center">
            <p className="text-xs font-mono font-semibold text-sky-300">Analyzing artifact...</p>
            <p className="text-2xs font-mono text-soc-500 mt-0.5">Computing entropy & IOC signatures</p>
          </div>
          <div className="absolute bottom-3 left-0 right-0 px-6">
            <div className="h-0.5 w-full bg-soc-800 rounded-full overflow-hidden">
              <div className="h-full bg-sky-500 rounded-full animate-[bar-fill_2s_ease-in-out_infinite]" />
            </div>
          </div>
        </>
      ) : (
        <>
          <div className={`p-3 rounded-xl border transition-colors ${
            isDraggingOver
              ? 'bg-sky-950/60 border-sky-500/40'
              : 'bg-soc-800/60 border-soc-700/50'
          }`}>
            <Upload className={`w-6 h-6 transition-colors ${isDraggingOver ? 'text-sky-400' : 'text-soc-500'}`} />
          </div>
          <div className="text-center px-4">
            <p className={`text-xs font-mono font-semibold transition-colors ${isDraggingOver ? 'text-sky-300' : 'text-soc-300'}`}>
              {isDraggingOver ? 'Release to analyze' : 'Drop artifact here'}
            </p>
            <p className="text-2xs font-mono text-soc-600 mt-0.5">
              or click to browse &bull; max 50 MB
            </p>
          </div>
          <div className="flex items-center gap-3 text-2xs font-mono text-soc-700">
            <span className="flex items-center gap-1">
              <span className="w-1 h-1 rounded-full bg-soc-700" />exe
            </span>
            <span className="flex items-center gap-1">
              <span className="w-1 h-1 rounded-full bg-soc-700" />doc
            </span>
            <span className="flex items-center gap-1">
              <span className="w-1 h-1 rounded-full bg-rose-700" />.locked
            </span>
            <span className="flex items-center gap-1">
              <span className="w-1 h-1 rounded-full bg-rose-700" />.enc
            </span>
            <span className="flex items-center gap-1">
              <span className="w-1 h-1 rounded-full bg-soc-700" />any
            </span>
          </div>
        </>
      )}
    </div>
  );
};

// ─── Main component ─────────────────────────────────────────────────────────

export const ArtifactSandbox: React.FC = () => {
  const [dropState, setDropState] = useState<DropState>('idle');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleFiles = useCallback(async (files: FileList) => {
    const file = files[0];
    if (!file) return;

    setDropState('uploading');
    setResult(null);
    setErrorMsg(null);

    try {
      const data = await uploadForAnalysis(file);
      setResult(data);
      setDropState('done');
    } catch (err: any) {
      setErrorMsg(err.message || 'Analysis failed — backend unreachable.');
      setDropState('error');
    }
  }, []);

  const handleReset = useCallback(() => {
    setDropState('idle');
    setResult(null);
    setErrorMsg(null);
  }, []);

  return (
    <div className="soc-panel p-5 flex flex-col gap-4">

      {/* ── Panel header ── */}
      <div className="flex items-center justify-between pb-3 border-b border-soc-800/60">
        <div className="flex items-center gap-2">
          <FileSearch className="w-3.5 h-3.5 text-sky-400" />
          <h2 className="soc-heading">Artifact Sandbox</h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-live-breathe" />
          <span className="soc-badge bg-soc-800/80 border-soc-700/60 text-soc-500">
            Entropy Analyzer
          </span>
        </div>
      </div>

      {/* ── Info strip ── */}
      <div className="flex items-start gap-2 bg-soc-900/40 border border-soc-800/60 rounded-lg px-3 py-2">
        <Info className="w-3.5 h-3.5 text-sky-500/70 shrink-0 mt-0.5" />
        <p className="text-2xs font-mono text-soc-500 leading-relaxed">
          Drop any suspicious file for instant forensic analysis. Shannon entropy and
          IOC extension matching are run in the sandboxed quarantine zone — no code is executed.
        </p>
      </div>

      {/* ── Drop zone (always visible unless result shown) ── */}
      {dropState !== 'done' && (
        <DropZone dropState={dropState} onFiles={handleFiles} />
      )}

      {/* ── Error message ── */}
      {dropState === 'error' && errorMsg && (
        <div className="flex items-start gap-2.5 p-3 rounded-lg bg-rose-950/15 border border-rose-500/25">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="text-xs font-mono font-semibold text-rose-300">Analysis Failed</p>
            <p className="text-2xs font-mono text-rose-400/80 mt-0.5">{errorMsg}</p>
          </div>
          <button onClick={handleReset} className="text-soc-600 hover:text-soc-400 cursor-pointer">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ── Results card ── */}
      {result && dropState === 'done' && (
        <ResultCard result={result} onReset={handleReset} />
      )}

      {/* ── IOC extension legend ── */}
      {dropState === 'idle' && (
        <div className="flex flex-wrap gap-1.5 pt-1">
          {['.locked', '.enc', '.crypt', '.wncry', '.locky', '.crypto', '.encrypted', '.zepto'].map(ext => (
            <span key={ext} className="px-1.5 py-0.5 text-2xs font-mono rounded bg-rose-950/20 text-rose-500/70 border border-rose-900/40">
              {ext}
            </span>
          ))}
          <span className="text-2xs font-mono text-soc-700 self-center ml-1">+ more IOCs</span>
        </div>
      )}
    </div>
  );
};
