import React, { useState } from 'react';
import type { FileEvent } from '../types';
import { FileText, Download, FileCode, AlertCircle, Loader2 } from 'lucide-react';
import { triggerReportDownload } from '../services/api';

interface EventTimelineProps {
  events: FileEvent[];
}

function getEventBadge(type: string): string {
  switch (type.toLowerCase()) {
    case 'created':  return 'bg-[#39ff14]/10 text-[#39ff14] border-[#39ff14]/30';
    case 'modified': return 'bg-[#8b5cf6]/10 text-[#8b5cf6] border-[#8b5cf6]/30';
    case 'renamed':  return 'bg-[#ef4444]/10 text-[#ef4444] border-[#ef4444]/30';
    case 'deleted':  return 'bg-soc-800      text-soc-400    border-soc-700';
    default:         return 'bg-[#39ff14]/10 text-[#39ff14] border-[#39ff14]/30';
  }
}

function entropyClass(h: number | null | undefined): string {
  if (h == null) return 'text-soc-600';
  if (h >= 7.0) return 'text-[#ef4444] font-bold';
  if (h >= 5.5) return 'text-[#8b5cf6]';
  return 'text-soc-400';
}

export const EventTimeline: React.FC<EventTimelineProps> = ({ events }) => {
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportFormat, setExportFormat] = useState<'pdf' | 'csv' | 'json'>('pdf');

  const handleExport = async (format: 'pdf' | 'csv' | 'json') => {
    setIsExporting(true);
    setExportError(null);
    try {
      await triggerReportDownload(undefined, format);
    } catch (err: any) {
      setExportError(err.message || `Report export (${format}) failed`);
    } finally {
      setIsExporting(false);
    }
  };

  const processedEvents = [...events]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 100);

  return (
    <div className="soc-panel p-3 flex flex-col h-full min-h-0">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-2 border-b border-white/5 shrink-0">
        <div>
          <h2 className="soc-heading flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-[#8b5cf6]" />
            File Activity &amp; Process Timeline
          </h2>
        </div>

        <div className="flex items-center gap-2">
          {exportError && (
            <span className="flex items-center gap-1 text-2xs font-mono text-[#ef4444]">
              <AlertCircle className="w-3 h-3" />
              {exportError}
            </span>
          )}
          <div className="flex items-center gap-2 bg-[#8b5cf6]/10 rounded border border-[#8b5cf6]/30 overflow-hidden pr-1">
            <select
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value as any)}
              disabled={isExporting}
              className="
                bg-transparent text-[#8b5cf6] text-[0.70rem] font-mono uppercase font-bold tracking-wide 
                px-2 py-1 outline-none appearance-none cursor-pointer border-r border-[#8b5cf6]/30
                disabled:opacity-50 disabled:cursor-not-allowed
              "
              title="Select Export Format"
            >
              <option value="pdf" className="bg-[#0A0A0A] text-[#8b5cf6]">PDF</option>
              <option value="csv" className="bg-[#0A0A0A] text-[#8b5cf6]">CSV</option>
              <option value="json" className="bg-[#0A0A0A] text-[#8b5cf6]">JSON</option>
            </select>
            <button
              onClick={() => handleExport(exportFormat)}
              disabled={isExporting}
              className="
                flex items-center gap-1 pl-1 pr-2 py-1 text-[#8b5cf6] hover:bg-[#8b5cf6]/20 transition-colors 
                text-[0.70rem] font-mono uppercase font-bold tracking-wide
                disabled:opacity-50 disabled:cursor-not-allowed
              "
            >
              {isExporting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
              {isExporting ? 'Wait' : 'Export'}
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto relative h-full w-full mt-2 pr-1">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 bg-[#0A0A0A] z-10 shadow-[0_4px_6px_-1px_rgba(0,0,0,0.5)]">
            <tr className="border-b border-white/5 text-2xs font-mono text-soc-500 uppercase tracking-wider">
              <th className="py-1.5 px-2 text-left font-semibold bg-[#0A0A0A]">Timestamp</th>
              <th className="py-1.5 px-2 text-left font-semibold bg-[#0A0A0A]">Event</th>
              <th className="py-1.5 px-2 text-left font-semibold bg-[#0A0A0A]">File Path</th>
              <th className="py-1.5 px-2 text-left font-semibold bg-[#0A0A0A]">Ext</th>
              <th className="py-1.5 px-2 text-right font-semibold bg-[#0A0A0A]">H (entropy)</th>
            </tr>
          </thead>
          <tbody className="font-mono text-2xs text-soc-300">
            {processedEvents.length === 0 ? (
              <tr>
                <td colSpan={5} className="text-center py-6 text-soc-600">
                  <FileCode className="w-4 h-4 mx-auto mb-1.5 opacity-40 text-[#8b5cf6]" />
                  <p>No events in active window.</p>
                </td>
              </tr>
            ) : (
              processedEvents.map((ev, idx) => (
                <tr key={ev.id || idx} className="soc-row hover:bg-white/[0.02] transition-colors">
                  <td className="py-1.5 px-2 whitespace-nowrap text-soc-500 tabular-nums">
                    {new Date(ev.timestamp).toLocaleTimeString([], {
                      hour: '2-digit', minute: '2-digit', second: '2-digit',
                    })}
                  </td>
                  <td className="py-1.5 px-2 whitespace-nowrap">
                    <span className={`soc-badge ${getEventBadge(ev.event_type)}`}>
                      {ev.event_type}
                    </span>
                  </td>
                  <td className="py-1.5 px-2 max-w-[12rem]">
                    <span className="truncate block text-soc-300 truncate-mono" title={ev.file_path}>
                      {ev.file_path}
                    </span>
                    {ev.destination_path && (
                      <span className="block text-soc-500 truncate-mono truncate mt-0.5" title={ev.destination_path}>
                        → {ev.destination_path}
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 px-2 whitespace-nowrap text-soc-500">
                    {ev.file_extension || <span className="text-soc-700">—</span>}
                  </td>
                  <td className={`py-1.5 px-2 whitespace-nowrap text-right tabular-nums ${entropyClass(ev.entropy_score)}`}>
                    {ev.entropy_score != null
                      ? ev.entropy_score.toFixed(2)
                      : <span className="text-soc-700">—</span>
                    }
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
