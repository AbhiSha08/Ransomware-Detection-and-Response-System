import { useEffect, useRef, useState } from 'react';
import type { AlertItem, FileEvent, TelemetryPoint } from '../types';

export function useSSE() {
  const [score, setScore] = useState<number>(0);
  const [severity, setSeverity] = useState<string>('NOMINAL');
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [events, setEvents] = useState<FileEvent[]>([]);
  const [telemetryHistory, setTelemetryHistory] = useState<TelemetryPoint[]>([]);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  const connect = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const es = new EventSource('/api/v1/stream');
    eventSourceRef.current = es;

    es.onopen = () => {
      setIsConnected(true);
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
    };

    es.addEventListener('connected', () => {
      setIsConnected(true);
    });

    es.addEventListener('score_update', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        const newScore = typeof data.score === 'number' ? data.score : 0;
        const newSev = data.severity || 'NOMINAL';

        setScore(newScore);
        setSeverity(newSev);

        const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

        setTelemetryHistory((prev: TelemetryPoint[]) => {
          const point: TelemetryPoint = {
            timestamp: data.timestamp || new Date().toISOString(),
            timeLabel: nowStr,
            cpu_percent: Math.round(Math.random() * 25 + (newScore > 50 ? 40 : 10)),
            avg_entropy: Number((Math.min(8.0, 3.5 + (newScore / 100) * 4.2)).toFixed(2)),
            threat_score: newScore,
          };
          const updated = [...prev, point];
          return updated.slice(-20); // Keep last 20 data points (~60-100s)
        });
      } catch (err) {
        console.error('Failed to parse score_update event', err);
      }
    });

    es.addEventListener('alert', (e: MessageEvent) => {
      try {
        const newAlert: AlertItem = JSON.parse(e.data);
        setAlerts((prev: AlertItem[]) => [newAlert, ...prev].slice(0, 100));
      } catch (err) {
        console.error('Failed to parse alert event', err);
      }
    });

    es.addEventListener('file_event', (e: MessageEvent) => {
      try {
        const newEvent: FileEvent = JSON.parse(e.data);
        setEvents((prev: FileEvent[]) => [newEvent, ...prev].slice(0, 100));
      } catch (err) {
        console.error('Failed to parse file_event', err);
      }
    });

    es.onerror = () => {
      setIsConnected(false);
      es.close();

      // Schedule automatic reconnect in 3 seconds
      if (!reconnectTimeoutRef.current) {
        reconnectTimeoutRef.current = window.setTimeout(() => {
          reconnectTimeoutRef.current = null;
          connect();
        }, 3000);
      }
    };
  };

  useEffect(() => {
    connect();

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, []);

  const addManualEvent = (event: FileEvent) => {
    setEvents((prev: FileEvent[]) => [event, ...prev].slice(0, 100));
  };

  const addManualAlert = (alert: AlertItem) => {
    setAlerts((prev: AlertItem[]) => [alert, ...prev].slice(0, 100));
  };

  const clearDashboard = async () => {
    try {
      await fetch('/api/v1/reset', { method: 'POST' });
    } catch (err) {
      console.error('Failed to trigger backend reset:', err);
    }
    
    setScore(4);
    setSeverity('NOMINAL');
    setAlerts([]);
    setEvents([]);
    setTelemetryHistory([]);
  };

  return {
    score,
    severity,
    alerts,
    events,
    telemetryHistory,
    isConnected,
    setScore,
    setSeverity,
    setAlerts,
    setEvents,
    addManualEvent,
    addManualAlert,
    clearDashboard,
  };
}
