import { useCallback, useEffect, useRef, useState } from 'react';

import { Log } from '@/lib/log';

// ==================== Event types ====================

export interface PhaseChangeEvent {
    phase: string;
    status: string;
    timestamp: string;
}

export interface FindingEvent {
    id: string;
    severity: string;
    title: string;
    target: string;
    vuln_type: string;
}

export interface CommandEvent {
    cmd_summary: string;
    agent: string;
    status: string;
    exit_code: number;
}

export interface MetricEvent {
    commands_run: number;
    findings_count: number;
    elapsed_seconds: number;
    attacks_done: number;
    attacks_blocked: number;
}

export interface AgentActivityEvent {
    agent_name: string;
    action_summary: string;
}

export interface FlowDashboardState {
    connected: boolean;
    phase: PhaseChangeEvent | null;
    findings: FindingEvent[];
    metrics: MetricEvent | null;
    commands: CommandEvent[];
    agentActivity: AgentActivityEvent | null;
    error: string | null;
}

const initialState: FlowDashboardState = {
    connected: false,
    phase: null,
    findings: [],
    metrics: null,
    commands: [],
    agentActivity: null,
    error: null,
};

/** Max SSE reconnect attempts before giving up. */
const MAX_RECONNECT_ATTEMPTS = 5;
/** Base delay between reconnect attempts (ms). Doubles each attempt. */
const RECONNECT_BASE_DELAY = 2000;

/**
 * Fetch initial dashboard data from REST endpoints as a fallback.
 * This ensures data is shown immediately even before SSE connects.
 */
async function fetchInitialData(flowId: string): Promise<Partial<FlowDashboardState>> {
    const result: Partial<FlowDashboardState> = {};

    try {
        // Fetch progress data (has phase, metrics, etc.)
        const progressResp = await fetch(`/api/v1/flows/${flowId}/progress`, {
            credentials: 'include',
        });
        if (progressResp.ok) {
            const progressBody = await progressResp.json();
            const progress = progressBody.data ?? progressBody;
            if (progress) {
                result.phase = {
                    phase: progress.phase || 'recon',
                    status: progress.status || 'unknown',
                    timestamp: new Date().toISOString(),
                };
                result.metrics = {
                    commands_run: progress.tool_call_count ?? 0,
                    findings_count: progress.findings_count ?? 0,
                    elapsed_seconds: progress.elapsed_seconds ?? 0,
                    attacks_done: progress.attacks_done ?? 0,
                    attacks_blocked: 0,
                };
            }
        }
    } catch (err) {
        Log.warn('Failed to fetch initial progress data:', err);
    }

    try {
        // Fetch findings
        const findingsResp = await fetch(`/api/v1/flows/${flowId}/findings`, {
            credentials: 'include',
        });
        if (findingsResp.ok) {
            const findingsBody = await findingsResp.json();
            const findingsData = findingsBody.data ?? findingsBody;
            if (findingsData?.findings?.length > 0) {
                result.findings = findingsData.findings.map(
                    (f: { description?: string; id?: string; severity?: string; vuln_type?: string }, idx: number) => ({
                        id: f.id ?? `rest-finding-${idx}`,
                        severity: f.severity ?? 'MEDIUM',
                        title: f.description ?? 'Unknown finding',
                        target: '',
                        vuln_type: f.vuln_type ?? '',
                    }),
                );
            }
        }
    } catch (err) {
        Log.warn('Failed to fetch initial findings data:', err);
    }

    return result;
}

/**
 * Hook that connects to the SSE endpoint for a flow and
 * returns the real-time dashboard state.
 *
 * On mount, it also fetches initial data from REST endpoints
 * to ensure the dashboard has data even before SSE events arrive.
 */
export function useFlowEvents(flowId: string | undefined): FlowDashboardState {
    const [state, setState] = useState<FlowDashboardState>(initialState);
    const esRef = useRef<EventSource | null>(null);
    const reconnectAttempts = useRef(0);
    const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    const handlePhaseChange = useCallback((e: MessageEvent) => {
        try {
            const data = JSON.parse(e.data) as PhaseChangeEvent;
            setState((prev) => ({ ...prev, phase: data }));
        } catch (err) {
            Log.error('Failed to parse phase_change event:', err);
        }
    }, []);

    const handleFinding = useCallback((e: MessageEvent) => {
        try {
            const data = JSON.parse(e.data) as FindingEvent;
            setState((prev) => ({
                ...prev,
                findings: [...prev.findings.filter((f) => f.id !== data.id), data],
            }));
        } catch (err) {
            Log.error('Failed to parse finding event:', err);
        }
    }, []);

    const handleCommand = useCallback((e: MessageEvent) => {
        try {
            const data = JSON.parse(e.data) as CommandEvent;
            setState((prev) => ({
                ...prev,
                commands: [...prev.commands.slice(-99), data], // keep last 100
            }));
        } catch (err) {
            Log.error('Failed to parse command event:', err);
        }
    }, []);

    const handleMetric = useCallback((e: MessageEvent) => {
        try {
            const data = JSON.parse(e.data) as MetricEvent;
            setState((prev) => ({ ...prev, metrics: data }));
        } catch (err) {
            Log.error('Failed to parse metric event:', err);
        }
    }, []);

    const handleAgentActivity = useCallback((e: MessageEvent) => {
        try {
            const data = JSON.parse(e.data) as AgentActivityEvent;
            setState((prev) => ({ ...prev, agentActivity: data }));
        } catch (err) {
            Log.error('Failed to parse agent_activity event:', err);
        }
    }, []);

    useEffect(() => {
        if (!flowId) {
            setState(initialState);
            return;
        }

        // Close previous connection and clear reconnect timer
        if (esRef.current) {
            esRef.current.close();
            esRef.current = null;
        }
        if (reconnectTimer.current) {
            clearTimeout(reconnectTimer.current);
            reconnectTimer.current = null;
        }
        reconnectAttempts.current = 0;

        setState(initialState);

        // Fetch initial data from REST endpoints immediately
        fetchInitialData(flowId).then((initialData) => {
            setState((prev) => ({
                ...prev,
                ...initialData,
                // Don't override connected status from SSE
                connected: prev.connected,
            }));
        });

        function connectSSE() {
            const es = new EventSource(`/api/v1/flows/${flowId}/events`, {
                withCredentials: true,
            });
            esRef.current = es;

            es.onopen = () => {
                reconnectAttempts.current = 0;
                setState((prev) => ({ ...prev, connected: true, error: null }));
            };

            es.onerror = (event) => {
                setState((prev) => ({ ...prev, connected: false }));

                // EventSource auto-reconnects, but if it fails repeatedly, we handle it
                if (es.readyState === EventSource.CLOSED) {
                    Log.warn('SSE connection closed');
                    es.close();
                    esRef.current = null;

                    // Attempt manual reconnect with exponential backoff
                    if (reconnectAttempts.current < MAX_RECONNECT_ATTEMPTS) {
                        const delay = RECONNECT_BASE_DELAY * Math.pow(2, reconnectAttempts.current);
                        reconnectAttempts.current++;
                        Log.info(`SSE reconnect attempt ${reconnectAttempts.current}/${MAX_RECONNECT_ATTEMPTS} in ${delay}ms`);
                        reconnectTimer.current = setTimeout(connectSSE, delay);
                    } else {
                        setState((prev) => ({
                            ...prev,
                            error: 'Lost connection to event stream. Data may be stale.',
                        }));
                        Log.error('SSE max reconnect attempts reached');
                    }
                }
            };

            es.addEventListener('phase_change', handlePhaseChange);
            es.addEventListener('finding', handleFinding);
            es.addEventListener('command', handleCommand);
            es.addEventListener('metric', handleMetric);
            es.addEventListener('agent_activity', handleAgentActivity);
            // heartbeat events are handled automatically to keep connection alive
        }

        connectSSE();

        return () => {
            if (esRef.current) {
                esRef.current.close();
                esRef.current = null;
            }
            if (reconnectTimer.current) {
                clearTimeout(reconnectTimer.current);
                reconnectTimer.current = null;
            }
        };
    }, [flowId, handlePhaseChange, handleFinding, handleCommand, handleMetric, handleAgentActivity]);

    return state;
}
