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
}

const initialState: FlowDashboardState = {
    connected: false,
    phase: null,
    findings: [],
    metrics: null,
    commands: [],
    agentActivity: null,
};

/**
 * Hook that connects to the SSE endpoint for a flow and
 * returns the real-time dashboard state.
 */
export function useFlowEvents(flowId: string | undefined): FlowDashboardState {
    const [state, setState] = useState<FlowDashboardState>(initialState);
    const esRef = useRef<EventSource | null>(null);

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

        // Close previous connection
        if (esRef.current) {
            esRef.current.close();
        }

        setState(initialState);

        const es = new EventSource(`/api/v1/flows/${flowId}/events`, {
            withCredentials: true,
        });
        esRef.current = es;

        es.onopen = () => {
            setState((prev) => ({ ...prev, connected: true }));
        };

        es.onerror = () => {
            setState((prev) => ({ ...prev, connected: false }));
        };

        es.addEventListener('phase_change', handlePhaseChange);
        es.addEventListener('finding', handleFinding);
        es.addEventListener('command', handleCommand);
        es.addEventListener('metric', handleMetric);
        es.addEventListener('agent_activity', handleAgentActivity);
        // heartbeat events are handled automatically to keep connection alive

        return () => {
            es.close();
            esRef.current = null;
        };
    }, [flowId, handlePhaseChange, handleFinding, handleCommand, handleMetric, handleAgentActivity]);

    return state;
}
