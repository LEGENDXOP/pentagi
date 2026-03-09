import { useCallback, useEffect, useRef, useState } from 'react';

import { axios } from '@/lib/axios';
import { Log } from '@/lib/log';

export type FlowControlStatus = 'running' | 'paused' | 'steered' | 'aborted';

export interface FlowControlState {
    flowId: number;
    status: FlowControlStatus;
    steerMessage?: string;
    updatedAt: string;
}

interface UseFlowControlOptions {
    /** Flow ID to track. Null/undefined disables polling. */
    flowId: null | string;
    /** Polling interval in ms. Default: 3000 */
    pollInterval?: number;
    /** Only poll when the flow is in an active state. Default: true */
    activeOnly?: boolean;
}

interface UseFlowControlReturn {
    /** Current flow control state */
    state: FlowControlState | null;
    /** Whether a control operation is in progress */
    isLoading: boolean;
    /** Last error from a control operation */
    error: string | null;
    /** Pause the flow */
    pause: () => Promise<void>;
    /** Resume the flow */
    resume: () => Promise<void>;
    /** Steer the flow with an operator instruction */
    steer: (message: string) => Promise<void>;
    /** Abort the flow */
    abort: () => Promise<void>;
    /** Force refresh the state */
    refresh: () => Promise<void>;
}

interface ApiResponse<T> {
    data: T;
    status: string;
}

export function useFlowControl({
    flowId,
    pollInterval = 3000,
}: UseFlowControlOptions): UseFlowControlReturn {
    const [state, setState] = useState<FlowControlState | null>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

    const fetchState = useCallback(async () => {
        if (!flowId) return;
        try {
            const res = (await axios.get(`/flows/${flowId}/control/`)) as ApiResponse<FlowControlState>;
            setState(res.data);
        } catch (err) {
            Log.error('Failed to fetch flow control state:', err);
        }
    }, [flowId]);

    // Poll for state changes
    useEffect(() => {
        if (!flowId) {
            setState(null);
            return;
        }

        // Initial fetch
        fetchState();

        intervalRef.current = setInterval(fetchState, pollInterval);
        return () => {
            if (intervalRef.current) {
                clearInterval(intervalRef.current);
            }
        };
    }, [flowId, pollInterval, fetchState]);

    const executeAction = useCallback(
        async (action: string, body?: Record<string, unknown>) => {
            if (!flowId) return;
            setIsLoading(true);
            setError(null);
            try {
                const res = (await axios.post(
                    `/flows/${flowId}/control/${action}`,
                    body,
                )) as ApiResponse<FlowControlState>;
                setState(res.data);
            } catch (err: unknown) {
                const message = err instanceof Error ? err.message : 'Flow control operation failed';
                setError(message);
                Log.error(`Flow control ${action} failed:`, err);
                throw err;
            } finally {
                setIsLoading(false);
            }
        },
        [flowId],
    );

    const pause = useCallback(() => executeAction('pause'), [executeAction]);
    const resume = useCallback(() => executeAction('resume'), [executeAction]);
    const steer = useCallback((message: string) => executeAction('steer', { message }), [executeAction]);
    const abort = useCallback(() => executeAction('abort'), [executeAction]);

    return {
        state,
        isLoading,
        error,
        pause,
        resume,
        steer,
        abort,
        refresh: fetchState,
    };
}
