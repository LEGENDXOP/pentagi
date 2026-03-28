import { AlertCircle, ArrowLeft, Radio, WifiOff } from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import AgentActivity from '@/features/flows/dashboard/agent-activity';
import FindingsFeed from '@/features/flows/dashboard/findings-feed';
import PhaseTimeline from '@/features/flows/dashboard/phase-timeline';
import StatsBar from '@/features/flows/dashboard/stats-bar';
import { useFlowEvents } from '@/hooks/use-flow-events';
import { cn } from '@/lib/utils';

const FlowDashboard = () => {
    const { flowId } = useParams<{ flowId: string }>();
    const navigate = useNavigate();
    const state = useFlowEvents(flowId);

    return (
        <div className="min-h-screen bg-background">
            {/* Header */}
            <header className="sticky top-0 z-10 flex h-14 items-center gap-4 border-b bg-background/95 px-6 backdrop-blur supports-[backdrop-filter]:bg-background/60">
                <Button
                    onClick={() => navigate(`/flows/${flowId}`)}
                    size="icon"
                    variant="ghost"
                >
                    <ArrowLeft className="size-4" />
                </Button>

                <div className="flex flex-1 items-center gap-3">
                    <h1 className="text-lg font-semibold">Flow Dashboard</h1>
                    <Badge
                        className="gap-1"
                        variant="outline"
                    >
                        #{flowId}
                    </Badge>
                </div>

                {/* Connection status */}
                <div
                    className={cn(
                        'flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium',
                        state.connected
                            ? 'border-green-500/30 bg-green-500/10 text-green-600 dark:text-green-400'
                            : 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400',
                    )}
                >
                    {state.connected ? (
                        <>
                            <Radio className="size-3" />
                            Live
                        </>
                    ) : (
                        <>
                            <WifiOff className="size-3" />
                            Disconnected
                        </>
                    )}
                </div>
            </header>

            {/* Dashboard content */}
            <div className="mx-auto flex max-w-7xl flex-col gap-6 p-6">
                {/* Error banner */}
                {state.error && (
                    <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-600 dark:text-amber-400">
                        <AlertCircle className="size-4 shrink-0" />
                        {state.error}
                    </div>
                )}

                {/* Phase Timeline */}
                <Card>
                    <CardHeader className="pb-2">
                        <CardTitle className="text-base">Phase Progress</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <PhaseTimeline
                            currentPhase={state.phase?.phase ?? null}
                            flowStatus={state.phase?.status ?? null}
                        />
                    </CardContent>
                </Card>

                {/* Stats Bar */}
                <StatsBar metrics={state.metrics} />

                {/* Agent Activity */}
                <AgentActivity
                    activity={state.agentActivity}
                    connected={state.connected}
                />

                {/* Findings Feed */}
                <Card className="flex flex-col">
                    <CardHeader className="pb-2">
                        <div className="flex items-center justify-between">
                            <CardTitle className="text-base">Findings</CardTitle>
                            {state.findings.length > 0 && (
                                <Badge variant="destructive">{state.findings.length}</Badge>
                            )}
                        </div>
                    </CardHeader>
                    <CardContent className="min-h-[200px] flex-1">
                        <FindingsFeed findings={state.findings} />
                    </CardContent>
                </Card>
            </div>
        </div>
    );
};

export default FlowDashboard;
