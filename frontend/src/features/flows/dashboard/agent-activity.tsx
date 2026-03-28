import { Bot, Loader2 } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import type { AgentActivityEvent } from '@/hooks/use-flow-events';

interface AgentActivityProps {
    activity: AgentActivityEvent | null;
    connected: boolean;
}

const AgentActivity = ({ activity, connected }: AgentActivityProps) => {
    if (!connected) {
        return (
            <div className="flex items-center gap-2 rounded-lg border border-dashed p-3 text-sm text-muted-foreground">
                <div className="size-2 rounded-full bg-muted-foreground/50" />
                Connecting to event stream...
            </div>
        );
    }

    if (!activity) {
        return (
            <div className="flex items-center gap-2 rounded-lg border border-dashed p-3 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin" />
                Waiting for agent activity...
            </div>
        );
    }

    return (
        <div className="flex items-center gap-3 rounded-lg border bg-card p-3">
            <div className="flex size-8 items-center justify-center rounded-full bg-primary/10">
                <Bot className="size-4 text-primary" />
            </div>
            <div className="flex flex-1 flex-col gap-0.5 overflow-hidden">
                <div className="flex items-center gap-2">
                    <Badge
                        className="shrink-0"
                        variant="secondary"
                    >
                        {activity.agent_name}
                    </Badge>
                    <div className="size-1.5 shrink-0 animate-pulse rounded-full bg-green-500" />
                </div>
                <span className="truncate text-sm text-muted-foreground">{activity.action_summary}</span>
            </div>
        </div>
    );
};

export default AgentActivity;
