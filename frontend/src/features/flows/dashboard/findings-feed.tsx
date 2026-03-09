import { AlertTriangle, Bug, Info, ShieldAlert, ShieldX } from 'lucide-react';
import { useState } from 'react';

import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import type { FindingEvent } from '@/hooks/use-flow-events';
import { cn } from '@/lib/utils';

const severityConfig: Record<string, { icon: React.ReactNode; color: string; bg: string }> = {
    CRITICAL: {
        bg: 'bg-red-500/10',
        color: 'text-red-500 border-red-500/30',
        icon: <ShieldX className="size-3.5" />,
    },
    HIGH: {
        bg: 'bg-orange-500/10',
        color: 'text-orange-500 border-orange-500/30',
        icon: <ShieldAlert className="size-3.5" />,
    },
    INFO: {
        bg: 'bg-blue-500/10',
        color: 'text-blue-500 border-blue-500/30',
        icon: <Info className="size-3.5" />,
    },
    LOW: {
        bg: 'bg-yellow-500/10',
        color: 'text-yellow-500 border-yellow-500/30',
        icon: <Bug className="size-3.5" />,
    },
    MEDIUM: {
        bg: 'bg-amber-500/10',
        color: 'text-amber-500 border-amber-500/30',
        icon: <AlertTriangle className="size-3.5" />,
    },
};

interface FindingsFeedProps {
    findings: FindingEvent[];
}

const FindingsFeed = ({ findings }: FindingsFeedProps) => {
    const [expandedId, setExpandedId] = useState<null | string>(null);

    if (findings.length === 0) {
        return (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                No findings yet — waiting for results...
            </div>
        );
    }

    return (
        <ScrollArea className="h-full">
            <div className="flex flex-col gap-2 pr-4">
                {findings.map((finding) => {
                    const sev = severityConfig[finding.severity] ?? severityConfig.MEDIUM;
                    const isExpanded = expandedId === finding.id;

                    return (
                        <button
                            className={cn(
                                'flex w-full flex-col gap-1.5 rounded-lg border p-3 text-left transition-colors hover:bg-accent/50',
                                isExpanded && 'bg-accent/30',
                            )}
                            key={finding.id}
                            onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                        >
                            <div className="flex items-start gap-2">
                                <Badge
                                    className={cn('shrink-0 gap-1', sev.color)}
                                    variant="outline"
                                >
                                    {sev.icon}
                                    {finding.severity}
                                </Badge>
                                <span className="line-clamp-2 flex-1 text-sm font-medium">{finding.title}</span>
                            </div>
                            {isExpanded && (
                                <div className="mt-1 flex flex-col gap-1 text-xs text-muted-foreground">
                                    {finding.vuln_type && (
                                        <span>
                                            <strong>Type:</strong> {finding.vuln_type}
                                        </span>
                                    )}
                                    {finding.target && (
                                        <span>
                                            <strong>Target:</strong> {finding.target}
                                        </span>
                                    )}
                                    <span>
                                        <strong>ID:</strong> {finding.id}
                                    </span>
                                </div>
                            )}
                        </button>
                    );
                })}
            </div>
        </ScrollArea>
    );
};

export default FindingsFeed;
