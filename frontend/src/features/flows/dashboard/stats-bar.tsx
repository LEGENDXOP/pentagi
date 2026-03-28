import { Bug, Clock, ShieldBan, Swords, Terminal } from 'lucide-react';
import { useEffect, useState } from 'react';

import type { MetricEvent } from '@/hooks/use-flow-events';
import { cn } from '@/lib/utils';

interface StatsBarProps {
    metrics: MetricEvent | null;
}

function formatElapsed(seconds: number): string {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;

    if (h > 0) {
        return `${h}h ${m}m ${s}s`;
    }

    if (m > 0) {
        return `${m}m ${s}s`;
    }

    return `${s}s`;
}

interface StatItemProps {
    icon: React.ReactNode;
    label: string;
    value: number | string;
    colorClass?: string;
}

const StatItem = ({ colorClass, icon, label, value }: StatItemProps) => (
    <div className="flex flex-col items-center gap-1 px-3 py-2">
        <div className={cn('flex items-center gap-1.5 text-sm font-semibold tabular-nums', colorClass)}>
            {icon}
            {value}
        </div>
        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{label}</span>
    </div>
);

const StatsBar = ({ metrics }: StatsBarProps) => {
    const [elapsed, setElapsed] = useState(metrics?.elapsed_seconds ?? 0);

    // Live elapsed time counter
    useEffect(() => {
        if (metrics) {
            setElapsed(metrics.elapsed_seconds);
        }
    }, [metrics]);

    useEffect(() => {
        const timer = setInterval(() => {
            setElapsed((prev) => prev + 1);
        }, 1000);

        return () => clearInterval(timer);
    }, []);

    const commands = metrics?.commands_run ?? 0;
    const findings = metrics?.findings_count ?? 0;
    const attacksDone = metrics?.attacks_done ?? 0;
    const attacksBlocked = metrics?.attacks_blocked ?? 0;

    return (
        <div className="flex items-center justify-around rounded-lg border bg-card">
            <StatItem
                icon={<Terminal className="size-4" />}
                label="Commands"
                value={commands}
            />
            <div className="h-8 w-px bg-border" />
            <StatItem
                colorClass={findings > 0 ? 'text-red-500' : undefined}
                icon={<Bug className="size-4" />}
                label="Findings"
                value={findings}
            />
            <div className="h-8 w-px bg-border" />
            <StatItem
                icon={<Clock className="size-4" />}
                label="Elapsed"
                value={formatElapsed(elapsed)}
            />
            <div className="h-8 w-px bg-border" />
            <StatItem
                icon={<Swords className="size-4" />}
                label="Attacks Done"
                value={attacksDone}
            />
            <div className="h-8 w-px bg-border" />
            <StatItem
                colorClass={attacksBlocked > 0 ? 'text-amber-500' : undefined}
                icon={<ShieldBan className="size-4" />}
                label="Blocked"
                value={attacksBlocked}
            />
        </div>
    );
};

export default StatsBar;
