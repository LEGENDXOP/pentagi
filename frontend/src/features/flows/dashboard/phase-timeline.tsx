import { Check, Circle, Loader2 } from 'lucide-react';

import { cn } from '@/lib/utils';

const PHASES = [
    { key: 'recon', label: 'Recon' },
    { key: 'auth', label: 'Auth' },
    { key: 'triage', label: 'Triage' },
    { key: 'deep_dive', label: 'Deep Dive' },
    { key: 'chains', label: 'Chains' },
    { key: 'report', label: 'Report' },
] as const;

interface PhaseTimelineProps {
    currentPhase: string | null;
    flowStatus: string | null;
}

const PhaseTimeline = ({ currentPhase, flowStatus }: PhaseTimelineProps) => {
    const currentIndex = PHASES.findIndex((p) => p.key === currentPhase);
    const isFinished = flowStatus === 'finished';

    return (
        <div className="flex w-full items-center justify-between gap-1">
            {PHASES.map((phase, idx) => {
                const isActive = idx === currentIndex && !isFinished;
                const isCompleted = isFinished || (currentIndex >= 0 && idx < currentIndex);
                const isPending = !isActive && !isCompleted;

                return (
                    <div
                        className="flex flex-1 flex-col items-center gap-1.5"
                        key={phase.key}
                    >
                        {/* Connector + circle */}
                        <div className="flex w-full items-center">
                            {/* Left connector */}
                            {idx > 0 && (
                                <div
                                    className={cn(
                                        'h-0.5 flex-1 transition-colors duration-500',
                                        isCompleted || isActive ? 'bg-primary' : 'bg-muted',
                                    )}
                                />
                            )}
                            {idx === 0 && <div className="flex-1" />}

                            {/* Phase indicator */}
                            <div
                                className={cn(
                                    'flex size-8 shrink-0 items-center justify-center rounded-full border-2 transition-all duration-500',
                                    isCompleted && 'border-primary bg-primary text-primary-foreground',
                                    isActive && 'border-primary bg-primary/10 text-primary',
                                    isPending && 'border-muted bg-muted/30 text-muted-foreground',
                                )}
                            >
                                {isCompleted && <Check className="size-4" />}
                                {isActive && <Loader2 className="size-4 animate-spin" />}
                                {isPending && <Circle className="size-3" />}
                            </div>

                            {/* Right connector */}
                            {idx < PHASES.length - 1 && (
                                <div
                                    className={cn(
                                        'h-0.5 flex-1 transition-colors duration-500',
                                        isCompleted ? 'bg-primary' : 'bg-muted',
                                    )}
                                />
                            )}
                            {idx === PHASES.length - 1 && <div className="flex-1" />}
                        </div>

                        {/* Label */}
                        <span
                            className={cn(
                                'text-xs font-medium transition-colors',
                                isActive && 'text-primary',
                                isCompleted && 'text-primary',
                                isPending && 'text-muted-foreground',
                            )}
                        >
                            {phase.label}
                        </span>
                    </div>
                );
            })}
        </div>
    );
};

export default PhaseTimeline;
