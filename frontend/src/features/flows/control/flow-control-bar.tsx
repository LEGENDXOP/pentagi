import { AlertTriangle, MessageSquareWarning, OctagonX, Pause, Play, Send } from 'lucide-react';
import { useCallback, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import type { FlowControlStatus } from '@/hooks/use-flow-control';
import { useFlowControl } from '@/hooks/use-flow-control';
import { StatusType } from '@/graphql/types';

interface FlowControlBarProps {
    flowId: null | string;
    /** The GraphQL flow status — control bar only shows for active flows */
    flowStatus?: StatusType;
}

const statusConfig: Record<
    FlowControlStatus,
    { color: string; label: string; variant: 'default' | 'destructive' | 'outline' | 'secondary' }
> = {
    running: { color: 'bg-green-500', label: 'Running', variant: 'default' },
    paused: { color: 'bg-yellow-500', label: 'Paused', variant: 'secondary' },
    steered: { color: 'bg-blue-500', label: 'Steered', variant: 'outline' },
    aborted: { color: 'bg-red-500', label: 'Aborted', variant: 'destructive' },
};

const FlowControlBar = ({ flowId, flowStatus }: FlowControlBarProps) => {
    const { state, isLoading, pause, resume, steer, abort } = useFlowControl({
        flowId,
        pollInterval: 2000,
    });
    const [steerMessage, setSteerMessage] = useState('');
    const [showAbortDialog, setShowAbortDialog] = useState(false);

    // Only show for active flows
    const isActive = flowStatus === StatusType.Running || flowStatus === StatusType.Waiting;
    if (!isActive || !flowId) {
        return null;
    }

    const currentStatus = state?.status ?? 'running';
    const config = statusConfig[currentStatus];
    const isPaused = currentStatus === 'paused';
    const isAborted = currentStatus === 'aborted';

    const handlePauseResume = async () => {
        try {
            if (isPaused) {
                await resume();
                toast.success('Flow resumed');
            } else {
                await pause();
                toast.success('Flow paused');
            }
        } catch {
            toast.error(`Failed to ${isPaused ? 'resume' : 'pause'} flow`);
        }
    };

    const handleSteer = async () => {
        if (!steerMessage.trim()) return;
        try {
            await steer(steerMessage.trim());
            setSteerMessage('');
            toast.success('Operator instruction sent');
        } catch {
            toast.error('Failed to steer flow');
        }
    };

    const handleSteerKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSteer();
        }
    };

    const handleAbort = async () => {
        try {
            await abort();
            setShowAbortDialog(false);
            toast.success('Flow abort signal sent');
        } catch {
            toast.error('Failed to abort flow');
        }
    };

    return (
        <div className="flex items-center gap-2 rounded-lg border bg-card p-2 shadow-sm">
            {/* Status Badge */}
            <TooltipProvider>
                <Tooltip>
                    <TooltipTrigger>
                        <Badge
                            className="gap-1.5"
                            variant={config.variant}
                        >
                            <span className={`size-2 rounded-full ${config.color}`} />
                            {config.label}
                        </Badge>
                    </TooltipTrigger>
                    <TooltipContent>
                        <p>Flow control status: {config.label}</p>
                        {state?.steerMessage && <p className="text-xs opacity-70">Last steer: {state.steerMessage}</p>}
                    </TooltipContent>
                </Tooltip>
            </TooltipProvider>

            {/* Pause/Resume Button */}
            <TooltipProvider>
                <Tooltip>
                    <TooltipTrigger asChild>
                        <Button
                            disabled={isLoading || isAborted}
                            onClick={handlePauseResume}
                            size="sm"
                            variant={isPaused ? 'default' : 'outline'}
                        >
                            {isPaused ? <Play className="size-4" /> : <Pause className="size-4" />}
                            <span className="sr-only">{isPaused ? 'Resume' : 'Pause'}</span>
                        </Button>
                    </TooltipTrigger>
                    <TooltipContent>{isPaused ? 'Resume execution' : 'Pause execution'}</TooltipContent>
                </Tooltip>
            </TooltipProvider>

            {/* Steer Input */}
            <div className="flex flex-1 items-center gap-1">
                <div className="relative flex-1">
                    <MessageSquareWarning className="absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                        className="h-8 pl-8 text-sm"
                        disabled={isLoading || isAborted}
                        onChange={(e) => setSteerMessage(e.target.value)}
                        onKeyDown={handleSteerKeyDown}
                        placeholder="Steer: inject operator instruction..."
                        value={steerMessage}
                    />
                </div>
                <TooltipProvider>
                    <Tooltip>
                        <TooltipTrigger asChild>
                            <Button
                                disabled={isLoading || isAborted || !steerMessage.trim()}
                                onClick={handleSteer}
                                size="sm"
                                variant="outline"
                            >
                                <Send className="size-4" />
                                <span className="sr-only">Send steer instruction</span>
                            </Button>
                        </TooltipTrigger>
                        <TooltipContent>Send instruction to the agent</TooltipContent>
                    </Tooltip>
                </TooltipProvider>
            </div>

            {/* Abort Button with Confirmation */}
            <Dialog
                onOpenChange={setShowAbortDialog}
                open={showAbortDialog}
            >
                <TooltipProvider>
                    <Tooltip>
                        <TooltipTrigger asChild>
                            <DialogTrigger asChild>
                                <Button
                                    disabled={isLoading || isAborted}
                                    size="sm"
                                    variant="destructive"
                                >
                                    <OctagonX className="size-4" />
                                    <span className="sr-only">Abort</span>
                                </Button>
                            </DialogTrigger>
                        </TooltipTrigger>
                        <TooltipContent>Abort flow (graceful shutdown)</TooltipContent>
                    </Tooltip>
                </TooltipProvider>

                <DialogContent>
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <AlertTriangle className="size-5 text-destructive" />
                            Abort Flow
                        </DialogTitle>
                        <DialogDescription>
                            This will gracefully abort the flow execution. The agent will write its current state,
                            collect evidence, and exit. This action cannot be undone.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <DialogClose asChild>
                            <Button variant="outline">Cancel</Button>
                        </DialogClose>
                        <Button
                            disabled={isLoading}
                            onClick={handleAbort}
                            variant="destructive"
                        >
                            Abort Flow
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
};

export default FlowControlBar;
