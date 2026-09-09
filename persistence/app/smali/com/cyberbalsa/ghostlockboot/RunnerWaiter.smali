.class final Lcom/cyberbalsa/ghostlockboot/RunnerWaiter;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.field private final process:Ljava/lang/Process;

.field private final service:Lcom/cyberbalsa/ghostlockboot/GhostLockService;

.method public constructor <init>(Lcom/cyberbalsa/ghostlockboot/GhostLockService;Ljava/lang/Process;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/cyberbalsa/ghostlockboot/RunnerWaiter;->service:Lcom/cyberbalsa/ghostlockboot/GhostLockService;
    iput-object p2, p0, Lcom/cyberbalsa/ghostlockboot/RunnerWaiter;->process:Ljava/lang/Process;
    return-void
.end method

.method public run()V
    .locals 1

    :try_wait
    iget-object v0, p0, Lcom/cyberbalsa/ghostlockboot/RunnerWaiter;->process:Ljava/lang/Process;
    invoke-virtual {v0}, Ljava/lang/Process;->waitFor()I
    :try_end
    .catch Ljava/lang/InterruptedException; {:try_wait .. :try_end} :wait_done

    :wait_done
    iget-object v0, p0, Lcom/cyberbalsa/ghostlockboot/RunnerWaiter;->service:Lcom/cyberbalsa/ghostlockboot/GhostLockService;
    invoke-virtual {v0}, Lcom/cyberbalsa/ghostlockboot/GhostLockService;->runnerFinished()V
    return-void
.end method
