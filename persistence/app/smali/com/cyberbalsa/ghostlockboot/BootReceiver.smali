.class public final Lcom/cyberbalsa/ghostlockboot/BootReceiver;
.super Landroid/content/BroadcastReceiver;

.field private static started:Z

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 4

    sget-boolean v0, Lcom/cyberbalsa/ghostlockboot/BootReceiver;->started:Z
    if-eqz v0, :start_service
    return-void

    :start_service
    const/4 v0, 0x1
    sput-boolean v0, Lcom/cyberbalsa/ghostlockboot/BootReceiver;->started:Z

    :try_start
    new-instance v1, Landroid/content/Intent;
    const-class v2, Lcom/cyberbalsa/ghostlockboot/GhostLockService;
    invoke-direct {v1, p1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {p1, v1}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;

    const-string v2, "GhostLockBoot"
    const-string v3, "boot foreground service requested"
    invoke-static {v2, v3}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch_error

    return-void

    :catch_error
    move-exception v0
    const-string v1, "GhostLockBoot"
    const-string v2, "could not start boot foreground service"
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    return-void
.end method
