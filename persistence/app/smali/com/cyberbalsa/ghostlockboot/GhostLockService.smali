.class public final Lcom/cyberbalsa/ghostlockboot/GhostLockService;
.super Landroid/app/Service;

.field private runner:Ljava/lang/Process;

.field private started:Z

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Service;-><init>()V
    return-void
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1

    const/4 v0, 0x0
    return-object v0
.end method

.method public onCreate()V
    .locals 6

    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    const-string v1, "ghostlock_boot"
    const-string v2, "GhostLock boot"
    const/4 v3, 0x2
    new-instance v0, Landroid/app/NotificationChannel;
    invoke-direct {v0, v1, v2, v3}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    const-string v4, "notification"
    invoke-virtual {p0, v4}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v4
    check-cast v4, Landroid/app/NotificationManager;
    invoke-virtual {v4, v0}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    new-instance v4, Landroid/app/Notification$Builder;
    invoke-direct {v4, p0, v1}, Landroid/app/Notification$Builder;-><init>(Landroid/content/Context;Ljava/lang/String;)V
    const v5, 0x108008a
    invoke-virtual {v4, v5}, Landroid/app/Notification$Builder;->setSmallIcon(I)Landroid/app/Notification$Builder;
    const-string v5, "Restoring ADB root"
    invoke-virtual {v4, v5}, Landroid/app/Notification$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;
    const-string v5, "Validating and running the boot payload"
    invoke-virtual {v4, v5}, Landroid/app/Notification$Builder;->setContentText(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;
    const/4 v5, 0x1
    invoke-virtual {v4, v5}, Landroid/app/Notification$Builder;->setOngoing(Z)Landroid/app/Notification$Builder;
    invoke-virtual {v4}, Landroid/app/Notification$Builder;->build()Landroid/app/Notification;
    move-result-object v0
    invoke-virtual {p0, v5, v0}, Landroid/app/Service;->startForeground(ILandroid/app/Notification;)V
    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 12

    iget-boolean v0, p0, Lcom/cyberbalsa/ghostlockboot/GhostLockService;->started:Z
    if-eqz v0, :start_runner
    const/4 v0, 0x2
    return v0

    :start_runner
    const/4 v0, 0x1
    iput-boolean v0, p0, Lcom/cyberbalsa/ghostlockboot/GhostLockService;->started:Z

    :try_start
    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0

    const-string v1, "boot_count"
    const/4 v2, -0x1
    invoke-static {v0, v1, v2}, Landroid/provider/Settings$Global;->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I
    move-result v3
    invoke-static {v3}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;
    move-result-object v3

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;
    move-result-object v4
    iget-object v4, v4, Landroid/content/pm/ApplicationInfo;->nativeLibraryDir:Ljava/lang/String;

    new-instance v5, Ljava/lang/StringBuilder;
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const-string v6, "/libghostlock_runner.so"
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v5

    invoke-virtual {p0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v6
    invoke-virtual {v6}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v6

    const/4 v7, 0x3
    new-array v7, v7, [Ljava/lang/String;
    const/4 v8, 0x0
    aput-object v5, v7, v8
    const/4 v8, 0x1
    aput-object v3, v7, v8
    const/4 v8, 0x2
    aput-object v6, v7, v8

    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v8
    invoke-virtual {v8, v7}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    move-result-object v9
    iput-object v9, p0, Lcom/cyberbalsa/ghostlockboot/GhostLockService;->runner:Ljava/lang/Process;

    new-instance v10, Lcom/cyberbalsa/ghostlockboot/RunnerWaiter;
    invoke-direct {v10, p0, v9}, Lcom/cyberbalsa/ghostlockboot/RunnerWaiter;-><init>(Lcom/cyberbalsa/ghostlockboot/GhostLockService;Ljava/lang/Process;)V
    new-instance v11, Ljava/lang/Thread;
    const-string v8, "GhostLockRunnerWaiter"
    invoke-direct {v11, v10, v8}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;Ljava/lang/String;)V
    invoke-virtual {v11}, Ljava/lang/Thread;->start()V

    const-string v8, "GhostLockBoot"
    const-string v7, "native boot runner started under foreground service"
    invoke-static {v8, v7}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch_error

    const/4 v0, 0x2
    return v0

    :catch_error
    move-exception v0
    const-string v1, "GhostLockBoot"
    const-string v2, "could not start native boot runner"
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    invoke-virtual {p0}, Lcom/cyberbalsa/ghostlockboot/GhostLockService;->runnerFinished()V
    const/4 v0, 0x2
    return v0
.end method

.method public runnerFinished()V
    .locals 1

    const/4 v0, 0x1
    invoke-virtual {p0, v0}, Landroid/app/Service;->stopForeground(Z)V
    invoke-virtual {p0}, Landroid/app/Service;->stopSelf()V
    return-void
.end method
