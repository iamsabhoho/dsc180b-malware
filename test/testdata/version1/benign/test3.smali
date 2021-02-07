.class final Landroid/arch/core/executor/c;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Executor;


# direct methods
.method constructor <init>()V
    .locals 0

    .line 50
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public execute(Ljava/lang/Runnable;)V
    .locals 0

    .line 53
    invoke-static {}, Landroid/arch/core/executor/a;->a()Landroid/arch/core/executor/a;

    move-result-object p0

    invoke-virtual {p0, p1}, Landroid/arch/core/executor/a;->a(Ljava/lang/Runnable;)V

    return-void
.end method
