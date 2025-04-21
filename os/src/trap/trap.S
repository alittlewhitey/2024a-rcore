    .attribute arch, "rv64gc"
    .altmacro

    .equ   FP_START,      50
    .equ   TRAPFRAME_SIZE, 688

    .macro SAVE_GP n
        sd    x\n, \n*8(sp)
    .endm

    .macro LOAD_GP n
        ld    x\n, \n*8(sp)
    .endm

    .macro SAVE_FP n, m
        fsd   f\n, \m*8(sp)
    .endm

    .macro LOAD_FP n, m
        fld   f\n, \m*8(sp)
    .endm
 #Push 所有 general purpose registers 到 TrapContext.x[0..31]
.macro PUSH_GENERAL_REGS
    sd ra,  0*8(sp)
    sd t0,  4*8(sp)
    sd t1,  5*8(sp)
    sd t2,  6*8(sp)
    sd s0,  7*8(sp)
    sd s1,  8*8(sp)
    sd a0,  9*8(sp)
    sd a1, 10*8(sp)
    sd a2, 11*8(sp)
    sd a3, 12*8(sp)
    sd a4, 13*8(sp)
    sd a5, 14*8(sp)
    sd a6, 15*8(sp)
    sd a7, 16*8(sp)
    sd s2, 17*8(sp)
    sd s3, 18*8(sp)
    sd s4, 19*8(sp)
    sd s5, 20*8(sp)
    sd s6, 21*8(sp)
    sd s7, 22*8(sp)
    sd s8, 23*8(sp)
    sd s9, 24*8(sp)
    sd s10,25*8(sp)
    sd s11,26*8(sp)
    sd t3, 27*8(sp)
    sd t4, 28*8(sp)
    sd t5, 29*8(sp)
    sd t6, 30*8(sp)
    # 注意：x31 是 zero 寄存器，不需要存储，通常跳过
.endm

 #从 TrapContext.x[0..31] 恢复所有通用寄存器
.macro POP_GENERAL_REGS
    ld ra,  0*8(sp)
    ld t0,  4*8(sp)
    ld t1,  5*8(sp)
    ld t2,  6*8(sp)
    ld s0,  7*8(sp)
    ld s1,  8*8(sp)
    ld a0,  9*8(sp)
    ld a1, 10*8(sp)
    ld a2, 11*8(sp)
    ld a3, 12*8(sp)
    ld a4, 13*8(sp)
    ld a5, 14*8(sp)
    ld a6, 15*8(sp)
    ld a7, 16*8(sp)
    ld s2, 17*8(sp)
    ld s3, 18*8(sp)
    ld s4, 19*8(sp)
    ld s5, 20*8(sp)
    ld s6, 21*8(sp)
    ld s7, 22*8(sp)
    ld s8, 23*8(sp)
    ld s9, 24*8(sp)
    ld s10,25*8(sp)
    ld s11,26*8(sp)
    ld t3, 27*8(sp)
    ld t4, 28*8(sp)
    ld t5, 29*8(sp)
    ld t6, 30*8(sp)
    # 同样，x31 不恢复
.endm

    # ----------------------------------------------------------------
    # SAVE_REGS：把 x1–x31, f0–f31, fcsr, a0, sstatus, sepc, sscratch(sp) 全都存到 TrapContext
    # TrapContext 布局里：
    #   x1..x31   → 偏移 1*8 … 31*8
    #   sscratch  → 存到 2*8
    #   original a0 → 50*8
    #   sstatus  → 32*8
    #   sepc     → 33*8
    #   f0..f31  → m=FP_START*8 … (FP_START+31)*8
    #   fcsr     → 83*8
    .macro SAVE_REGS
    PUSH_GENERAL_REGS
    csrr    t0, sepc
    csrr    t1, sstatus
    csrrw   t2, sscratch, zero    # 保存 sscratch 到 t2，并清空它

    sd      t0, 32*8(sp)          # tf.sepc
    sd      t1, 31*8(sp)          # tf.sstatus
    sd      t2, 1*8(sp)           # tf.regs.sp

     #—— save浮点寄存器 f0..f31
        .set    n, 0
        .set    m, FP_START
        .rept   32
            SAVE_FP  %n, %m
            .set n, n+1
            .set m, m+1
        .endr
    csrr    t0, scause
    csrr    t1, stval
    sd      t0, 83*8(sp)          # tf.scause
    sd      t1, 84*8(sp)          # tf.stval

    li      t0, 1
    sd      t0, 85*8(sp)          # tf.trap_status = 1
    .endm

    # ----------------------------------------------------------------
    # RESTORE_REGS：把 TrapContext 里的 sstatus, sepc, fcsr, f0..f31, x1..x31, sscratch(sp) 全恢复
    .macro RESTORE_REGS
        # 载入 sepc 和 sstatus 并恢复
    ld      t0, 32*8(sp)          # LDR t0, sp, 31
    ld      t1, 31*8(sp)          # LDR t1, sp, 32
    csrw    sepc, t0
    csrw    sstatus, t1

    # 恢复浮点寄存器

    POP_GENERAL_REGS
 #—— 恢复浮点寄存器 f0..f31
        .set    n, 0
        .set    m, FP_START
        .rept   32
            LOAD_FP  %n, %m
            .set n, n+1
            .set m, m+1
        .endr
    # 恢复原来的 sp（内核或用户栈）
    ld      sp, 1*8(sp)           # LDR sp, sp, 1

    .endm

    .section .text
    .globl __trap_from_user
    .globl __return_to_user
    .globl  trap_vector_base
    .globl trap_return1
    .globl user_return1
    .align 2


# user -> kernel
__trap_from_user:
    csrrw sp, sscratch, sp
    # now sp->*TrapContext in kernel space, sscratch->user stack
    # save other general purpose registers
    sd x1, 1*8(sp)
    # skip sp(x2), we will save it later
    # save x3~x31 (x4 is tp)
    .set n, 3
    .rept 29
        SAVE_GP %n
        .set n, n+1
    .endr
    # sd freg
    .set n, 0
    .set m, FP_START
    .rept 32
        SAVE_FP %n, %m
        .set n, n+1
        .set m, m+1
    .endr
    # sd fcsr
    csrr t0, fcsr
    sd t0, 83*8(sp)
    # sd original_a0
    sd a0, 50*8(sp)
    # we can use t0/t1/t2 freely, because they have been saved in TrapContext
    csrr t0, sstatus
    csrr t1, sepc
    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    # read user stack from sscratch and save it in TrapContext
    csrr t2, sscratch
    sd t2, 2*8(sp)

    # # move to kernel_sp
    # load kernel ra
    ld ra, 35*8(sp)
    # load callee-saved regs
    ld s0, 36*8(sp)
    ld s1, 37*8(sp)
    ld s2, 38*8(sp)
    ld s3, 39*8(sp)
    ld s4, 40*8(sp)
    ld s5, 41*8(sp)
    ld s6, 42*8(sp)
    ld s7, 43*8(sp)
    ld s8, 44*8(sp)
    ld s9, 45*8(sp)
    ld s10, 46*8(sp)
    ld s11, 47*8(sp)
    # load kernel fp
    ld fp, 48*8(sp)
    ld tp, 49*8(sp)
    ld sp, 34*8(sp)
    # return to kernel ra
    ret  

# kernel -> user
__return_to_user:
    # a0: *TrapContext in user space(Constant); a1: user space token
    # switch to user space

    # let sscratch store the trap context's address
    csrw sscratch, a0
    # save kernel callee-saved regs
    sd sp, 34*8(a0)
    sd ra, 35*8(a0)
    sd s0, 36*8(a0)
    sd s1, 37*8(a0)
    sd s2, 38*8(a0)
    sd s3, 39*8(a0)
    sd s4, 40*8(a0)
    sd s5, 41*8(a0)
    sd s6, 42*8(a0)
    sd s7, 43*8(a0)
    sd s8, 44*8(a0)
    sd s9, 45*8(a0)
    sd s10, 46*8(a0)
    sd s11, 47*8(a0)
    sd fp, 48*8(a0)
    sd tp, 49*8(a0)

    mv sp, a0
    # now sp points to TrapContext in kernel space, start restoring based on it
    # restore sstatus/sepc
    ld t0, 83*8(sp)
    csrw fcsr, t0
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    # restore general purpose registers except x0/sp/
    ld x1, 1*8(sp)
    .set n, 3
    .rept 29
        LOAD_GP %n
        .set n, n+1
    .endr
    .set n, 0
    .set m, FP_START
    .rept 32
        LOAD_FP %n, %m
        .set n, n+1
        .set m, m+1
    .endr
    # back to user stack
    ld sp, 2*8(sp)
    sret
.align 2
trap_vector_base:
    # —— 交换 sp 和 sscratch
    csrrw   sp, sscratch, sp
    # sscratch（旧 sp）非零：用户态 trap；为零：内核态 trap
    bnez    sp, user_trap
    # sscratch == 0，跳到内核态处理
    j       kernel_trap

kernel_trap:
    # 内核态陷入：sscratch 中保存了原来的 sp
    csrr    sp, sscratch
    addi    sp, sp, -TRAPFRAME_SIZE    # 在内核栈上为 TrapFrame 腾出空间
    SAVE_REGS                          # 保存寄存器、sepc、sstatus、sp、fs0、fs1……
    mv      a0, sp                     # 第一个参数：TrapFrame 指针
    li      a1, 1                      # 第二个参数：通过 trap 进入 trampoline
    li      a2, 0                      # 第三个参数：在内核态发生 Trap
    call    trampoline
    RESTORE_REGS                       # 恢复寄存器
    sret                               # 从陷阱返回

# ----------------------------------------------------------------
# 用户态陷入分支
user_trap:
    SAVE_REGS                          # sp 已是 TrapFrame 指针，sscratch 保存了原 sp
    # 假设以下偏移按字节展开

    li      a0, 1
    sd      a0, 85*8(sp)                # TrapFrame[37]=1，表示任务优先处理 Trap
    mv      a0, sp                     # 参数1：TrapFrame 指针
    li      a1, 1                      # 参数2：通过 trap 进入 trampoline
    li      a2, 1                      # 参数3：由用户态进入
    ld      sp, 33*8(sp)                # 从 TrapFrame[38] 恢复内核栈顶指针
    call    trampoline                 # 不会返回，最终在 trampoline 中走 trap_return

    .size   trap_vector_base, .-trap_vector_base
    # void trap_return(TrapContext* ctx);
trap_return1:
    # 参数 a0 是 TrapContext*，先设 sp = a0
    mv      sp, a0

    # 恢复浮点寄存器 fs0, fs1TODO
    

    # 恢复 sepc / sstatus
    ld      t0, 32*8(sp)      # sepc
    ld      t1, 31*8(sp)      # sstatus
    csrw    sepc,    t0
    csrw    sstatus, t1

    # 恢复通用寄存器 x1..x31（x0 固定为 0）
    POP_GENERAL_REGS
    # 恢复内核栈指针
    ld      sp, 33*8(sp)      # kernel_sp

    sret
 #void user_return(TrapContext* ctx);
user_return1:
    mv      sp, a0

    # 恢复浮点寄存器
   

    # 交换 gp <-> x3 (TrapContext.x[3])TODO
   # ld      t0, 3*8(sp)
  #  sd      gp, 3*8(sp)
   # mv      gp, t0

    # 交换 tp <-> x4 (TrapContext.x[4])
   # ld      t0, 4*8(sp)
    #sd      tp, 4*8(sp)
   # mv      tp, t0

    # 存一份 ctx 到 sscratch，便于 trap handler 使用
    csrw    sscratch, a0

    # 恢复 sepc / sstatus
    ld      t0, 32*8(sp)
    ld      t1, 31*8(sp)
    csrw    sepc,    t0
    csrw    sstatus, t1

    # 恢复通用寄存器
    
    POP_GENERAL_REGS

    # 恢复用户态 sp（x2）
    ld      sp, 1*8(sp)

    sret
