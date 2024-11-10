1. 正确进入 U 态后，程序的特征还应有：使用 S 态特权指令，访问 S 态寄存器后会报错。 请同学们可以自行测试这些内容（运行 [三个 bad 测例 (ch2b_bad_*.rs)](https://github.com/LearningOS/rCore-Tutorial-Test-2024S/tree/master/src/bin) ）， 描述程序出错行为，同时注意注明你使用的 sbi 及其版本。

   > rustsbi版本：`rustsbi-lib: 0.2.0-alpha`
   >
   >  ch2b_bad_address
   > 段错误 (核心已转储)
   >
   > ` qemu-riscv64 
   >
   > ` ch2b_bad_instructions` 和 `ch2b_bad_register.rs`
   > 非法指令 (核心已转储)
   >
   > 
   >
   > `ch2b_bad_instruction.rs`和 `ch2b_bad_register.rs`程序在U态下访问S态的指令和寄存器报错被内核kill掉
   >
   > 

   

   

2. 深入理解 [trap.S](https://github.com/LearningOS/rCore-Tutorial-Code-2024S/blob/ch3/os/src/trap/trap.S) 中两个函数 `<span class="pre">__alltraps</span>` 和 `<span class="pre">__restore</span>` 的作用，并回答如下问题

   1. L40：刚进入 `__restore` 时，`a0` 代表了什么值。请指出 `__restore` 的两种使用情景

      > 刚进 `__restore`时，`a0`是用于指示返回用户态后执行起始地址；`__restore`在起始运行程序和在处理trap后返回U态时使用

   2. L43-L48：这几行汇编代码特殊处理了哪些寄存器？这些寄存器的的值对于进入用户态有何意义？请分别解释。

      ```
      ld t0, 32*8(sp)
      ld t1, 33*8(sp)
      ld t2, 2*8(sp)
      csrw sstatus, t0
      csrw sepc, t1
      csrw sscratch, t2
      ```

      

      > 这几行汇编代码处理了CSR寄存器（`sstatus`、`sepc`、`sscratch`），这三个寄存器中存储了trap前的信息，若不先恢复这些寄存器的值，则无法恢复此前的三个临时寄存器（`t0`、`t1`、`t2`）

   3. L50-L56：为何跳过了 `x2` 和 `x4`？

      ```
      ld x1, 1*8(sp)
      ld x3, 3*8(sp)
      .set n, 5
      .rep t27
          LOAD_GP %n
          .set n, n+1
      .endr
      ```

      

      > 因为 `x0`被硬编码为0，而 `x4`则不常用到，除非手动出于特殊用途使用，因此无需保存和恢复

   4. L60：该指令之后，`sp` 和 `sscratch` 中的值分别有什么意义？

      ```
      csrrw sp, sscratch, sp
      ```

      

      > `csrrw`指令将 `sscratch`和 `sp`中的值交换，此前 `sscratch->user stack`，`sp->kernel stack`；结果 `sscratch->kernel stack`，`sp->user stack`

   5. `__restore`：中发生状态切换在哪一条指令？为何该指令执行之后会进入用户态？

      > 状态切换发生在 `sret`指令，指令执行后CPU会将当前的特权级按照 `sstatus`的 `SPP`字段设置为U；之后跳转到 `sepc`寄存器指向的那条指令，然后继续执行。

   6. L13：该指令之后，`sp`和 `sscratch`中的值分别有什么意义？

      ```
      csrrw sp, sscratch, sp
      ```

      

      交换 `sscratch`和 `sp`中的值，交换后 `sscratch->user stack`，`sp->kernel stack`

   7. 从U态进入S态是哪一条指令发生的？

      > ecall指令，在应用程序启动、发起系统调用、执行出错、执行结束时执行切换到S态进行处理