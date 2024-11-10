stride 算法深入

> stride 算法原理非常简单，但是有一个比较大的问题。例如两个 pass = 10 的进程，使用 8bit 无符号整形储存 stride， p1.stride = 255, p2.stride = 250，在 p2 执行一个时间片后，理论上下一次应该 p1 执行。
>
> - 实际情况是轮到 p1 执行吗？为什么？
>   在给定的例子中，两个优先级为 10 的进程 `p1` 和 `p2`，分别被分配了 `stride` 值 `255` 和 `250`。理论上，`p2` 执行完一个时间片后，应该轮到 `p1` 执行，因为 `p1` 的 stride 值较小。但实际情况可能并不如此，原因在于 8-bit 整型存储导致的溢出问题。
>
> 我们之前要求进程优先级 >= 2 其实就是为了解决这个问题。可以证明， **在不考虑溢出的情况下** , 在进程优先级全部 >= 2 的情况下，如果严格按照算法执行，那么 STRIDE_MAX – STRIDE_MIN <= BigStride / 2。
>
> - 为什么？尝试简单说明（不要求严格证明）。
>   在 stride 算法中，步长 stride\text{stride}stride 与进程的优先级成反比，优先级越高，步长越小。因此，当所有进程的优先级都大于等于 2 时，步长的最大值和最小值之间的差距会受到限制，这样可以避免较大差异带来的调度问题。
> - 已知以上结论，**考虑溢出的情况下**，可以为 Stride 设计特别的比较器，让 BinaryHeap<Stride> 的 pop 方法能返回真正最小的 Stride。补全下列代码中的 `partial_cmp` 函数，假设两个 Stride 永远不会相等。
>
> ```rust
> use core::cmp::Ordering;
> 
> struct Stride(u64);
> 
> impl PartialOrd for Stride {
>     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
>         // 处理溢出情况
>         let adjusted_self = (self.0 + 128) % 256;
>         let adjusted_other = (other.0 + 128) % 256;
>         
>         adjusted_self.partial_cmp(&adjusted_other)
>     }
> }
> 
> impl PartialEq for Stride {
>     fn eq(&self, other: &Self) -> bool {
>         false
>     }
> }
> 
> ```