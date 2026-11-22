//! Weakness classification and remediation guidance for findings.
//!
//! One home for "what kind of bug is this": SARIF rules, `DefectDojo` findings,
//! and the campaign report all classify a crash through [`classify`], so the
//! CWE a report prints is the CWE the exported SARIF carries. The guidance is
//! deterministic text per class, written for the engineer who fixes the bug;
//! it does not depend on a model being configured, and a model-written bug
//! report adds to it rather than replacing it.

use hf_core::crash::{Crash, CrashKind};

use crate::report::ReportLanguage;

/// The weakness a finding demonstrates, at the granularity a fix differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeaknessClass {
    /// Read past the end or before the start of a buffer (CWE-125).
    OutOfBoundsRead,
    /// Write past the end or before the start of a buffer (CWE-787).
    OutOfBoundsWrite,
    /// Write past a stack buffer (CWE-121).
    StackBufferOverflow,
    /// Access to memory the program marked unusable, direction unknown (CWE-119).
    MemoryBounds,
    /// Use of heap memory after it was freed (CWE-416).
    UseAfterFree,
    /// The same allocation freed twice (CWE-415).
    DoubleFree,
    /// `free` of memory that did not come from the heap allocator (CWE-590).
    FreeOfNonHeapMemory,
    /// Allocation and release through mismatched routines (CWE-762).
    MismatchedDeallocation,
    /// Use of a stack object after its function returned or scope ended (CWE-562).
    StackAddressEscape,
    /// Dereference of a null or near-null pointer (CWE-476).
    NullDereference,
    /// Integer division or remainder by zero (CWE-369).
    DivideByZero,
    /// Arithmetic that overflows or wraps (CWE-190).
    IntegerOverflow,
    /// Stack exhausted by unbounded recursion (CWE-674).
    UncontrolledRecursion,
    /// Allocation size taken from input without a limit (CWE-789).
    ExcessiveAllocation,
    /// Memory exhausted while processing one input (CWE-400).
    ResourceExhaustion,
    /// Memory never released (CWE-401).
    MemoryLeak,
    /// CWE-457: a value read before anything wrote it.
    UninitializedMemory,
    /// CWE-362: unsynchronized concurrent access to shared memory.
    RaceCondition,
    /// Other undefined behavior reported by `UBSan` (CWE-758).
    UndefinedBehavior,
    /// An assertion or abort reachable from input (CWE-617).
    ReachableAssertion,
    /// Input that keeps the target running past the time limit (CWE-834).
    ExcessiveIteration,
    /// A managed-runtime panic or uncaught exception (CWE-248).
    UncaughtException,
    /// A kernel bug report from syzkaller; its class is in the summary.
    KernelBug,
    /// No classification evidence.
    Uncategorized,
}

impl WeaknessClass {
    /// Every class, for exhaustive checks over the guidance table.
    pub const ALL: [Self; 24] = [
        Self::OutOfBoundsRead,
        Self::OutOfBoundsWrite,
        Self::StackBufferOverflow,
        Self::MemoryBounds,
        Self::UseAfterFree,
        Self::DoubleFree,
        Self::FreeOfNonHeapMemory,
        Self::MismatchedDeallocation,
        Self::StackAddressEscape,
        Self::NullDereference,
        Self::DivideByZero,
        Self::IntegerOverflow,
        Self::UncontrolledRecursion,
        Self::ExcessiveAllocation,
        Self::ResourceExhaustion,
        Self::MemoryLeak,
        Self::UninitializedMemory,
        Self::RaceCondition,
        Self::UndefinedBehavior,
        Self::ReachableAssertion,
        Self::ExcessiveIteration,
        Self::UncaughtException,
        Self::KernelBug,
        Self::Uncategorized,
    ];

    /// The CWE identifier and name. `CWE-noinfo` is MITRE's sentinel for "no
    /// specific weakness", not an entry.
    #[must_use]
    pub const fn cwe(self) -> (&'static str, &'static str) {
        match self {
            Self::OutOfBoundsRead => ("CWE-125", "Out-of-bounds Read"),
            Self::OutOfBoundsWrite => ("CWE-787", "Out-of-bounds Write"),
            Self::StackBufferOverflow => ("CWE-121", "Stack-based Buffer Overflow"),
            Self::MemoryBounds => (
                "CWE-119",
                "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            ),
            Self::UseAfterFree => ("CWE-416", "Use After Free"),
            Self::DoubleFree => ("CWE-415", "Double Free"),
            Self::FreeOfNonHeapMemory => ("CWE-590", "Free of Memory not on the Heap"),
            Self::MismatchedDeallocation => ("CWE-762", "Mismatched Memory Management Routines"),
            Self::StackAddressEscape => ("CWE-562", "Return of Stack Variable Address"),
            Self::NullDereference => ("CWE-476", "NULL Pointer Dereference"),
            Self::DivideByZero => ("CWE-369", "Divide By Zero"),
            Self::IntegerOverflow => ("CWE-190", "Integer Overflow or Wraparound"),
            Self::UncontrolledRecursion => ("CWE-674", "Uncontrolled Recursion"),
            Self::ExcessiveAllocation => ("CWE-789", "Memory Allocation with Excessive Size Value"),
            Self::ResourceExhaustion => ("CWE-400", "Uncontrolled Resource Consumption"),
            Self::MemoryLeak => (
                "CWE-401",
                "Missing Release of Memory after Effective Lifetime",
            ),
            Self::UninitializedMemory => ("CWE-457", "Use of Uninitialized Variable"),
            Self::RaceCondition => (
                "CWE-362",
                "Concurrent Execution using Shared Resource with Improper Synchronization",
            ),
            Self::UndefinedBehavior => ("CWE-758", "Reliance on Undefined Behavior"),
            Self::ReachableAssertion => ("CWE-617", "Reachable Assertion"),
            Self::ExcessiveIteration => ("CWE-834", "Excessive Iteration"),
            Self::UncaughtException => ("CWE-248", "Uncaught Exception"),
            Self::KernelBug => ("CWE-noinfo", "Kernel Bug"),
            Self::Uncategorized => ("CWE-noinfo", "Uncategorized Crash"),
        }
    }

    /// Whether the class corrupts or discloses memory, as opposed to costing
    /// availability. CASR's "not exploitable" speaks to code execution only;
    /// these classes still disclose or corrupt memory.
    #[must_use]
    pub const fn is_memory_safety(self) -> bool {
        matches!(
            self,
            Self::OutOfBoundsRead
                | Self::OutOfBoundsWrite
                | Self::StackBufferOverflow
                | Self::MemoryBounds
                | Self::UseAfterFree
                | Self::DoubleFree
                | Self::FreeOfNonHeapMemory
                | Self::MismatchedDeallocation
                | Self::StackAddressEscape
        )
    }
}

/// Classify a crash, preferring CASR's short description (as CASR prints it:
/// `heap-buffer-overflow(read)`, `SourceAvNearNull`, `stack-overflow`) and
/// falling back to the crash kind.
#[must_use]
pub fn classify(crash: &Crash) -> WeaknessClass {
    let short = crash
        .casr
        .as_ref()
        .map(|casr| casr.severity_short.to_ascii_lowercase())
        .unwrap_or_default();
    from_short_description(&short).unwrap_or(match crash.kind {
        // An unspecified sanitizer memory error is assumed to be a write, the
        // more serious direction, until CASR says otherwise.
        CrashKind::Asan => WeaknessClass::OutOfBoundsWrite,
        CrashKind::Ubsan => WeaknessClass::UndefinedBehavior,
        CrashKind::KernelBug => WeaknessClass::KernelBug,
        CrashKind::Leak => WeaknessClass::MemoryLeak,
        CrashKind::Msan => WeaknessClass::UninitializedMemory,
        CrashKind::Tsan => WeaknessClass::RaceCondition,
        CrashKind::Segv => WeaknessClass::NullDereference,
        CrashKind::Abort => WeaknessClass::ReachableAssertion,
        CrashKind::Timeout => WeaknessClass::ExcessiveIteration,
        CrashKind::Panic => WeaknessClass::UncaughtException,
        CrashKind::Other => WeaknessClass::Uncategorized,
    })
}

fn from_short_description(short: &str) -> Option<WeaknessClass> {
    use WeaknessClass as W;
    if short.is_empty() {
        return None;
    }
    let read = short.contains("(read)");
    let has = |needle: &str| short.contains(needle);
    let class = if has("double-free") {
        W::DoubleFree
    } else if has("bad-free") || has("invalid-free") {
        W::FreeOfNonHeapMemory
    } else if has("alloc-dealloc-mismatch") || has("new-delete-type-mismatch") {
        W::MismatchedDeallocation
    } else if has("use-after-free") {
        W::UseAfterFree
    } else if has("stack-use-after-return") || has("stack-use-after-scope") {
        W::StackAddressEscape
    } else if has("buffer-overflow")
        || has("container-overflow")
        || has("out-of-bounds")
        || has("index-out-of-bounds")
    {
        if read {
            W::OutOfBoundsRead
        } else if has("stack-buffer-overflow") {
            W::StackBufferOverflow
        } else {
            // A write, or an overflow CASR did not annotate: treated as the
            // more serious direction.
            W::OutOfBoundsWrite
        }
    } else if has("stack-overflow") || has("stack-exhaustion") {
        W::UncontrolledRecursion
    } else if has("use-after-poison") || has("callav") || has("badinstruction") {
        W::MemoryBounds
    } else if has("null") {
        W::NullDereference
    } else if has("sourceav") {
        W::OutOfBoundsRead
    } else if has("destav") {
        W::OutOfBoundsWrite
    } else if has("fpe") || has("divide-by-zero") || has("division-by-zero") {
        W::DivideByZero
    } else if has("integer-overflow") || has("integer overflow") {
        W::IntegerOverflow
    } else if has("allocation-size-too-big") || has("calloc-overflow") || has("malloc-exceeded") {
        W::ExcessiveAllocation
    } else if has("out-of-memory") || has("rss-limit") {
        W::ResourceExhaustion
    } else if has("leak") {
        W::MemoryLeak
    } else if has("uninitialized") {
        W::UninitializedMemory
    } else if has("data race") || has("data-race") {
        W::RaceCondition
    } else if has("timeout") {
        W::ExcessiveIteration
    } else if has("abort") || has("assert") {
        W::ReachableAssertion
    } else {
        return None;
    };
    Some(class)
}

/// Remediation guidance for one weakness class.
#[derive(Debug, Clone, Copy)]
pub struct Guidance {
    /// What an attacker or a malformed input gains from the weakness.
    pub impact: &'static str,
    /// Ordered steps that fix the weakness at its cause.
    pub remediation: &'static [&'static str],
}

/// The deterministic guidance for `class` in `language`.
#[must_use]
pub const fn guidance(class: WeaknessClass, language: ReportLanguage) -> Guidance {
    match language {
        ReportLanguage::En => english(class),
        ReportLanguage::Zh => chinese(class),
    }
}

const fn english(class: WeaknessClass) -> Guidance {
    use WeaknessClass as W;
    let (impact, remediation): (&str, &[&str]) = match class {
        W::OutOfBoundsRead => (
            "Reads memory outside the buffer. It can disclose adjacent heap or stack data (keys, pointers that defeat ASLR) and crash the process.",
            &[
                "Check the index or remaining length against the buffer length before every read at the reported line, including reads of multi-byte sequences whose length comes from the input.",
                "Carry the buffer length with the pointer (pointer plus length, or a span type) instead of trusting a length or terminator taken from the input.",
                "Reject truncated input with an error instead of reading past the end.",
            ],
        ),
        W::OutOfBoundsWrite => (
            "Writes memory outside the buffer. This corrupts adjacent data or allocator metadata and is commonly exploitable for code execution.",
            &[
                "Compute the destination size and check it against the bytes to be written before the write at the reported line.",
                "Replace unbounded copies (strcpy, sprintf, memcpy with an input-derived length) with bounded forms that take the destination size.",
                "Check size arithmetic for overflow before allocating or copying.",
            ],
        ),
        W::StackBufferOverflow => (
            "Writes past a stack buffer. This can overwrite saved registers or the return address and is a classic code-execution primitive.",
            &[
                "Bound every write into the stack buffer by its declared size; reject input longer than the buffer.",
                "Move variable-size data to a heap allocation sized from the validated input length.",
                "Keep stack protector and FORTIFY_SOURCE enabled in release builds as defense in depth, not as the fix.",
            ],
        ),
        W::MemoryBounds => (
            "Accesses memory the program had marked unusable (poisoned or otherwise invalid). Depending on direction it discloses or corrupts data.",
            &[
                "Find which object owns the reported address (the sanitizer report names it) and check the access against that object's live, valid range.",
                "If a custom allocator or container poisons the region, check the size bookkeeping that decides where valid data ends.",
                "Rebuild with the sanitizer's detailed report options and replay the reproducer to confirm the access direction.",
            ],
        ),
        W::UseAfterFree => (
            "Uses an object after it was freed. An attacker who controls the reallocation can redirect function pointers or data and gain code execution.",
            &[
                "Identify the free site in the sanitizer report and the later use; establish a single owner for the object's lifetime.",
                "Set the pointer to NULL after free and stop all aliases from outliving the owner (reference counting or scoped ownership).",
                "Check error paths: a free on failure followed by use in the caller is the common pattern.",
            ],
        ),
        W::DoubleFree => (
            "Frees the same allocation twice, corrupting allocator state; frequently exploitable for arbitrary writes.",
            &[
                "Make exactly one code path responsible for releasing the object.",
                "Set the pointer to NULL immediately after freeing it, and audit error and cleanup paths that release the same object.",
            ],
        ),
        W::FreeOfNonHeapMemory => (
            "Passes memory to free that the heap allocator did not return, corrupting allocator state.",
            &[
                "Release only pointers returned by the matching allocator; never free stack, static, or interior pointers.",
                "Track ownership so borrowed buffers are not released by the borrower.",
            ],
        ),
        W::MismatchedDeallocation => (
            "Releases memory with a routine that does not match its allocation (malloc/delete, new[]/delete), which is undefined behavior and can corrupt the heap.",
            &[
                "Pair every allocation with its matching release routine (malloc/free, new/delete, new[]/delete[]).",
                "Prefer owning types (std::unique_ptr, std::vector) so the release is chosen by the type.",
            ],
        ),
        W::StackAddressEscape => (
            "Uses a stack object after its function returned or its scope ended; the memory is reused by later calls.",
            &[
                "Do not return or store the address of a local variable beyond its scope.",
                "Allocate data that must outlive the call on the heap or pass a caller-owned buffer.",
            ],
        ),
        W::NullDereference => (
            "Dereferences a null or near-null pointer, crashing the process: a denial of service for any input that reaches it.",
            &[
                "Check the pointer (or the allocation or lookup result that produced it) before use at the reported line.",
                "Return an error to the caller instead of continuing when a required object is missing.",
            ],
        ),
        W::DivideByZero => (
            "Divides by zero, which crashes the process (SIGFPE) on integer division: a denial of service.",
            &[
                "Validate the divisor taken from input before the division and reject zero.",
                "Check for INT_MIN / -1, which also traps on most platforms.",
            ],
        ),
        W::IntegerOverflow => (
            "Arithmetic overflows or wraps. Used as a size or index, the wrapped value leads to undersized allocations and out-of-bounds access.",
            &[
                "Check operands before the operation (or use checked arithmetic such as __builtin_mul_overflow) where values come from input.",
                "Use an unsigned type wide enough for sizes (size_t) and validate ranges at parse time.",
            ],
        ),
        W::UncontrolledRecursion => (
            "Input drives recursion deep enough to exhaust the stack, crashing the process: a denial of service.",
            &[
                "Limit nesting depth explicitly and reject input that exceeds it.",
                "Convert the recursion to iteration with an explicit, bounded stack where nesting is legitimate.",
            ],
        ),
        W::ExcessiveAllocation => (
            "An allocation size comes from input without a limit; a small input can request gigabytes and exhaust memory.",
            &[
                "Validate sizes read from input against an upper bound derived from the remaining input length or a documented maximum.",
                "Check the multiplication that computes the size for overflow before allocating.",
            ],
        ),
        W::ResourceExhaustion => (
            "Processing one input consumes memory without bound: a denial of service.",
            &[
                "Cap the memory and work done per input (element counts, buffer growth, decompression ratio).",
                "Stream data instead of materializing it whole where the format allows.",
            ],
        ),
        W::MemoryLeak => (
            "Memory is never released. Repeated input grows the process until it is killed: a denial of service in long-running services.",
            &[
                "Release the allocation reported by LeakSanitizer on every path, including early returns on error.",
                "Use scoped cleanup (RAII, goto-cleanup blocks, defer) so error paths cannot skip the release.",
            ],
        ),
        W::UninitializedMemory => (
            "The code acts on memory it never wrote. The value is whatever was there before, so behavior varies between runs and can disclose earlier contents of the heap or stack.",
            &[
                "Initialize the object at its allocation or declaration; MemorySanitizer's origin trace names where it was created.",
                "Check that every path, including short or truncated input, writes a field before it is read.",
            ],
        ),
        W::RaceCondition => (
            "Two threads access the same memory without synchronization and at least one writes. The outcome depends on timing and can corrupt state.",
            &[
                "Guard the shared object with one lock held for every access, or make it atomic.",
                "Prefer passing ownership between threads over sharing mutable state.",
            ],
        ),
        W::UndefinedBehavior => (
            "Undefined behavior: the compiler may produce code that misbehaves in ways that differ between builds, including memory corruption.",
            &[
                "Fix the operation the UBSan message names at the reported line (shift width, misaligned access, invalid enum or bool value, and so on).",
                "Validate the input-derived operand before the operation.",
            ],
        ),
        W::ReachableAssertion => (
            "Input reaches an assertion or abort, terminating the process: a denial of service, and often a sign of an unhandled invalid state.",
            &[
                "Treat the asserted condition as input validation: return an error for invalid input instead of aborting.",
                "Keep assertions only for states that input cannot reach, and add the reproducer as a regression test.",
            ],
        ),
        W::ExcessiveIteration => (
            "Input keeps the target running past the time limit (an infinite or super-linear loop): a denial of service.",
            &[
                "Find the loop whose bound comes from input and ensure it always advances and terminates on malformed data.",
                "Bound work per input (iterations, backtracking, nested repetition).",
            ],
        ),
        W::UncaughtException => (
            "A runtime panic or uncaught exception terminates the process: a denial of service.",
            &[
                "Handle the error the panic reports (index, unwrap, type assertion) and return it to the caller.",
                "Validate input before operations that panic on invalid values.",
            ],
        ),
        W::KernelBug => (
            "A kernel bug reachable from system calls. Depending on its class it ranges from a denial of service to privilege escalation.",
            &[
                "Use the kernel report's class (KASAN, WARN, GPF, hung task) and stack to locate the faulting subsystem.",
                "Reproduce with the syzkaller reproducer on the patched kernel before reporting upstream.",
            ],
        ),
        W::Uncategorized => (
            "The crash could not be classified; its impact is unknown until it is analyzed.",
            &[
                "Replay the reproducer with full sanitizer output to identify the faulting operation.",
                "Classify and fix it as the identified weakness class.",
            ],
        ),
    };
    Guidance {
        impact,
        remediation,
    }
}

const fn chinese(class: WeaknessClass) -> Guidance {
    use WeaknessClass as W;
    let (impact, remediation): (&str, &[&str]) = match class {
        W::OutOfBoundsRead => (
            "读取缓冲区以外的内存，可能泄露相邻的堆或栈数据（如密钥、可绕过 ASLR 的指针），并导致进程崩溃。",
            &[
                "在报告的代码行每次读取之前，用缓冲区长度校验索引或剩余长度，包括长度由输入决定的多字节序列。",
                "让指针始终携带缓冲区长度（指针加长度或 span 类型），不要信任来自输入的长度或结束符。",
                "对被截断的输入返回错误，而不是越过末尾继续读取。",
            ],
        ),
        W::OutOfBoundsWrite => (
            "向缓冲区以外写入内存，会破坏相邻数据或分配器元数据，通常可被利用来执行代码。",
            &[
                "在报告的代码行写入之前计算目标大小，并与要写入的字节数比较。",
                "将无界拷贝（strcpy、sprintf、长度来自输入的 memcpy）替换为带目标大小的有界版本。",
                "在分配或拷贝之前检查尺寸计算是否溢出。",
            ],
        ),
        W::StackBufferOverflow => (
            "越过栈缓冲区写入，可能覆盖保存的寄存器或返回地址，是典型的代码执行手段。",
            &[
                "用声明的大小限制对栈缓冲区的每次写入；拒绝超过缓冲区长度的输入。",
                "将可变长度的数据改为按已校验的输入长度在堆上分配。",
                "在发布构建中保持栈保护和 FORTIFY_SOURCE 开启，作为纵深防御而不是修复本身。",
            ],
        ),
        W::MemoryBounds => (
            "访问了程序已标记为不可用（被毒化或无效）的内存。视访问方向不同，会泄露或破坏数据。",
            &[
                "根据消毒器报告找到该地址所属的对象，并用该对象有效的存活范围校验这次访问。",
                "如果是自定义分配器或容器毒化了该区域，检查决定有效数据结束位置的尺寸记录。",
                "开启消毒器的详细报告选项后重新构建，回放复现输入以确认访问方向。",
            ],
        ),
        W::UseAfterFree => (
            "在对象释放后继续使用。能够控制重新分配的攻击者可以篡改函数指针或数据并执行代码。",
            &[
                "根据消毒器报告确定释放位置和之后的使用位置；为该对象的生命周期确立唯一所有者。",
                "释放后将指针置为 NULL，并确保所有别名都不会比所有者存活更久（引用计数或作用域所有权）。",
                "检查错误路径：失败时释放、调用方随后继续使用，是最常见的模式。",
            ],
        ),
        W::DoubleFree => (
            "同一块内存被释放两次，破坏分配器状态，经常可被利用实现任意写。",
            &[
                "确保只有一条代码路径负责释放该对象。",
                "释放后立即将指针置为 NULL，并审查会释放同一对象的错误处理和清理路径。",
            ],
        ),
        W::FreeOfNonHeapMemory => (
            "把不是由堆分配器返回的内存传给 free，破坏分配器状态。",
            &[
                "只释放由对应分配器返回的指针；不要释放栈、静态或内部指针。",
                "跟踪所有权，避免借用者释放借来的缓冲区。",
            ],
        ),
        W::MismatchedDeallocation => (
            "释放内存所用的函数与分配方式不匹配（malloc/delete、new[]/delete），属于未定义行为并可能破坏堆。",
            &[
                "让每次分配与对应的释放函数配对（malloc/free、new/delete、new[]/delete[]）。",
                "优先使用拥有所有权的类型（std::unique_ptr、std::vector），由类型决定释放方式。",
            ],
        ),
        W::StackAddressEscape => (
            "在函数返回或作用域结束后继续使用栈上对象；这块内存会被后续调用复用。",
            &[
                "不要返回或保存超出作用域的局部变量地址。",
                "需要在调用结束后继续存在的数据应在堆上分配，或使用调用方提供的缓冲区。",
            ],
        ),
        W::NullDereference => (
            "解引用空指针或接近空的指针导致进程崩溃：任何能到达此处的输入都可造成拒绝服务。",
            &[
                "在报告的代码行使用之前检查该指针（或产生它的分配、查找结果）。",
                "缺少必需对象时向调用方返回错误，而不是继续执行。",
            ],
        ),
        W::DivideByZero => (
            "整数除以零会使进程崩溃（SIGFPE）：拒绝服务。",
            &[
                "在除法之前校验来自输入的除数，拒绝零。",
                "同时检查 INT_MIN / -1，它在大多数平台上同样会触发异常。",
            ],
        ),
        W::IntegerOverflow => (
            "算术运算溢出或回绕。回绕后的值若用作大小或索引，会导致分配过小和越界访问。",
            &[
                "对来自输入的值，在运算前检查操作数（或使用 __builtin_mul_overflow 等带检查的运算）。",
                "表示大小时使用足够宽的无符号类型（size_t），并在解析时校验取值范围。",
            ],
        ),
        W::UncontrolledRecursion => (
            "输入驱动递归深度过大，耗尽栈空间使进程崩溃：拒绝服务。",
            &[
                "显式限制嵌套深度，拒绝超过限制的输入。",
                "在嵌套合法的场景下，把递归改写为使用显式、有界栈的迭代。",
            ],
        ),
        W::ExcessiveAllocation => (
            "分配大小取自输入且没有上限；很小的输入就能请求数 GB 内存并耗尽内存。",
            &[
                "用由剩余输入长度或文档规定的最大值推导出的上限，校验从输入读取的大小。",
                "在分配之前检查计算大小的乘法是否溢出。",
            ],
        ),
        W::ResourceExhaustion => (
            "处理单个输入时内存消耗没有上限：拒绝服务。",
            &[
                "限制每个输入可使用的内存和工作量（元素数量、缓冲区增长、解压比例）。",
                "在格式允许时以流式方式处理数据，而不是一次性全部加载。",
            ],
        ),
        W::MemoryLeak => (
            "内存从未被释放。重复输入会使进程不断增长直至被终止：长期运行的服务会因此拒绝服务。",
            &[
                "在所有路径上释放 LeakSanitizer 报告的分配，包括出错提前返回的路径。",
                "使用作用域清理（RAII、goto 清理块、defer），避免错误路径跳过释放。",
            ],
        ),
        W::UninitializedMemory => (
            "代码使用了从未写入的内存。其值是此前遗留的内容，因此每次运行的行为可能不同，并可能泄露堆或栈上的旧数据。",
            &[
                "在分配或声明处初始化该对象；MemorySanitizer 的来源追踪会指出它的创建位置。",
                "确认每条路径（包括过短或被截断的输入）都在读取字段之前写入它。",
            ],
        ),
        W::RaceCondition => (
            "两个线程在没有同步的情况下访问同一块内存，且至少有一个在写入。结果取决于时序，可能破坏状态。",
            &[
                "用同一把锁保护对该共享对象的每一次访问，或将其改为原子类型。",
                "优先在线程之间传递所有权，而不是共享可变状态。",
            ],
        ),
        W::UndefinedBehavior => (
            "未定义行为：编译器生成的代码可能在不同构建中表现不一致，包括内存破坏。",
            &[
                "修复 UBSan 消息在报告行指出的操作（移位宽度、未对齐访问、无效的枚举或布尔值等）。",
                "在运算前校验来自输入的操作数。",
            ],
        ),
        W::ReachableAssertion => (
            "输入可触发断言或 abort 使进程终止：拒绝服务，通常也说明存在未处理的非法状态。",
            &[
                "把被断言的条件当作输入校验：对非法输入返回错误，而不是终止进程。",
                "断言只保留给输入无法到达的状态，并将复现输入加入回归测试。",
            ],
        ),
        W::ExcessiveIteration => (
            "输入使目标运行超过时间限制（无限循环或超线性循环）：拒绝服务。",
            &[
                "找到边界取自输入的循环，确保其在畸形数据上也始终前进并终止。",
                "限制每个输入的工作量（迭代次数、回溯、嵌套重复）。",
            ],
        ),
        W::UncaughtException => (
            "运行时 panic 或未捕获的异常使进程终止：拒绝服务。",
            &[
                "处理 panic 报告的错误（索引、unwrap、类型断言），并将其返回给调用方。",
                "在会因非法值而 panic 的操作之前校验输入。",
            ],
        ),
        W::KernelBug => (
            "可由系统调用触发的内核缺陷。视类型不同，影响从拒绝服务到权限提升不等。",
            &[
                "根据内核报告的类型（KASAN、WARN、GPF、hung task）和调用栈定位出错的子系统。",
                "在向上游报告前，用 syzkaller 复现程序在打过补丁的内核上复现。",
            ],
        ),
        W::Uncategorized => (
            "该崩溃无法分类；在分析之前其影响未知。",
            &[
                "开启完整的消毒器输出回放复现输入，确定出错的操作。",
                "按识别出的缺陷类型进行分类并修复。",
            ],
        ),
    };
    Guidance {
        impact,
        remediation,
    }
}
