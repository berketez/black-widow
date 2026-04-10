#!/usr/bin/env python3
"""Generate comprehensive Go stdlib + runtime + common third-party function signatures.

Target: 30K+ signatures for Go binary analysis via GOPCLNTAB symbol recovery.
"""
import json
import itertools
from pathlib import Path

sigs = {}

def add(name, lib, purpose, category):
    """Add signature, skip duplicates."""
    if name not in sigs:
        sigs[name] = {"lib": lib, "purpose": purpose, "category": category}

def add_method(pkg, receiver, method, lib, purpose, category):
    """Add method signature like pkg.(*Type).Method"""
    add(f"{pkg}.(*{receiver}).{method}", lib, purpose, category)

def add_func(pkg, func, lib, purpose, category):
    """Add function signature like pkg.Function"""
    add(f"{pkg}.{func}", lib, purpose, category)

# =============================================================================
# PART 1: RUNTIME (appears in EVERY Go binary)
# =============================================================================

# --- Runtime: scheduler ---
for fn, purpose in [
    ("main", "Go program main entry (calls main.main)"),
    ("goexit", "goroutine exit point"),
    ("goexit0", "goroutine exit cleanup"),
    ("goexit1", "goroutine exit finalization"),
    ("newproc", "create new goroutine (go statement)"),
    ("newproc1", "create new goroutine (internal)"),
    ("mstart", "OS thread start routine for Go"),
    ("mstart0", "initial OS thread setup"),
    ("mstart1", "OS thread setup phase 1"),
    ("mexit", "OS thread exit"),
    ("schedinit", "scheduler initialization"),
    ("schedule", "select next goroutine to run"),
    ("findrunnable", "find a runnable goroutine"),
    ("findRunnable", "find a runnable goroutine"),
    ("park_m", "park current goroutine"),
    ("gopark", "goroutine park (suspend)"),
    ("goready", "goroutine ready (resume)"),
    ("goready.func1", "goroutine ready callback"),
    ("Gosched", "yield to scheduler (cooperative)"),
    ("GOMAXPROCS", "set max OS threads for goroutines"),
    ("NumGoroutine", "get number of goroutines"),
    ("NumCPU", "get number of CPUs"),
    ("procPin", "pin goroutine to current P"),
    ("procUnpin", "unpin goroutine from P"),
    ("acquirep", "acquire P for current M"),
    ("releasep", "release P from current M"),
    ("handoffp", "hand off P to another M"),
    ("startm", "start or wake M to run P"),
    ("stopm", "stop execution of M"),
    ("wakep", "wake a P for scheduling"),
    ("preemptone", "preempt single goroutine"),
    ("preemptall", "preempt all goroutines"),
    ("preemptM", "preempt specific M"),
    ("suspendG", "suspend goroutine for GC"),
    ("resumeG", "resume goroutine after GC"),
    ("casgstatus", "CAS goroutine status"),
    ("casGToWaiting", "set goroutine to waiting"),
    ("casGToPreemptScan", "set goroutine to preempt scan"),
    ("casfrom_Gscanstatus", "clear goroutine scan status"),
    ("castogscanstatus", "set goroutine scan status"),
    ("gopreempt_m", "preempt goroutine on M"),
    ("goschedImpl", "goroutine schedule implementation"),
    ("gosched_m", "schedule goroutine from M"),
    ("goyield", "yield execution to scheduler"),
    ("goyield_m", "yield goroutine on M"),
    ("runqput", "put goroutine on local run queue"),
    ("runqget", "get goroutine from local run queue"),
    ("runqsteal", "steal goroutine from another P"),
    ("runqgrab", "grab batch from run queue"),
    ("globrunqput", "put goroutine on global run queue"),
    ("globrunqget", "get goroutine from global run queue"),
    ("injectglist", "inject goroutine list into scheduler"),
    ("execute", "execute a goroutine"),
    ("exitsyscall", "return from syscall"),
    ("exitsyscall0", "slow path syscall return"),
    ("exitsyscallfast", "fast path syscall return"),
    ("entersyscall", "enter syscall"),
    ("entersyscall_sysmon", "enter syscall (sysmon path)"),
    ("entersyscall_gcwait", "enter syscall waiting for GC"),
    ("entersyscallblock", "enter blocking syscall"),
    ("reentersyscall", "re-enter syscall"),
    ("sysmon", "system monitor goroutine"),
    ("retake", "retake P from syscall or preempt"),
    ("checkdead", "check for deadlocked goroutines"),
    ("templateThread", "template thread for new OS threads"),
    ("sigtramp", "signal trampoline"),
    ("sigtrampgo", "signal trampoline (Go)"),
    ("sighandler", "Go signal handler"),
    ("sigfwd", "forward signal to non-Go handler"),
    ("sigfwdgo", "forward signal from Go handler"),
    ("bgsweep", "background sweep goroutine"),
    ("bgscavenge", "background scavenge goroutine"),
    ("forcegchelper", "forced GC helper goroutine"),
    ("timerproc", "timer goroutine"),
    ("sysmonBack", "sysmon background operations"),
    ("checkTimers", "check timer expiration"),
    ("runtimer", "run expired timer"),
    ("runOneTimer", "execute single timer"),
    ("addtimer", "add timer to heap"),
    ("deltimer", "delete timer from heap"),
    ("modtimer", "modify timer"),
    ("resettimer", "reset timer deadline"),
    ("cleantimers", "clean timer heap"),
    ("adjusttimers", "adjust timer heap"),
    ("nobarrierWakeTime", "get wakeup time without barrier"),
    ("timeSleepUntil", "sleep until specified time"),
    ("goroutineProfileWithLabels", "profile goroutine with labels"),
    ("goroutineReady", "mark goroutine as ready"),
    ("stopTheWorld", "pause all goroutines for GC"),
    ("startTheWorld", "resume all goroutines after GC"),
    ("stopTheWorldWithSema", "STW with semaphore"),
    ("startTheWorldWithSema", "start world with semaphore"),
    ("freezetheworld", "freeze world for fatal error"),
    ("needm", "need M for cgo callback"),
    ("dropm", "drop M after cgo callback"),
    ("cgoCheckPointer", "check pointer for cgo"),
    ("cgoCheckResult", "check cgo result"),
    ("lockOSThread", "lock goroutine to OS thread"),
    ("unlockOSThread", "unlock goroutine from OS thread"),
    ("LockOSThread", "lock goroutine to OS thread (exported)"),
    ("UnlockOSThread", "unlock goroutine from OS thread (exported)"),
    ("dolockOSThread", "lock OS thread implementation"),
    ("dounlockOSThread", "unlock OS thread implementation"),
    ("allgadd", "add goroutine to allg list"),
    ("allGsSnapshot", "snapshot of all goroutines"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_runtime")

# --- Runtime: memory allocation ---
for fn, purpose in [
    ("mallocgc", "GC-aware memory allocation"),
    ("makeslice", "allocate and initialize slice"),
    ("makeslice64", "allocate large slice (64-bit length)"),
    ("makeslicecopy", "allocate slice with copy"),
    ("makemap", "allocate and initialize map"),
    ("makemap64", "allocate map (64-bit hint)"),
    ("makemap_small", "allocate small map (inline)"),
    ("makechan", "allocate and initialize channel"),
    ("makechan64", "allocate channel (64-bit size)"),
    ("newobject", "allocate new object on heap"),
    ("newarray", "allocate new array on heap"),
    ("memmove", "Go runtime memory move"),
    ("memclrNoHeapPointers", "clear non-pointer memory"),
    ("memclrHasPointers", "clear memory containing pointers"),
    ("memhash", "hash memory for map"),
    ("memhash32", "hash 32-bit value for map"),
    ("memhash64", "hash 64-bit value for map"),
    ("strhash", "hash string for map"),
    ("f32hash", "hash float32 for map"),
    ("f64hash", "hash float64 for map"),
    ("c64hash", "hash complex64 for map"),
    ("c128hash", "hash complex128 for map"),
    ("interhash", "hash interface for map"),
    ("nilinterhash", "hash nil interface for map"),
    ("memequal", "compare memory for equality"),
    ("memequal0", "compare zero-size values"),
    ("memequal8", "compare 8-byte values"),
    ("memequal16", "compare 16-byte values"),
    ("memequal32", "compare 32-byte values"),
    ("memequal64", "compare 64-byte values"),
    ("memequal128", "compare 128-byte values"),
    ("interequal", "compare interfaces for equality"),
    ("nilinterequal", "compare nil interfaces"),
    ("efaceeq", "empty interface equality"),
    ("ifaceeq", "interface equality"),
    ("stkalloc", "allocate on stack"),
    ("stackalloc", "allocate goroutine stack"),
    ("stackfree", "free goroutine stack"),
    ("stackgrow", "grow goroutine stack"),
    ("copystack", "copy goroutine stack"),
    ("shrinkstack", "shrink goroutine stack"),
    ("persistentalloc", "persistent non-GC allocation"),
    ("persistentalloc1", "persistent allocation (internal)"),
    ("sysAlloc", "allocate OS memory"),
    ("sysFree", "free OS memory"),
    ("sysReserve", "reserve OS memory"),
    ("sysMap", "map reserved OS memory"),
    ("sysUsed", "mark OS memory as used"),
    ("sysUnused", "mark OS memory as unused"),
    ("sysFault", "mark OS memory as faulting"),
    ("sysHugePage", "hint huge pages to OS"),
    ("mHeap_Alloc", "heap allocate span"),
    ("mHeap_Free", "heap free span"),
    ("fixalloc_alloc", "fixed-size allocator alloc"),
    ("fixalloc_free", "fixed-size allocator free"),
    ("spanalloc", "allocate memory span"),
    ("spanfree", "free memory span"),
    ("largeAlloc", "large object allocation"),
    ("nextFreeFast", "fast path free object allocation"),
    ("nextFree", "get next free object from span"),
    ("mcacheRefill", "refill mcache from mcentral"),
    ("allocmcache", "allocate new mcache"),
    ("freemcache", "free mcache"),
    ("mCentral_Grow", "grow mcentral span list"),
    ("pageAlloc_alloc", "page allocator allocation"),
    ("pageAlloc_free", "page allocator free"),
    ("heapBitsSetType", "set type bits in heap"),
    ("typedmemmove", "type-aware memory move"),
    ("typedmemclr", "type-aware memory clear"),
    ("typedslicecopy", "type-aware slice copy"),
    ("bulkBarrierPreWrite", "GC write barrier (bulk pre-write)"),
    ("bulkBarrierPreWriteSrcOnly", "GC write barrier (src only)"),
    ("writebarrierptr", "GC write barrier pointer"),
    ("wbBufFlush", "flush write barrier buffer"),
    ("gcWriteBarrier", "GC write barrier entry"),
    ("gcWriteBarrierR1", "GC write barrier (R1 register)"),
    ("gcWriteBarrierR2", "GC write barrier (R2 register)"),
    ("gcWriteBarrierR3", "GC write barrier (R3 register)"),
    ("gcWriteBarrierR4", "GC write barrier (R4 register)"),
    ("gcWriteBarrierR5", "GC write barrier (R5 register)"),
    ("gcWriteBarrierR6", "GC write barrier (R6 register)"),
    ("gcWriteBarrierR7", "GC write barrier (R7 register)"),
    ("gcWriteBarrierR8", "GC write barrier (R8 register)"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_memory")

# --- Runtime: GC ---
for fn, purpose in [
    ("GC", "trigger garbage collection"),
    ("SetFinalizer", "set finalizer on object"),
    ("ReadMemStats", "read memory allocator stats"),
    ("KeepAlive", "prevent GC from collecting object"),
    ("gcStart", "start garbage collection cycle"),
    ("gcDrain", "drain GC mark work queue"),
    ("gcMarkDone", "signal GC marking phase complete"),
    ("gcBgMarkWorker", "background GC mark worker"),
    ("gcSweep", "GC sweep phase"),
    ("gcMarkTermination", "GC mark termination phase"),
    ("gcMarkRootPrepare", "prepare GC root marking"),
    ("gcMarkRootCheck", "check GC root marking"),
    ("markroot", "mark GC root"),
    ("markrootBlock", "mark block of GC roots"),
    ("markrootFreeGStacks", "free G stacks during GC"),
    ("markrootSpans", "mark heap spans during GC"),
    ("gcDrainN", "drain N items from GC work queue"),
    ("gcFlushBgCredit", "flush background GC credit"),
    ("gcAssistAlloc", "GC assist allocation"),
    ("gcAssistAlloc1", "GC assist allocation phase 1"),
    ("gcWakeAllAssists", "wake all GC assist goroutines"),
    ("gcParkAssist", "park goroutine for GC assist"),
    ("gcResetMarkState", "reset GC mark state"),
    ("gcTrigger_test", "test GC trigger condition"),
    ("gcSetTriggerRatio", "set GC trigger ratio"),
    ("sweepone", "sweep one span"),
    ("deductSweepCredit", "deduct sweep credit"),
    ("sweepLocked_sweep", "sweep locked span"),
    ("scanobject", "scan object for GC pointers"),
    ("scanblock", "scan memory block for pointers"),
    ("scanstack", "scan goroutine stack for pointers"),
    ("greyobject", "mark object as grey (GC tricolor)"),
    ("shade", "shade object (GC write barrier)"),
    ("gcmarknewobject", "mark newly allocated object"),
    ("clearpools", "clear sync.Pool during GC"),
    ("gchelper", "GC helper goroutine"),
    ("gchelperstart", "start GC helper"),
    ("gcBgMarkStartWorkers", "start background mark workers"),
    ("gcBgMarkPrepare", "prepare background GC marking"),
    ("gcBgMarkWorkerNode", "background mark worker node"),
    ("gcWaitOnMark", "wait for GC mark phase"),
    ("gcController_startCycle", "GC controller start cycle"),
    ("gcController_endCycle", "GC controller end cycle"),
    ("gcController_revise", "GC controller revise pacing"),
    ("gcController_findRunnableGCWorker", "find runnable GC worker"),
    ("gcPaceScavenger", "pace memory scavenger"),
    ("finishsweep_m", "finish sweep on M"),
    ("setGCPhase", "set GC phase"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_gc")

# --- Runtime: maps ---
for fn, purpose in [
    ("mapaccess1", "map lookup returning value (m[k])"),
    ("mapaccess2", "map lookup returning value+ok (v,ok=m[k])"),
    ("mapassign", "map assignment (m[k]=v)"),
    ("mapdelete", "map deletion (delete(m,k))"),
    ("mapiterinit", "initialize map iterator"),
    ("mapiternext", "advance map iterator"),
    ("mapclear", "clear all map entries"),
    ("makeBucketArray", "allocate map bucket array"),
    ("hashGrow", "grow map hash table"),
    ("growWork", "incremental map grow work"),
    ("evacuate", "evacuate map bucket during grow"),
    ("advanceEvacuationMark", "advance map evacuation mark"),
    ("overLoadFactor", "check map load factor"),
    ("tooManyOverflowBuckets", "check map overflow"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_map")

# Fast map variants for various key types
for keytype in ["32", "64", "str"]:
    for op in ["mapaccess1", "mapaccess2", "mapassign", "mapdelete"]:
        add(f"runtime.{op}_fast{keytype}", "go-runtime",
            f"fast {op.replace('map','')} ({keytype} key)", "go_map")

# --- Runtime: slices ---
for fn, purpose in [
    ("growslice", "grow slice backing array (append)"),
    ("slicecopy", "copy elements between slices"),
    ("slicebytetostring", "convert []byte to string"),
    ("slicebytetostringtmp", "temporary []byte to string (no copy)"),
    ("stringtoslicebyte", "convert string to []byte"),
    ("stringtoslicebytetmp", "temporary string to []byte"),
    ("stringtoslicerune", "convert string to []rune"),
    ("slicerunetostring", "convert []rune to string"),
    ("concatstrings", "concatenate strings"),
    ("concatstring2", "concatenate 2 strings"),
    ("concatstring3", "concatenate 3 strings"),
    ("concatstring4", "concatenate 4 strings"),
    ("concatstring5", "concatenate 5 strings"),
    ("rawstringtmp", "create temporary raw string"),
    ("rawstring", "create raw string"),
    ("rawbyteslice", "create raw byte slice"),
    ("rawruneslice", "create raw rune slice"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_slice")

# --- Runtime: channels ---
for fn, purpose in [
    ("chansend", "send value on channel (ch <- v)"),
    ("chansend1", "send on channel (compiler generated)"),
    ("chanrecv", "receive value from channel (<-ch)"),
    ("chanrecv1", "receive from channel (compiler generated)"),
    ("chanrecv2", "receive from channel with ok"),
    ("closechan", "close a channel"),
    ("selectgo", "Go select statement implementation"),
    ("selectnbsend", "non-blocking channel send in select"),
    ("selectnbrecv", "non-blocking channel receive in select"),
    ("selectnbrecv2", "non-blocking receive with ok in select"),
    ("block", "block forever (unreachable channel op)"),
    ("reflect_chansend", "reflect channel send"),
    ("reflect_chanrecv", "reflect channel receive"),
    ("reflect_chanlen", "reflect channel length"),
    ("reflect_chanclose", "reflect channel close"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_channel")

# --- Runtime: sync ---
for fn, purpose in [
    ("lock", "runtime internal lock acquire"),
    ("lock2", "runtime internal lock acquire v2"),
    ("unlock", "runtime internal lock release"),
    ("unlock2", "runtime internal lock release v2"),
    ("semacquire", "semaphore acquire (used by sync pkg)"),
    ("semacquire1", "semaphore acquire variant"),
    ("semrelease", "semaphore release"),
    ("semrelease1", "semaphore release variant"),
    ("noteclear", "clear notification"),
    ("notewakeup", "wake up notification"),
    ("notesleep", "sleep on notification"),
    ("notetsleep", "timed sleep on notification"),
    ("notetsleepg", "timed sleep on notification (goroutine)"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_sync")

# --- Runtime: panic/defer ---
for fn, purpose in [
    ("throw", "runtime fatal error (unrecoverable)"),
    ("fatal", "runtime fatal error"),
    ("fatalthrow", "fatal throw error"),
    ("gopanic", "Go panic() entry point"),
    ("gorecover", "Go recover() entry point"),
    ("goPanicIndex", "panic: index out of range"),
    ("goPanicIndexU", "panic: unsigned index out of range"),
    ("goPanicSliceAlen", "panic: slice len out of range"),
    ("goPanicSliceAlenU", "panic: unsigned slice len out of range"),
    ("goPanicSliceAcap", "panic: slice cap out of range"),
    ("goPanicSliceAcapU", "panic: unsigned slice cap out of range"),
    ("goPanicSliceB", "panic: slice [:b] out of range"),
    ("goPanicSliceBU", "panic: unsigned slice [:b] out of range"),
    ("goPanicSlice3Alen", "panic: 3-index slice len out of range"),
    ("goPanicSlice3AlenU", "panic: unsigned 3-index slice len"),
    ("goPanicSlice3Acap", "panic: 3-index slice cap out of range"),
    ("goPanicSlice3AcapU", "panic: unsigned 3-index slice cap"),
    ("goPanicSlice3B", "panic: 3-index slice [:b:] out of range"),
    ("goPanicSlice3BU", "panic: unsigned 3-index slice [:b:]"),
    ("goPanicSlice3C", "panic: 3-index slice [::c] out of range"),
    ("goPanicSlice3CU", "panic: unsigned 3-index slice [::c]"),
    ("goPanicSliceConvert", "panic: slice type conversion"),
    ("panicshift", "panic: shift count overflow"),
    ("panicdivide", "panic: integer divide by zero"),
    ("panicmem", "panic: invalid memory address (nil deref)"),
    ("panicmemAddr", "panic: invalid memory address"),
    ("panicnildottype", "panic: nil pointer type assertion"),
    ("panicoverflow", "panic: integer overflow"),
    ("panicfloat", "panic: float conversion overflow"),
    ("panicwrap", "panic: method call on nil"),
    ("panicdottypeE", "panic: empty interface type assertion"),
    ("panicdottypeI", "panic: interface type assertion"),
    ("panicunsafeslicelen", "panic: unsafe.Slice negative length"),
    ("panicunsafeslicenilptr", "panic: unsafe.Slice nil pointer"),
    ("panicunsafestringlen", "panic: unsafe.String negative length"),
    ("panicunsafestringnilptr", "panic: unsafe.String nil pointer"),
    ("deferproc", "register deferred function call"),
    ("deferreturn", "execute deferred function calls"),
    ("deferprocStack", "defer on stack (optimization)"),
    ("deferCallSave", "save state for open-coded defer"),
    ("deferFunc", "get deferred function"),
    ("freedefer", "free defer record"),
    ("newdefer", "allocate new defer record"),
    ("printpanics", "print panic chain"),
    ("preprintpanics", "prepare to print panics"),
    ("recovery", "recovery from panic"),
    ("fatalpanic", "fatal unrecovered panic"),
    ("startpanic_m", "start panic on M"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_panic")

# --- Runtime: interfaces / type assertions ---
for fn, purpose in [
    ("convT", "convert concrete type to interface"),
    ("convTstring", "convert string to interface"),
    ("convTslice", "convert slice to interface"),
    ("convT16", "convert 16-bit to interface"),
    ("convT32", "convert 32-bit to interface"),
    ("convT64", "convert 64-bit to interface"),
    ("convTnoptr", "convert no-pointer type to interface"),
    ("assertI2I", "interface-to-interface type assertion"),
    ("assertI2I2", "interface-to-interface (comma-ok)"),
    ("assertE2I", "empty-to-interface type assertion"),
    ("assertE2I2", "empty-to-interface (comma-ok)"),
    ("convI2I", "convert between interface types"),
    ("panicdottypeE", "empty iface type assert panic"),
    ("panicdottypeI", "iface type assert panic"),
    ("getitab", "get interface method table"),
    ("additab", "add to interface table cache"),
    ("itabsinit", "initialize interface tables"),
    ("itabAdd", "add interface table entry"),
    ("itabHashFunc", "hash function for itab"),
    ("typ2Itab", "create itab from type"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_runtime")

# --- Runtime: stack / morestack ---
for fn, purpose in [
    ("morestack", "goroutine stack growth"),
    ("morestack_noctxt", "goroutine stack growth (no closure context)"),
    ("rt0_go", "Go bootstrap entry point (before runtime.main)"),
    ("systemstack", "switch to system stack"),
    ("mcall", "call function on m stack"),
    ("gogo", "switch to goroutine (context switch)"),
    ("gosave_systemstack_switch", "save context for system stack switch"),
    ("asmcgocall", "call C from Go (asm)"),
    ("cgocall", "call C from Go"),
    ("cgocallback", "callback from C to Go"),
    ("cgocallbackg", "callback from C to Go (goroutine)"),
    ("cgocallbackg1", "callback from C to Go (goroutine phase 1)"),
    ("asmcgocall_no_g", "C call without goroutine"),
    ("Caller", "get calling goroutine stack info"),
    ("Callers", "get stack trace of goroutine"),
    ("Stack", "format stack trace"),
    ("FuncForPC", "get function info for program counter"),
    ("printstring", "runtime internal string print"),
    ("printint", "runtime internal int print"),
    ("printuint", "runtime internal uint print"),
    ("printhex", "runtime internal hex print"),
    ("printfloat", "runtime internal float print"),
    ("printnl", "runtime internal newline print"),
    ("printbool", "runtime internal bool print"),
    ("printsp", "runtime internal space print"),
    ("printpointer", "runtime internal pointer print"),
    ("printslice", "runtime internal slice print"),
    ("printcomplex", "runtime internal complex print"),
    ("printeface", "runtime internal eface print"),
    ("printiface", "runtime internal iface print"),
    ("printlock", "lock runtime print"),
    ("printunlock", "unlock runtime print"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_runtime")

# --- Runtime: OS/syscall interface ---
for fn, purpose in [
    ("osinit", "OS-specific initialization"),
    ("goenvs", "initialize Go environment"),
    ("args", "process command-line arguments"),
    ("getRandomData", "get random data from OS"),
    ("sysargs", "process system arguments"),
    ("write", "write to file descriptor"),
    ("write1", "write to fd (internal)"),
    ("read", "read from file descriptor"),
    ("open", "open file descriptor"),
    ("closefd", "close file descriptor"),
    ("exit", "exit process"),
    ("raise", "raise signal"),
    ("raiseproc", "raise signal for process"),
    ("crash", "crash process"),
    ("mmap", "memory map"),
    ("munmap", "memory unmap"),
    ("madvise", "memory advice to OS"),
    ("nanotime", "monotonic time in nanoseconds"),
    ("nanotime1", "monotonic time (internal)"),
    ("walltime", "wall clock time"),
    ("walltime1", "wall clock time (internal)"),
    ("usleep", "sleep microseconds"),
    ("usleep_no_g", "sleep without goroutine"),
    ("osyield", "OS thread yield"),
    ("procyield", "processor yield (spin)"),
    ("futex", "futex syscall wrapper"),
    ("futexwakeup", "futex wakeup"),
    ("futexsleep", "futex sleep"),
    ("getproccount", "get processor count from OS"),
    ("getpid", "get process ID"),
    ("getg", "get current goroutine pointer"),
    ("setg", "set goroutine pointer"),
    ("getm", "get current M pointer"),
    ("getcallerpc", "get caller program counter"),
    ("getcallersp", "get caller stack pointer"),
    ("getsp", "get current stack pointer"),
    ("cputicks", "get CPU cycle counter"),
    ("asmstdcall", "asm standard call (Windows)"),
    ("sigpanic", "handle signal as panic"),
    ("sigpanic0", "signal panic entry"),
    ("sigreturn", "return from signal handler"),
    ("mincore", "check page residency"),
    ("mlock", "lock memory pages"),
    ("tgkill", "send signal to thread (Linux)"),
    ("osRelax", "allow OS thread scheduling relaxation"),
    ("sysSigaction", "set signal action"),
    ("setsig", "set signal handler"),
    ("sigaltstack", "set alternate signal stack"),
    ("sigprocmask", "set signal mask"),
    ("clone", "create new thread (Linux)"),
    ("newosproc", "create new OS thread"),
    ("newosproc0", "create OS thread for bootstrap"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_runtime")

# --- Runtime: reflect support ---
for fn, purpose in [
    ("reflect_typedmemmove", "reflect typed memory move"),
    ("reflect_typedslicecopy", "reflect typed slice copy"),
    ("reflect_unsafe_New", "reflect allocate new"),
    ("reflect_unsafe_NewArray", "reflect allocate new array"),
    ("reflect_mapaccess", "reflect map access"),
    ("reflect_mapassign", "reflect map assign"),
    ("reflect_mapdelete", "reflect map delete"),
    ("reflect_mapiterinit", "reflect map iter init"),
    ("reflect_mapiternext", "reflect map iter next"),
    ("reflect_mapiterkey", "reflect map iter key"),
    ("reflect_mapiterelem", "reflect map iter elem"),
    ("reflect_maplen", "reflect map length"),
    ("reflect_makemap", "reflect make map"),
    ("reflect_makechan", "reflect make channel"),
    ("reflect_chansend", "reflect channel send"),
    ("reflect_chanrecv", "reflect channel receive"),
    ("reflect_chanlen", "reflect channel length"),
    ("reflect_chanclose", "reflect channel close"),
    ("reflect_ifaceE2I", "reflect empty to iface"),
    ("reflectlite_typedmemmove", "reflectlite typed move"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_runtime")

# --- Runtime: race/msan/asan ---
for fn, purpose in [
    ("raceinit", "race detector init"),
    ("racefini", "race detector finish"),
    ("raceread", "race detector read"),
    ("racewrite", "race detector write"),
    ("racereadrange", "race detector read range"),
    ("racewriterange", "race detector write range"),
    ("raceacquire", "race detector acquire"),
    ("racerelease", "race detector release"),
    ("raceacquireg", "race detector acquire goroutine"),
    ("racereleaseg", "race detector release goroutine"),
    ("racefuncenter", "race detector function enter"),
    ("racefuncexit", "race detector function exit"),
    ("msanread", "memory sanitizer read"),
    ("msanwrite", "memory sanitizer write"),
    ("msanmalloc", "memory sanitizer malloc"),
    ("msanfree", "memory sanitizer free"),
    ("asanread", "address sanitizer read"),
    ("asanwrite", "address sanitizer write"),
]:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_runtime")

# --- Runtime: internal packages ---
for fn, purpose in [
    ("runtime/internal/atomic.Load", "atomic load uint32"),
    ("runtime/internal/atomic.Load64", "atomic load uint64"),
    ("runtime/internal/atomic.LoadAcq", "atomic load acquire"),
    ("runtime/internal/atomic.LoadAcq64", "atomic load acquire 64"),
    ("runtime/internal/atomic.Loadp", "atomic load pointer"),
    ("runtime/internal/atomic.Store", "atomic store uint32"),
    ("runtime/internal/atomic.Store64", "atomic store uint64"),
    ("runtime/internal/atomic.StoreRel", "atomic store release"),
    ("runtime/internal/atomic.StoreRel64", "atomic store release 64"),
    ("runtime/internal/atomic.Storep", "atomic store pointer"),
    ("runtime/internal/atomic.Xadd", "atomic add uint32"),
    ("runtime/internal/atomic.Xadd64", "atomic add uint64"),
    ("runtime/internal/atomic.Xchg", "atomic exchange uint32"),
    ("runtime/internal/atomic.Xchg64", "atomic exchange uint64"),
    ("runtime/internal/atomic.Xchguintptr", "atomic exchange uintptr"),
    ("runtime/internal/atomic.Cas", "compare-and-swap uint32"),
    ("runtime/internal/atomic.Cas64", "compare-and-swap uint64"),
    ("runtime/internal/atomic.CasRel", "CAS release uint32"),
    ("runtime/internal/atomic.Casp1", "CAS pointer"),
    ("runtime/internal/atomic.Casuintptr", "CAS uintptr"),
    ("runtime/internal/atomic.Or8", "atomic OR byte"),
    ("runtime/internal/atomic.And8", "atomic AND byte"),
    ("runtime/internal/math.MulUintptr", "multiply uintptr with overflow check"),
    ("runtime/internal/sys.OnesCount64", "count ones in uint64"),
    ("runtime/internal/sys.TrailingZeros64", "count trailing zeros uint64"),
    ("runtime/internal/sys.Len64", "bit length of uint64"),
    ("runtime/internal/sys.Prefetch", "prefetch cache line"),
    ("runtime/internal/sys.PrefetchStreamed", "prefetch streamed cache line"),
]:
    add(fn, "go-runtime-internal", purpose, "go_runtime")

# --- internal/abi, internal/bytealg ---
for fn, purpose in [
    ("internal/bytealg.IndexByte", "find byte in slice"),
    ("internal/bytealg.IndexByteString", "find byte in string"),
    ("internal/bytealg.IndexString", "find string in string"),
    ("internal/bytealg.Index", "find bytes in bytes"),
    ("internal/bytealg.Compare", "compare byte slices"),
    ("internal/bytealg.Equal", "check byte slice equality"),
    ("internal/bytealg.Count", "count byte occurrences"),
    ("internal/bytealg.CountString", "count byte in string"),
    ("internal/bytealg.Cutover", "algorithm cutover threshold"),
    ("internal/bytealg.HashStr", "hash string (Rabin-Karp)"),
    ("internal/bytealg.HashStrBytes", "hash bytes (Rabin-Karp)"),
    ("internal/bytealg.IndexRabinKarp", "Rabin-Karp string search"),
    ("internal/bytealg.MakeNoZero", "allocate without zeroing"),
    ("internal/abi.FuncPCABI0", "get ABI0 function PC"),
    ("internal/abi.FuncPCABIInternal", "get ABIInternal function PC"),
    ("internal/reflectlite.TypeOf", "lightweight typeof"),
    ("internal/poll.(*FD).Read", "internal file descriptor read"),
    ("internal/poll.(*FD).Write", "internal file descriptor write"),
    ("internal/poll.(*FD).Close", "internal file descriptor close"),
    ("internal/poll.(*FD).Init", "internal file descriptor init"),
    ("internal/poll.(*FD).Pread", "internal pread"),
    ("internal/poll.(*FD).Pwrite", "internal pwrite"),
    ("internal/poll.(*FD).ReadMsg", "internal read message"),
    ("internal/poll.(*FD).WriteMsg", "internal write message"),
    ("internal/poll.(*FD).Accept", "internal accept connection"),
    ("internal/poll.(*FD).RawControl", "internal raw fd control"),
    ("internal/poll.(*pollDesc).init", "poll descriptor init"),
    ("internal/poll.(*pollDesc).evict", "poll descriptor evict"),
    ("internal/poll.runtime_pollServerInit", "poll server init"),
    ("internal/poll.runtime_pollOpen", "poll open fd"),
    ("internal/poll.runtime_pollClose", "poll close fd"),
    ("internal/poll.runtime_pollWait", "poll wait for event"),
    ("internal/poll.runtime_pollWaitCanceled", "poll wait canceled"),
    ("internal/poll.runtime_pollReset", "poll reset"),
    ("internal/poll.runtime_pollSetDeadline", "poll set deadline"),
    ("internal/poll.runtime_pollUnblock", "poll unblock"),
]:
    add(fn, "go-internal", purpose, "go_runtime")


# =============================================================================
# PART 2: STANDARD LIBRARY (comprehensive)
# =============================================================================

# --- fmt ---
fmt_funcs = {
    "Errorf": "format error message",
    "Fprint": "print to io.Writer",
    "Fprintf": "formatted I/O to io.Writer",
    "Fprintln": "print line to io.Writer",
    "Fscan": "scan from io.Reader",
    "Fscanf": "formatted scan from io.Reader",
    "Fscanln": "scan line from io.Reader",
    "Print": "print to stdout",
    "Printf": "formatted I/O to stdout",
    "Println": "print with newline to stdout",
    "Scan": "scan from stdin",
    "Scanf": "formatted scan from stdin",
    "Scanln": "scan line from stdin",
    "Sprint": "format to string",
    "Sprintf": "formatted string return",
    "Sprintln": "format line to string",
    "Sscan": "scan from string",
    "Sscanf": "scan formatted string",
    "Sscanln": "scan line from string",
    "Append": "format and append to byte slice",
    "Appendf": "formatted append to byte slice",
    "Appendln": "append line to byte slice",
}
for fn, p in fmt_funcs.items():
    add_func("fmt", fn, "go-fmt", p, "go_fmt")

# --- os ---
os_funcs = {
    "Create": "create or truncate file",
    "CreateTemp": "create temporary file",
    "NewFile": "create File from fd",
    "Open": "open file for reading",
    "OpenFile": "open file with flags and permissions",
    "Chdir": "change working directory",
    "Chmod": "change file mode",
    "Chown": "change file ownership",
    "Chtimes": "change file access/modification times",
    "Clearenv": "clear all environment variables",
    "DirFS": "return filesystem rooted at dir",
    "Environ": "get all environment variables",
    "Executable": "get path of current executable",
    "Exit": "exit process with status code",
    "Expand": "expand environment variables in string",
    "ExpandEnv": "expand $VAR in string using environ",
    "Getegid": "get effective group ID",
    "Getenv": "get environment variable",
    "Geteuid": "get effective user ID",
    "Getgid": "get group ID",
    "Getgroups": "get supplementary group IDs",
    "Getpagesize": "get system page size",
    "Getpid": "get process ID",
    "Getppid": "get parent process ID",
    "Getuid": "get user ID",
    "Getwd": "get current working directory",
    "Hostname": "get system hostname",
    "IsExist": "check if error is 'already exists'",
    "IsNotExist": "check if error is 'not found'",
    "IsPathSeparator": "check if byte is path separator",
    "IsPermission": "check if error is permission denied",
    "IsTimeout": "check if error is timeout",
    "Lchown": "change symlink ownership",
    "Link": "create hard link",
    "LookupEnv": "lookup env var with existence check",
    "Lstat": "get file info (no follow symlink)",
    "Mkdir": "create directory",
    "MkdirAll": "create directory tree",
    "MkdirTemp": "create temporary directory",
    "Pipe": "create pipe file descriptors",
    "ReadDir": "read directory entries",
    "ReadFile": "read entire file contents",
    "Readlink": "read symbolic link target",
    "Remove": "remove file or empty directory",
    "RemoveAll": "remove file/directory tree",
    "Rename": "rename file",
    "SameFile": "check if two FileInfo are same file",
    "Setenv": "set environment variable",
    "Stat": "get file info",
    "Symlink": "create symbolic link",
    "TempDir": "get temp directory path",
    "Truncate": "truncate file to size",
    "Unsetenv": "unset environment variable",
    "UserCacheDir": "get user cache directory",
    "UserConfigDir": "get user config directory",
    "UserHomeDir": "get user home directory",
    "WriteFile": "write data to file",
}
for fn, p in os_funcs.items():
    add_func("os", fn, "go-os", p, "go_os")

# os.File methods
for method, purpose in [
    ("Read", "read from file"),
    ("ReadAt", "read from file at offset"),
    ("ReadDir", "read directory entries from file"),
    ("ReadFrom", "read from reader into file"),
    ("Write", "write to file"),
    ("WriteAt", "write to file at offset"),
    ("WriteString", "write string to file"),
    ("Close", "close file"),
    ("Stat", "get file info"),
    ("Sync", "sync file to disk"),
    ("Seek", "seek in file"),
    ("Truncate", "truncate file"),
    ("Fd", "get file descriptor"),
    ("Name", "get file name"),
    ("Chdir", "change to file directory"),
    ("Chmod", "change file mode"),
    ("Chown", "change file ownership"),
    ("Readdir", "read directory (deprecated)"),
    ("Readdirnames", "read directory names"),
    ("SetDeadline", "set file I/O deadline"),
    ("SetReadDeadline", "set read deadline"),
    ("SetWriteDeadline", "set write deadline"),
    ("SyscallConn", "get raw syscall connection"),
]:
    add_method("os", "File", method, "go-os", purpose, "go_os")

# os.Process methods
for method, purpose in [
    ("Kill", "kill process"),
    ("Signal", "send signal to process"),
    ("Wait", "wait for process to exit"),
    ("Release", "release process resources"),
]:
    add_method("os", "Process", method, "go-os", purpose, "go_os")

# --- io ---
io_funcs = {
    "Copy": "copy from Reader to Writer",
    "CopyBuffer": "copy with buffer",
    "CopyN": "copy N bytes",
    "LimitReader": "limit reader to N bytes",
    "MultiReader": "concatenate multiple Readers",
    "MultiWriter": "duplicate writes to multiple Writers",
    "NopCloser": "wrap Reader with no-op Close",
    "Pipe": "create in-memory pipe",
    "ReadAll": "read all bytes from Reader",
    "ReadAtLeast": "read at least N bytes",
    "ReadFull": "read exactly N bytes",
    "TeeReader": "tee reader output",
    "WriteString": "write string to Writer",
    "NewSectionReader": "create section reader",
    "NewOffsetWriter": "create offset writer",
}
for fn, p in io_funcs.items():
    add_func("io", fn, "go-io", p, "go_io")

# io methods
for method, purpose in [
    ("Read", "read from section"),
    ("ReadAt", "read at offset from section"),
    ("Seek", "seek in section"),
    ("Size", "get section size"),
]:
    add_method("io", "SectionReader", method, "go-io", purpose, "go_io")

# --- io/ioutil (deprecated but still appears) ---
for fn, purpose in [
    ("ReadAll", "read all from reader (deprecated)"),
    ("ReadFile", "read file contents (deprecated)"),
    ("WriteFile", "write file (deprecated)"),
    ("TempDir", "create temp dir (deprecated)"),
    ("TempFile", "create temp file (deprecated)"),
    ("ReadDir", "read directory (deprecated)"),
    ("NopCloser", "no-op closer (deprecated)"),
]:
    add_func("io/ioutil", fn, "go-io", purpose, "go_io")

# --- bufio ---
for fn, purpose in [
    ("NewReader", "create buffered Reader"),
    ("NewReaderSize", "create buffered Reader with size"),
    ("NewWriter", "create buffered Writer"),
    ("NewWriterSize", "create buffered Writer with size"),
    ("NewScanner", "create line scanner"),
    ("NewReadWriter", "create buffered ReadWriter"),
    ("ScanBytes", "split by bytes"),
    ("ScanLines", "split by lines"),
    ("ScanRunes", "split by runes"),
    ("ScanWords", "split by words"),
]:
    add_func("bufio", fn, "go-bufio", purpose, "go_io")

for method, purpose in [
    ("Read", "read buffered data"),
    ("ReadByte", "read single byte"),
    ("ReadBytes", "read until delimiter"),
    ("ReadLine", "read line"),
    ("ReadRune", "read rune"),
    ("ReadSlice", "read until delimiter (no copy)"),
    ("ReadString", "read until delimiter as string"),
    ("Peek", "peek at buffered data"),
    ("Reset", "reset reader buffer"),
    ("Buffered", "get buffered byte count"),
    ("Discard", "discard N bytes"),
    ("UnreadByte", "unread last byte"),
    ("UnreadRune", "unread last rune"),
    ("WriteTo", "write buffered data to writer"),
]:
    add_method("bufio", "Reader", method, "go-bufio", purpose, "go_io")

for method, purpose in [
    ("Write", "write buffered data"),
    ("WriteByte", "write single byte"),
    ("WriteRune", "write rune"),
    ("WriteString", "write string"),
    ("Flush", "flush buffer to underlying writer"),
    ("Reset", "reset writer buffer"),
    ("Available", "get available buffer space"),
    ("Buffered", "get buffered byte count"),
    ("ReadFrom", "read from reader into buffer"),
]:
    add_method("bufio", "Writer", method, "go-bufio", purpose, "go_io")

for method, purpose in [
    ("Scan", "advance scanner to next token"),
    ("Text", "get current token as string"),
    ("Bytes", "get current token as bytes"),
    ("Err", "get scanner error"),
    ("Split", "set split function"),
    ("Buffer", "set scanner buffer"),
]:
    add_method("bufio", "Scanner", method, "go-bufio", purpose, "go_io")

# --- strings ---
strings_funcs = {
    "Clone": "copy string",
    "Compare": "compare strings",
    "Contains": "check if string contains substring",
    "ContainsAny": "check if string contains any chars",
    "ContainsRune": "check if string contains rune",
    "Count": "count non-overlapping instances",
    "Cut": "cut string around separator",
    "CutPrefix": "cut prefix from string",
    "CutSuffix": "cut suffix from string",
    "EqualFold": "case-insensitive string compare",
    "Fields": "split string by whitespace",
    "FieldsFunc": "split string by function",
    "HasPrefix": "check string prefix",
    "HasSuffix": "check string suffix",
    "Index": "find first instance of substr",
    "IndexAny": "find first instance of any char",
    "IndexByte": "find first instance of byte",
    "IndexFunc": "find first rune satisfying function",
    "IndexRune": "find first instance of rune",
    "Join": "join strings with separator",
    "LastIndex": "find last instance of substr",
    "LastIndexAny": "find last instance of any char",
    "LastIndexByte": "find last instance of byte",
    "LastIndexFunc": "find last rune satisfying function",
    "Map": "map function over string",
    "NewReader": "create Reader from string",
    "NewReplacer": "create string replacer",
    "Repeat": "repeat string N times",
    "Replace": "replace substring occurrences",
    "ReplaceAll": "replace all substring occurrences",
    "Split": "split string by separator",
    "SplitAfter": "split after separator",
    "SplitAfterN": "split after separator N times",
    "SplitN": "split N times",
    "Title": "title case string (deprecated)",
    "ToLower": "convert string to lowercase",
    "ToLowerSpecial": "lowercase with special case",
    "ToTitle": "convert string to title case",
    "ToTitleSpecial": "title case with special case",
    "ToUpper": "convert string to uppercase",
    "ToUpperSpecial": "uppercase with special case",
    "ToValidUTF8": "replace invalid UTF-8",
    "Trim": "trim chars from both ends",
    "TrimFunc": "trim runes satisfying function",
    "TrimLeft": "trim chars from left",
    "TrimLeftFunc": "trim left by function",
    "TrimPrefix": "trim prefix",
    "TrimRight": "trim chars from right",
    "TrimRightFunc": "trim right by function",
    "TrimSpace": "trim leading/trailing whitespace",
    "TrimSuffix": "trim suffix",
}
for fn, p in strings_funcs.items():
    add_func("strings", fn, "go-strings", p, "go_string")

for method, purpose in [
    ("Len", "get reader length"),
    ("Read", "read from string"),
    ("ReadAt", "read at offset"),
    ("ReadByte", "read byte"),
    ("ReadRune", "read rune"),
    ("Reset", "reset reader"),
    ("Seek", "seek in string"),
    ("Size", "get string size"),
    ("UnreadByte", "unread byte"),
    ("UnreadRune", "unread rune"),
    ("WriteTo", "write to writer"),
]:
    add_method("strings", "Reader", method, "go-strings", purpose, "go_string")

for method, purpose in [
    ("Cap", "builder capacity"),
    ("Grow", "grow builder capacity"),
    ("Len", "builder length"),
    ("Reset", "reset builder"),
    ("String", "get built string"),
    ("Write", "write bytes to builder"),
    ("WriteByte", "write byte to builder"),
    ("WriteRune", "write rune to builder"),
    ("WriteString", "write string to builder"),
]:
    add_method("strings", "Builder", method, "go-strings", purpose, "go_string")

for method, purpose in [
    ("Replace", "replace in reader"),
    ("WriteString", "write replacement string"),
]:
    add_method("strings", "Replacer", method, "go-strings", purpose, "go_string")

# --- bytes ---
bytes_funcs = {
    "Clone": "copy byte slice",
    "Compare": "compare byte slices",
    "Contains": "check if byte slice contains pattern",
    "ContainsAny": "check for any byte",
    "ContainsRune": "check for rune",
    "Count": "count occurrences",
    "Cut": "cut around separator",
    "CutPrefix": "cut prefix",
    "CutSuffix": "cut suffix",
    "Equal": "compare byte slices for equality",
    "EqualFold": "case-insensitive compare",
    "Fields": "split by whitespace",
    "FieldsFunc": "split by function",
    "HasPrefix": "check prefix",
    "HasSuffix": "check suffix",
    "Index": "find first occurrence",
    "IndexAny": "find first of any byte",
    "IndexByte": "find byte",
    "IndexFunc": "find by function",
    "IndexRune": "find rune",
    "Join": "join with separator",
    "LastIndex": "find last occurrence",
    "LastIndexAny": "find last of any byte",
    "LastIndexByte": "find last byte",
    "LastIndexFunc": "find last by function",
    "Map": "map function over bytes",
    "NewBuffer": "create byte buffer from initial data",
    "NewBufferString": "create byte buffer from string",
    "NewReader": "create Reader from byte slice",
    "Repeat": "repeat bytes N times",
    "Replace": "replace occurrences",
    "ReplaceAll": "replace all occurrences",
    "Runes": "convert to runes",
    "Split": "split by separator",
    "SplitAfter": "split after separator",
    "SplitAfterN": "split after N times",
    "SplitN": "split N times",
    "Title": "title case (deprecated)",
    "ToLower": "convert to lowercase",
    "ToLowerSpecial": "lowercase special",
    "ToTitle": "convert to title case",
    "ToTitleSpecial": "title case special",
    "ToUpper": "convert to uppercase",
    "ToUpperSpecial": "uppercase special",
    "ToValidUTF8": "replace invalid UTF-8",
    "Trim": "trim bytes",
    "TrimFunc": "trim by function",
    "TrimLeft": "trim left",
    "TrimLeftFunc": "trim left by function",
    "TrimPrefix": "trim prefix",
    "TrimRight": "trim right",
    "TrimRightFunc": "trim right by function",
    "TrimSpace": "trim whitespace",
    "TrimSuffix": "trim suffix",
}
for fn, p in bytes_funcs.items():
    add_func("bytes", fn, "go-bytes", p, "go_string")

for method, purpose in [
    ("Bytes", "get buffer contents"),
    ("Cap", "buffer capacity"),
    ("Grow", "grow buffer"),
    ("Len", "buffer length"),
    ("Next", "read next N bytes"),
    ("Read", "read from buffer"),
    ("ReadByte", "read byte"),
    ("ReadBytes", "read until delimiter"),
    ("ReadFrom", "read from reader"),
    ("ReadRune", "read rune"),
    ("ReadString", "read until delimiter"),
    ("Reset", "reset buffer"),
    ("String", "get string"),
    ("Truncate", "truncate buffer"),
    ("UnreadByte", "unread byte"),
    ("UnreadRune", "unread rune"),
    ("Write", "write bytes"),
    ("WriteByte", "write byte"),
    ("WriteRune", "write rune"),
    ("WriteString", "write string"),
    ("WriteTo", "write to writer"),
]:
    add_method("bytes", "Buffer", method, "go-bytes", purpose, "go_string")

# --- strconv ---
strconv_funcs = {
    "AppendBool": "append bool to byte slice",
    "AppendFloat": "append float to byte slice",
    "AppendInt": "append int to byte slice",
    "AppendQuote": "append quoted string to byte slice",
    "AppendQuoteRune": "append quoted rune to byte slice",
    "AppendQuoteRuneToASCII": "append ASCII quoted rune",
    "AppendQuoteRuneToGraphic": "append graphic quoted rune",
    "AppendQuoteToASCII": "append ASCII quoted string",
    "AppendQuoteToGraphic": "append graphic quoted string",
    "AppendUint": "append uint to byte slice",
    "Atoi": "ASCII string to integer",
    "CanBackquote": "check if string can be backquoted",
    "FormatBool": "format bool to string",
    "FormatComplex": "format complex to string",
    "FormatFloat": "format float to string",
    "FormatInt": "format int64 to string",
    "FormatUint": "format uint64 to string",
    "IsGraphic": "check if rune is graphic",
    "IsPrint": "check if rune is printable",
    "Itoa": "integer to ASCII string",
    "ParseBool": "parse string to bool",
    "ParseComplex": "parse string to complex",
    "ParseFloat": "parse string to float",
    "ParseInt": "parse string to int64",
    "ParseUint": "parse string to uint64",
    "Quote": "quote string",
    "QuoteRune": "quote rune",
    "QuoteRuneToASCII": "ASCII quote rune",
    "QuoteRuneToGraphic": "graphic quote rune",
    "QuoteToASCII": "ASCII quote string",
    "QuoteToGraphic": "graphic quote string",
    "Unquote": "unquote string",
    "UnquoteChar": "unquote character",
}
for fn, p in strconv_funcs.items():
    add_func("strconv", fn, "go-strconv", p, "go_string")

# --- unicode/utf8 ---
utf8_funcs = {
    "DecodeLastRune": "decode last rune in bytes",
    "DecodeLastRuneInString": "decode last rune in string",
    "DecodeRune": "decode first rune in bytes",
    "DecodeRuneInString": "decode first rune in string",
    "EncodeRune": "encode rune to bytes",
    "FullRune": "check if bytes are complete rune",
    "FullRuneInString": "check if string starts with full rune",
    "RuneCount": "count runes in bytes",
    "RuneCountInString": "count runes in string",
    "RuneLen": "get encoded rune length",
    "RuneStart": "check if byte starts a rune",
    "Valid": "check if bytes are valid UTF-8",
    "ValidRune": "check if rune is valid",
    "ValidString": "check if string is valid UTF-8",
    "AppendRune": "append rune to byte slice",
}
for fn, p in utf8_funcs.items():
    add_func("unicode/utf8", fn, "go-unicode", p, "go_string")

# --- unicode ---
unicode_funcs = {
    "In": "check if rune is in range table",
    "Is": "check if rune is in range table",
    "IsControl": "check if rune is control char",
    "IsDigit": "check if rune is digit",
    "IsGraphic": "check if rune is graphic",
    "IsLetter": "check if rune is letter",
    "IsLower": "check if rune is lowercase",
    "IsMark": "check if rune is mark",
    "IsNumber": "check if rune is number",
    "IsOneOf": "check rune against range tables",
    "IsPrint": "check if rune is printable",
    "IsPunct": "check if rune is punctuation",
    "IsSpace": "check if rune is space",
    "IsSymbol": "check if rune is symbol",
    "IsTitle": "check if rune is title case",
    "IsUpper": "check if rune is uppercase",
    "SimpleFold": "simple Unicode case fold",
    "To": "convert rune case",
    "ToLower": "convert rune to lowercase",
    "ToTitle": "convert rune to title case",
    "ToUpper": "convert rune to uppercase",
}
for fn, p in unicode_funcs.items():
    add_func("unicode", fn, "go-unicode", p, "go_string")

# --- net ---
net_funcs = {
    "Dial": "connect to network address",
    "DialTimeout": "connect with timeout",
    "DialIP": "connect to IP address",
    "DialTCP": "connect TCP",
    "DialUDP": "connect UDP",
    "DialUnix": "connect Unix domain socket",
    "FileConn": "create Conn from file",
    "FileListener": "create Listener from file",
    "FilePacketConn": "create PacketConn from file",
    "InterfaceAddrs": "get network interface addresses",
    "InterfaceByIndex": "get interface by index",
    "InterfaceByName": "get interface by name",
    "Interfaces": "list network interfaces",
    "JoinHostPort": "join host and port strings",
    "Listen": "listen on network address",
    "ListenIP": "listen on IP address",
    "ListenMulticastUDP": "listen multicast UDP",
    "ListenPacket": "listen for packets",
    "ListenTCP": "listen TCP",
    "ListenUDP": "listen UDP",
    "ListenUnix": "listen Unix domain socket",
    "ListenUnixgram": "listen Unix datagram",
    "LookupAddr": "reverse DNS lookup",
    "LookupCNAME": "lookup CNAME record",
    "LookupHost": "DNS hostname lookup",
    "LookupIP": "lookup IP addresses for host",
    "LookupMX": "lookup MX records",
    "LookupNS": "lookup NS records",
    "LookupPort": "lookup port number",
    "LookupSRV": "lookup SRV records",
    "LookupTXT": "lookup TXT records",
    "ParseCIDR": "parse CIDR notation address",
    "ParseIP": "parse IP address string",
    "ParseMAC": "parse MAC address",
    "Pipe": "create in-memory network pipe",
    "ResolveIPAddr": "resolve IP address",
    "ResolveTCPAddr": "resolve TCP address",
    "ResolveUDPAddr": "resolve UDP address",
    "ResolveUnixAddr": "resolve Unix address",
    "SplitHostPort": "split host:port string",
    "CIDRMask": "create CIDR mask",
    "IPv4": "create IPv4 address",
    "IPv4Mask": "create IPv4 mask",
}
for fn, p in net_funcs.items():
    add_func("net", fn, "go-net", p, "go_net")

for receiver, methods in {
    "TCPConn": [
        ("Read", "read data from TCP connection"),
        ("Write", "write data to TCP connection"),
        ("Close", "close TCP connection"),
        ("CloseRead", "close TCP read side"),
        ("CloseWrite", "close TCP write side"),
        ("LocalAddr", "get local address"),
        ("RemoteAddr", "get remote address"),
        ("SetDeadline", "set read/write deadline"),
        ("SetReadDeadline", "set read deadline"),
        ("SetWriteDeadline", "set write deadline"),
        ("SetKeepAlive", "set TCP keepalive"),
        ("SetKeepAlivePeriod", "set keepalive period"),
        ("SetLinger", "set TCP linger"),
        ("SetNoDelay", "set TCP no delay"),
        ("SetReadBuffer", "set read buffer size"),
        ("SetWriteBuffer", "set write buffer size"),
        ("ReadFrom", "read from reader into TCP"),
        ("File", "get underlying file"),
        ("SyscallConn", "get raw syscall connection"),
    ],
    "UDPConn": [
        ("Read", "read UDP data"),
        ("ReadFrom", "read with source address"),
        ("ReadFromUDP", "read UDP datagram"),
        ("ReadMsgUDP", "read UDP message"),
        ("Write", "write UDP data"),
        ("WriteTo", "write to address"),
        ("WriteToUDP", "write UDP datagram"),
        ("WriteMsgUDP", "write UDP message"),
        ("Close", "close UDP connection"),
        ("LocalAddr", "get local address"),
        ("RemoteAddr", "get remote address"),
        ("SetDeadline", "set deadline"),
        ("SetReadDeadline", "set read deadline"),
        ("SetWriteDeadline", "set write deadline"),
        ("SetReadBuffer", "set read buffer"),
        ("SetWriteBuffer", "set write buffer"),
        ("File", "get underlying file"),
    ],
    "TCPListener": [
        ("Accept", "accept TCP connection"),
        ("AcceptTCP", "accept TCP connection (typed)"),
        ("Addr", "get listener address"),
        ("Close", "close listener"),
        ("SetDeadline", "set accept deadline"),
        ("File", "get underlying file"),
        ("SyscallConn", "get raw syscall connection"),
    ],
    "Dialer": [
        ("Dial", "dial network address"),
        ("DialContext", "dial with context"),
    ],
    "Resolver": [
        ("LookupAddr", "reverse DNS lookup"),
        ("LookupCNAME", "lookup CNAME"),
        ("LookupHost", "lookup host"),
        ("LookupIP", "lookup IP"),
        ("LookupIPAddr", "lookup IP addresses"),
        ("LookupMX", "lookup MX records"),
        ("LookupNS", "lookup NS records"),
        ("LookupPort", "lookup port"),
        ("LookupSRV", "lookup SRV records"),
        ("LookupTXT", "lookup TXT records"),
    ],
    "IPConn": [
        ("Read", "read IP data"),
        ("ReadFrom", "read from IP"),
        ("ReadFromIP", "read IP packet"),
        ("ReadMsgIP", "read IP message"),
        ("Write", "write IP data"),
        ("WriteTo", "write to address"),
        ("WriteToIP", "write IP packet"),
        ("WriteMsgIP", "write IP message"),
        ("Close", "close IP connection"),
        ("LocalAddr", "get local address"),
        ("RemoteAddr", "get remote address"),
        ("SetDeadline", "set deadline"),
    ],
    "IP": [
        ("DefaultMask", "get default IP mask"),
        ("Equal", "compare IP addresses"),
        ("IsGlobalUnicast", "check global unicast"),
        ("IsInterfaceLocalMulticast", "check interface multicast"),
        ("IsLinkLocalMulticast", "check link-local multicast"),
        ("IsLinkLocalUnicast", "check link-local unicast"),
        ("IsLoopback", "check loopback"),
        ("IsMulticast", "check multicast"),
        ("IsPrivate", "check private address"),
        ("IsUnspecified", "check unspecified"),
        ("MarshalText", "marshal to text"),
        ("Mask", "apply network mask"),
        ("String", "convert to string"),
        ("To16", "convert to 16-byte form"),
        ("To4", "convert to 4-byte form"),
        ("UnmarshalText", "unmarshal from text"),
    ],
}.items():
    for method, purpose in methods:
        add_method("net", receiver, method, "go-net", purpose, "go_net")

# --- net/http ---
http_funcs = {
    "CanonicalHeaderKey": "canonical header key format",
    "DetectContentType": "detect content type from data",
    "Error": "HTTP error response",
    "Get": "HTTP GET request",
    "Handle": "register HTTP handler",
    "HandleFunc": "register HTTP handler function",
    "Head": "HTTP HEAD request",
    "ListenAndServe": "start HTTP server",
    "ListenAndServeTLS": "start HTTPS server",
    "MaxBytesReader": "limit request body size",
    "NewFileTransport": "create file transport",
    "NewRequest": "create HTTP request",
    "NewRequestWithContext": "create HTTP request with context",
    "NewServeMux": "create new ServeMux",
    "NotFound": "404 handler",
    "NotFoundHandler": "get 404 handler",
    "ParseHTTPVersion": "parse HTTP version string",
    "ParseTime": "parse HTTP time",
    "Post": "HTTP POST request",
    "PostForm": "HTTP POST form request",
    "ProxyFromEnvironment": "get proxy from env",
    "ProxyURL": "create proxy URL function",
    "ReadRequest": "read HTTP request",
    "ReadResponse": "read HTTP response",
    "Redirect": "HTTP redirect response",
    "Serve": "serve HTTP on listener",
    "ServeContent": "serve content with headers",
    "ServeFile": "serve file over HTTP",
    "ServeTLS": "serve HTTPS on listener",
    "SetCookie": "set HTTP cookie",
    "StatusText": "get status text for code",
    "StripPrefix": "strip URL prefix handler",
    "TimeoutHandler": "handler with timeout",
    "FileServer": "create file server handler",
    "NewFileTransportFS": "create file transport from FS",
    "AllowQuerySemicolons": "allow semicolons in query",
    "MaxBytesHandler": "handler with max bytes",
}
for fn, p in http_funcs.items():
    add_func("net/http", fn, "go-net-http", p, "go_http")

for receiver, methods in {
    "Client": [
        ("Do", "execute HTTP request"),
        ("Get", "HTTP GET"),
        ("Head", "HTTP HEAD"),
        ("Post", "HTTP POST"),
        ("PostForm", "HTTP POST form"),
        ("CloseIdleConnections", "close idle connections"),
    ],
    "Server": [
        ("Close", "close server"),
        ("ListenAndServe", "start serving"),
        ("ListenAndServeTLS", "start TLS serving"),
        ("RegisterOnShutdown", "register shutdown callback"),
        ("Serve", "serve on listener"),
        ("ServeTLS", "serve TLS on listener"),
        ("SetKeepAlivesEnabled", "set keepalive"),
        ("Shutdown", "graceful shutdown"),
    ],
    "Request": [
        ("AddCookie", "add cookie to request"),
        ("BasicAuth", "get basic auth"),
        ("Clone", "clone request"),
        ("Context", "get request context"),
        ("Cookie", "get named cookie"),
        ("Cookies", "get all cookies"),
        ("FormFile", "get form file"),
        ("FormValue", "get form value"),
        ("MultipartReader", "get multipart reader"),
        ("ParseForm", "parse URL query and POST form"),
        ("ParseMultipartForm", "parse multipart form"),
        ("PostFormValue", "get POST form value"),
        ("ProtoAtLeast", "check protocol version"),
        ("Referer", "get referer header"),
        ("SetBasicAuth", "set basic auth"),
        ("UserAgent", "get user agent"),
        ("WithContext", "create request with context"),
        ("Write", "write request to writer"),
        ("WriteProxy", "write request as proxy"),
    ],
    "Response": [
        ("Cookies", "get response cookies"),
        ("Location", "get redirect location"),
        ("ProtoAtLeast", "check protocol version"),
        ("Write", "write response"),
    ],
    "ResponseWriter": [
        ("Header", "get response headers"),
        ("Write", "write response body"),
        ("WriteHeader", "write status code"),
    ],
    "Header": [
        ("Add", "add header value"),
        ("Clone", "clone headers"),
        ("Del", "delete header"),
        ("Get", "get header value"),
        ("Set", "set header value"),
        ("Values", "get all header values"),
        ("Write", "write headers"),
        ("WriteSubset", "write header subset"),
    ],
    "Transport": [
        ("CancelRequest", "cancel HTTP request"),
        ("CloseIdleConnections", "close idle connections"),
        ("Clone", "clone transport"),
        ("RegisterProtocol", "register protocol"),
        ("RoundTrip", "execute single HTTP transaction"),
    ],
    "ServeMux": [
        ("Handle", "register handler for pattern"),
        ("HandleFunc", "register handler function"),
        ("Handler", "get handler for request"),
        ("ServeHTTP", "dispatch request to handler"),
    ],
    "Cookie": [
        ("String", "format cookie as string"),
        ("Valid", "validate cookie"),
    ],
}.items():
    for method, purpose in methods:
        add_method("net/http", receiver, method, "go-net-http", purpose, "go_http")

# --- net/http/httputil ---
for fn, purpose in [
    ("DumpRequest", "dump HTTP request"),
    ("DumpRequestOut", "dump outgoing request"),
    ("DumpResponse", "dump HTTP response"),
    ("NewChunkedReader", "create chunked reader"),
    ("NewChunkedWriter", "create chunked writer"),
    ("NewSingleHostReverseProxy", "create reverse proxy"),
]:
    add_func("net/http/httputil", fn, "go-net-http", purpose, "go_http")

for method, purpose in [
    ("ServeHTTP", "serve reverse proxy"),
    ("ModifyResponse", "modify proxy response"),
    ("FlushInterval", "proxy flush interval"),
]:
    add_method("net/http/httputil", "ReverseProxy", method, "go-net-http", purpose, "go_http")

# --- net/url ---
for fn, purpose in [
    ("Parse", "parse URL string"),
    ("ParseQuery", "parse URL query string"),
    ("ParseRequestURI", "parse request URI"),
    ("PathEscape", "escape URL path"),
    ("PathUnescape", "unescape URL path"),
    ("QueryEscape", "escape URL query"),
    ("QueryUnescape", "unescape URL query"),
    ("JoinPath", "join URL path elements"),
]:
    add_func("net/url", fn, "go-net-url", purpose, "go_net")

for method, purpose in [
    ("EscapedFragment", "escaped fragment"),
    ("EscapedPath", "escaped path"),
    ("Hostname", "get hostname"),
    ("IsAbs", "check if absolute URL"),
    ("JoinPath", "join path elements"),
    ("MarshalBinary", "marshal URL"),
    ("Parse", "parse relative URL"),
    ("Port", "get port"),
    ("Query", "parse query string"),
    ("Redacted", "URL with redacted password"),
    ("RequestURI", "get request URI"),
    ("ResolveReference", "resolve relative reference"),
    ("String", "format URL as string"),
    ("UnmarshalBinary", "unmarshal URL"),
]:
    add_method("net/url", "URL", method, "go-net-url", purpose, "go_net")

for method, purpose in [
    ("Add", "add value to query"),
    ("Del", "delete query key"),
    ("Encode", "encode query string"),
    ("Get", "get query value"),
    ("Has", "check if key exists"),
    ("Set", "set query value"),
]:
    add_method("net/url", "Values", method, "go-net-url", purpose, "go_net")

# --- encoding/json ---
json_funcs = {
    "Compact": "compact JSON encoding",
    "HTMLEscape": "HTML-escape JSON",
    "Indent": "indent JSON",
    "Marshal": "JSON marshal (struct to bytes)",
    "MarshalIndent": "JSON marshal with indent",
    "NewDecoder": "create streaming JSON decoder",
    "NewEncoder": "create streaming JSON encoder",
    "Unmarshal": "JSON unmarshal (bytes to struct)",
    "Valid": "check if valid JSON",
}
for fn, p in json_funcs.items():
    add_func("encoding/json", fn, "go-json", p, "go_json")

for method, purpose in [
    ("Decode", "decode JSON from stream"),
    ("Buffered", "get decoder buffer"),
    ("DisallowUnknownFields", "disallow unknown JSON fields"),
    ("InputOffset", "get decoder input offset"),
    ("More", "check if more JSON values"),
    ("Token", "get next JSON token"),
    ("UseNumber", "use json.Number for numbers"),
]:
    add_method("encoding/json", "Decoder", method, "go-json", purpose, "go_json")

for method, purpose in [
    ("Encode", "encode JSON to stream"),
    ("SetEscapeHTML", "set HTML escaping"),
    ("SetIndent", "set encoding indent"),
]:
    add_method("encoding/json", "Encoder", method, "go-json", purpose, "go_json")

# --- encoding/xml ---
xml_funcs = {
    "Escape": "XML escape text",
    "EscapeText": "XML escape text to writer",
    "Marshal": "XML marshal",
    "MarshalIndent": "XML marshal with indent",
    "NewDecoder": "create XML decoder",
    "NewEncoder": "create XML encoder",
    "NewTokenDecoder": "create token-based decoder",
    "Unmarshal": "XML unmarshal",
    "CopyToken": "copy XML token",
}
for fn, p in xml_funcs.items():
    add_func("encoding/xml", fn, "go-xml", p, "go_encoding")

for method, purpose in [
    ("Decode", "decode XML"),
    ("DecodeElement", "decode XML element"),
    ("InputOffset", "get decoder offset"),
    ("InputPos", "get decoder position"),
    ("RawToken", "get raw XML token"),
    ("Skip", "skip XML element"),
    ("Token", "get next XML token"),
]:
    add_method("encoding/xml", "Decoder", method, "go-xml", purpose, "go_encoding")

# --- encoding/base64, encoding/hex, encoding/binary, encoding/csv, encoding/gob, encoding/pem ---
for fn, purpose in [
    ("encoding/base64.NewDecoder", "create base64 decoder"),
    ("encoding/base64.NewEncoder", "create base64 encoder"),
    ("encoding/base64.StdEncoding.EncodeToString", "base64 encode to string"),
    ("encoding/base64.StdEncoding.DecodeString", "base64 decode from string"),
    ("encoding/base64.URLEncoding.EncodeToString", "URL-safe base64 encode"),
    ("encoding/base64.URLEncoding.DecodeString", "URL-safe base64 decode"),
    ("encoding/base64.RawStdEncoding.EncodeToString", "raw base64 encode"),
    ("encoding/base64.RawStdEncoding.DecodeString", "raw base64 decode"),
    ("encoding/base64.RawURLEncoding.EncodeToString", "raw URL-safe base64 encode"),
    ("encoding/base64.RawURLEncoding.DecodeString", "raw URL-safe base64 decode"),
    ("encoding/hex.Decode", "hex decode bytes"),
    ("encoding/hex.DecodeString", "hex decode string"),
    ("encoding/hex.DecodedLen", "decoded hex length"),
    ("encoding/hex.Dump", "hex dump bytes"),
    ("encoding/hex.Dumper", "create hex dumper"),
    ("encoding/hex.Encode", "hex encode bytes"),
    ("encoding/hex.EncodeToString", "hex encode to string"),
    ("encoding/hex.EncodedLen", "encoded hex length"),
    ("encoding/hex.NewDecoder", "create hex decoder"),
    ("encoding/hex.NewEncoder", "create hex encoder"),
    ("encoding/binary.Read", "read binary data from reader"),
    ("encoding/binary.Write", "write binary data to writer"),
    ("encoding/binary.BigEndian.Uint16", "read big-endian uint16"),
    ("encoding/binary.BigEndian.Uint32", "read big-endian uint32"),
    ("encoding/binary.BigEndian.Uint64", "read big-endian uint64"),
    ("encoding/binary.BigEndian.PutUint16", "write big-endian uint16"),
    ("encoding/binary.BigEndian.PutUint32", "write big-endian uint32"),
    ("encoding/binary.BigEndian.PutUint64", "write big-endian uint64"),
    ("encoding/binary.LittleEndian.Uint16", "read little-endian uint16"),
    ("encoding/binary.LittleEndian.Uint32", "read little-endian uint32"),
    ("encoding/binary.LittleEndian.Uint64", "read little-endian uint64"),
    ("encoding/binary.LittleEndian.PutUint16", "write little-endian uint16"),
    ("encoding/binary.LittleEndian.PutUint32", "write little-endian uint32"),
    ("encoding/binary.LittleEndian.PutUint64", "write little-endian uint64"),
    ("encoding/binary.Size", "binary encoding size"),
    ("encoding/binary.PutVarint", "encode varint"),
    ("encoding/binary.PutUvarint", "encode unsigned varint"),
    ("encoding/binary.Varint", "decode varint"),
    ("encoding/binary.Uvarint", "decode unsigned varint"),
    ("encoding/binary.ReadVarint", "read varint from reader"),
    ("encoding/binary.ReadUvarint", "read uvarint from reader"),
    ("encoding/binary.AppendVarint", "append varint to slice"),
    ("encoding/binary.AppendUvarint", "append uvarint to slice"),
    ("encoding/csv.NewReader", "create CSV reader"),
    ("encoding/csv.NewWriter", "create CSV writer"),
    ("encoding/gob.NewDecoder", "create gob decoder"),
    ("encoding/gob.NewEncoder", "create gob encoder"),
    ("encoding/gob.Register", "register gob type"),
    ("encoding/gob.RegisterName", "register gob type with name"),
    ("encoding/pem.Decode", "decode PEM block"),
    ("encoding/pem.Encode", "encode PEM block"),
    ("encoding/pem.EncodeToMemory", "encode PEM to memory"),
    ("encoding/asn1.Marshal", "ASN.1 marshal"),
    ("encoding/asn1.MarshalWithParams", "ASN.1 marshal with params"),
    ("encoding/asn1.Unmarshal", "ASN.1 unmarshal"),
    ("encoding/asn1.UnmarshalWithParams", "ASN.1 unmarshal with params"),
]:
    add(fn, "go-encoding", purpose, "go_encoding")

# CSV reader/writer methods
for method, purpose in [
    ("Read", "read CSV record"),
    ("ReadAll", "read all CSV records"),
    ("FieldPos", "get field position"),
    ("InputOffset", "get input offset"),
]:
    add_method("encoding/csv", "Reader", method, "go-encoding", purpose, "go_encoding")

for method, purpose in [
    ("Write", "write CSV record"),
    ("WriteAll", "write all CSV records"),
    ("Flush", "flush CSV writer"),
    ("Error", "get writer error"),
]:
    add_method("encoding/csv", "Writer", method, "go-encoding", purpose, "go_encoding")

# Gob decoder/encoder
for method, purpose in [
    ("Decode", "decode gob value"),
    ("DecodeValue", "decode gob reflect value"),
]:
    add_method("encoding/gob", "Decoder", method, "go-encoding", purpose, "go_encoding")

for method, purpose in [
    ("Encode", "encode gob value"),
    ("EncodeValue", "encode gob reflect value"),
]:
    add_method("encoding/gob", "Encoder", method, "go-encoding", purpose, "go_encoding")

# --- crypto packages ---
# crypto/sha256, sha512, sha1, md5
for pkg, alg in [
    ("crypto/sha256", "SHA-256"), ("crypto/sha512", "SHA-512"),
    ("crypto/sha1", "SHA-1"), ("crypto/md5", "MD5"),
]:
    add_func(pkg, "New", f"go-crypto", f"create new {alg} hash", "go_crypto")
    add_func(pkg, "Sum256" if "256" in pkg else ("Sum512" if "512" in pkg else ("Sum" if "sha1" in pkg or "md5" in pkg else "Sum")),
             "go-crypto", f"{alg} hash computation", "go_crypto")

# Fix sha512 variants
for fn, purpose in [
    ("crypto/sha512.New384", "create SHA-384 hash"),
    ("crypto/sha512.New512_224", "create SHA-512/224 hash"),
    ("crypto/sha512.New512_256", "create SHA-512/256 hash"),
    ("crypto/sha512.Sum384", "SHA-384 hash sum"),
    ("crypto/sha512.Sum512", "SHA-512 hash sum"),
    ("crypto/sha512.Sum512_224", "SHA-512/224 hash sum"),
    ("crypto/sha512.Sum512_256", "SHA-512/256 hash sum"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/hmac
for fn, purpose in [
    ("crypto/hmac.Equal", "compare HMAC values (constant-time)"),
    ("crypto/hmac.New", "create HMAC hash"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/aes, des, rc4
for fn, purpose in [
    ("crypto/aes.NewCipher", "create AES cipher block"),
    ("crypto/des.NewCipher", "create DES cipher block"),
    ("crypto/des.NewTripleDESCipher", "create 3DES cipher block"),
    ("crypto/rc4.NewCipher", "create RC4 cipher"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/cipher
for fn, purpose in [
    ("crypto/cipher.NewGCM", "create GCM AEAD cipher"),
    ("crypto/cipher.NewGCMWithNonceSize", "create GCM with nonce size"),
    ("crypto/cipher.NewGCMWithTagSize", "create GCM with tag size"),
    ("crypto/cipher.NewCBCDecrypter", "create CBC decrypter"),
    ("crypto/cipher.NewCBCEncrypter", "create CBC encrypter"),
    ("crypto/cipher.NewCFBDecrypter", "create CFB decrypter"),
    ("crypto/cipher.NewCFBEncrypter", "create CFB encrypter"),
    ("crypto/cipher.NewCTR", "create CTR stream cipher"),
    ("crypto/cipher.NewOFB", "create OFB stream cipher"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/rand
for fn, purpose in [
    ("crypto/rand.Int", "generate random big.Int"),
    ("crypto/rand.Prime", "generate random prime"),
    ("crypto/rand.Read", "read cryptographic random bytes"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/rsa
for fn, purpose in [
    ("crypto/rsa.GenerateKey", "generate RSA key pair"),
    ("crypto/rsa.GenerateMultiPrimeKey", "generate multi-prime RSA key"),
    ("crypto/rsa.EncryptOAEP", "RSA OAEP encrypt"),
    ("crypto/rsa.DecryptOAEP", "RSA OAEP decrypt"),
    ("crypto/rsa.EncryptPKCS1v15", "RSA PKCS#1 v1.5 encrypt"),
    ("crypto/rsa.DecryptPKCS1v15", "RSA PKCS#1 v1.5 decrypt"),
    ("crypto/rsa.SignPKCS1v15", "RSA PKCS#1 v1.5 sign"),
    ("crypto/rsa.VerifyPKCS1v15", "RSA PKCS#1 v1.5 verify"),
    ("crypto/rsa.SignPSS", "RSA PSS sign"),
    ("crypto/rsa.VerifyPSS", "RSA PSS verify"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/ecdsa
for fn, purpose in [
    ("crypto/ecdsa.GenerateKey", "generate ECDSA key pair"),
    ("crypto/ecdsa.Sign", "ECDSA sign"),
    ("crypto/ecdsa.SignASN1", "ECDSA sign (ASN.1)"),
    ("crypto/ecdsa.Verify", "ECDSA verify"),
    ("crypto/ecdsa.VerifyASN1", "ECDSA verify (ASN.1)"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/ed25519
for fn, purpose in [
    ("crypto/ed25519.GenerateKey", "generate Ed25519 key pair"),
    ("crypto/ed25519.Sign", "Ed25519 sign"),
    ("crypto/ed25519.Verify", "Ed25519 verify"),
    ("crypto/ed25519.NewKeyFromSeed", "Ed25519 key from seed"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/elliptic
for fn, purpose in [
    ("crypto/elliptic.P224", "get P-224 curve"),
    ("crypto/elliptic.P256", "get P-256 curve"),
    ("crypto/elliptic.P384", "get P-384 curve"),
    ("crypto/elliptic.P521", "get P-521 curve"),
    ("crypto/elliptic.GenerateKey", "generate elliptic curve key"),
    ("crypto/elliptic.Marshal", "marshal elliptic curve point"),
    ("crypto/elliptic.MarshalCompressed", "marshal compressed point"),
    ("crypto/elliptic.Unmarshal", "unmarshal elliptic curve point"),
    ("crypto/elliptic.UnmarshalCompressed", "unmarshal compressed point"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# crypto/tls
for fn, purpose in [
    ("crypto/tls.Dial", "TLS dial connection"),
    ("crypto/tls.DialWithDialer", "TLS dial with dialer"),
    ("crypto/tls.Listen", "TLS listen"),
    ("crypto/tls.NewListener", "create TLS listener"),
    ("crypto/tls.Client", "create TLS client conn"),
    ("crypto/tls.Server", "create TLS server conn"),
    ("crypto/tls.LoadX509KeyPair", "load X.509 cert and key"),
    ("crypto/tls.X509KeyPair", "create X.509 key pair from PEM"),
    ("crypto/tls.CipherSuiteName", "get cipher suite name"),
    ("crypto/tls.CipherSuites", "list cipher suites"),
    ("crypto/tls.InsecureCipherSuites", "list insecure cipher suites"),
    ("crypto/tls.NewLRUClientSessionCache", "create LRU session cache"),
    ("crypto/tls.VersionName", "get TLS version name"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

for method, purpose in [
    ("Close", "close TLS connection"),
    ("CloseWrite", "close TLS write"),
    ("ConnectionState", "get TLS connection state"),
    ("Handshake", "perform TLS handshake"),
    ("HandshakeContext", "TLS handshake with context"),
    ("LocalAddr", "get local address"),
    ("NetConn", "get underlying net.Conn"),
    ("OCSPResponse", "get OCSP response"),
    ("Read", "read TLS data"),
    ("RemoteAddr", "get remote address"),
    ("SetDeadline", "set deadline"),
    ("SetReadDeadline", "set read deadline"),
    ("SetWriteDeadline", "set write deadline"),
    ("VerifyHostname", "verify server hostname"),
    ("Write", "write TLS data"),
]:
    add_method("crypto/tls", "Conn", method, "go-crypto", purpose, "go_crypto")

# crypto/x509
for fn, purpose in [
    ("crypto/x509.CreateCertificate", "create X.509 certificate"),
    ("crypto/x509.CreateCertificateRequest", "create X.509 CSR"),
    ("crypto/x509.CreateRevocationList", "create X.509 CRL"),
    ("crypto/x509.DecryptPEMBlock", "decrypt PEM block (deprecated)"),
    ("crypto/x509.EncryptPEMBlock", "encrypt PEM block (deprecated)"),
    ("crypto/x509.IsEncryptedPEMBlock", "check if PEM encrypted (deprecated)"),
    ("crypto/x509.MarshalECPrivateKey", "marshal EC private key"),
    ("crypto/x509.MarshalPKCS1PrivateKey", "marshal PKCS#1 private key"),
    ("crypto/x509.MarshalPKCS1PublicKey", "marshal PKCS#1 public key"),
    ("crypto/x509.MarshalPKCS8PrivateKey", "marshal PKCS#8 private key"),
    ("crypto/x509.MarshalPKIXPublicKey", "marshal PKIX public key"),
    ("crypto/x509.ParseCertificate", "parse X.509 certificate"),
    ("crypto/x509.ParseCertificates", "parse X.509 certificates"),
    ("crypto/x509.ParseCRL", "parse CRL (deprecated)"),
    ("crypto/x509.ParseCertificateRequest", "parse X.509 CSR"),
    ("crypto/x509.ParseDERCRL", "parse DER CRL (deprecated)"),
    ("crypto/x509.ParseECPrivateKey", "parse EC private key"),
    ("crypto/x509.ParsePKCS1PrivateKey", "parse PKCS#1 private key"),
    ("crypto/x509.ParsePKCS1PublicKey", "parse PKCS#1 public key"),
    ("crypto/x509.ParsePKCS8PrivateKey", "parse PKCS#8 private key"),
    ("crypto/x509.ParsePKIXPublicKey", "parse PKIX public key"),
    ("crypto/x509.ParseRevocationList", "parse X.509 CRL"),
    ("crypto/x509.SystemCertPool", "get system certificate pool"),
    ("crypto/x509.NewCertPool", "create new certificate pool"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

for method, purpose in [
    ("AddCert", "add certificate to pool"),
    ("AppendCertsFromPEM", "add PEM certs to pool"),
    ("Subjects", "get pool subjects (deprecated)"),
]:
    add_method("crypto/x509", "CertPool", method, "go-crypto", purpose, "go_crypto")

for method, purpose in [
    ("CheckCRLSignature", "check CRL signature"),
    ("CheckSignature", "check certificate signature"),
    ("CheckSignatureFrom", "check signature from issuer"),
    ("CreateCRL", "create CRL (deprecated)"),
    ("Equal", "compare certificates"),
    ("Verify", "verify certificate chain"),
    ("VerifyHostname", "verify hostname"),
]:
    add_method("crypto/x509", "Certificate", method, "go-crypto", purpose, "go_crypto")

# crypto/subtle
for fn, purpose in [
    ("crypto/subtle.ConstantTimeByteEq", "constant-time byte compare"),
    ("crypto/subtle.ConstantTimeCompare", "constant-time byte slice compare"),
    ("crypto/subtle.ConstantTimeCopy", "constant-time conditional copy"),
    ("crypto/subtle.ConstantTimeEq", "constant-time int32 compare"),
    ("crypto/subtle.ConstantTimeLessOrEq", "constant-time less or equal"),
    ("crypto/subtle.ConstantTimeSelect", "constant-time int select"),
    ("crypto/subtle.XORBytes", "XOR byte slices"),
]:
    add(fn, "go-crypto", purpose, "go_crypto")

# --- sync ---
sync_methods_all = {
    "Mutex": [
        ("Lock", "acquire mutex lock"),
        ("TryLock", "try acquire mutex lock"),
        ("Unlock", "release mutex lock"),
    ],
    "RWMutex": [
        ("Lock", "acquire write lock"),
        ("TryLock", "try acquire write lock"),
        ("Unlock", "release write lock"),
        ("RLock", "acquire read lock"),
        ("TryRLock", "try acquire read lock"),
        ("RUnlock", "release read lock"),
        ("RLocker", "get read locker"),
    ],
    "WaitGroup": [
        ("Add", "add delta to WaitGroup counter"),
        ("Done", "decrement WaitGroup counter"),
        ("Wait", "block until WaitGroup counter is zero"),
    ],
    "Once": [
        ("Do", "execute function exactly once"),
    ],
    "Pool": [
        ("Get", "get item from sync pool"),
        ("Put", "return item to sync pool"),
    ],
    "Map": [
        ("CompareAndDelete", "CAS delete from concurrent map"),
        ("CompareAndSwap", "CAS update concurrent map"),
        ("Delete", "delete from concurrent map"),
        ("Load", "load value from concurrent map"),
        ("LoadAndDelete", "load and delete from concurrent map"),
        ("LoadOrStore", "load or store in concurrent map"),
        ("Range", "iterate concurrent map"),
        ("Store", "store value in concurrent map"),
        ("Swap", "swap value in concurrent map"),
    ],
    "Cond": [
        ("Broadcast", "signal all waiters"),
        ("Signal", "signal one waiter"),
        ("Wait", "wait on condition variable"),
    ],
}
for receiver, methods in sync_methods_all.items():
    for method, purpose in methods:
        add_method("sync", receiver, method, "go-sync", purpose, "go_sync")

add_func("sync", "NewCond", "go-sync", "create condition variable", "go_sync")
add_func("sync", "OnceFunc", "go-sync", "create function that runs once", "go_sync")
add_func("sync", "OnceValue", "go-sync", "create value-returning once function", "go_sync")
add_func("sync", "OnceValues", "go-sync", "create two-value-returning once function", "go_sync")

# --- sync/atomic ---
for typ in ["Int32", "Int64", "Uint32", "Uint64", "Uintptr", "Bool", "Value", "Pointer"]:
    for op in ["Load", "Store", "Swap", "CompareAndSwap"]:
        if typ == "Value" and op in ("Swap", "CompareAndSwap"):
            op_name = op
        elif typ == "Pointer":
            continue  # generic, handled below
        elif typ == "Bool" and op == "CompareAndSwap":
            continue
        else:
            op_name = op
        add_func("sync/atomic", f"{op}{typ}" if typ != "Value" else f"(*Value).{op}",
                 "go-sync-atomic", f"atomic {op.lower()} {typ.lower()}", "go_sync")

for op in ["Add"]:
    for typ in ["Int32", "Int64", "Uint32", "Uint64", "Uintptr"]:
        add_func("sync/atomic", f"{op}{typ}", "go-sync-atomic", f"atomic add {typ.lower()}", "go_sync")

# Atomic type methods
for method, purpose in [
    ("Load", "atomic load value"),
    ("Store", "atomic store value"),
    ("CompareAndSwap", "atomic CAS value"),
    ("Swap", "atomic swap value"),
]:
    add_method("sync/atomic", "Value", method, "go-sync-atomic", purpose, "go_sync")

# --- context ---
for fn, purpose in [
    ("Background", "root context"),
    ("TODO", "placeholder context"),
    ("WithCancel", "create cancellable context"),
    ("WithCancelCause", "create cancellable context with cause"),
    ("WithTimeout", "create context with timeout"),
    ("WithTimeoutCause", "create context with timeout and cause"),
    ("WithDeadline", "create context with deadline"),
    ("WithDeadlineCause", "create context with deadline and cause"),
    ("WithValue", "create context with value"),
    ("WithoutCancel", "create non-cancellable child context"),
    ("AfterFunc", "call function after context done"),
    ("Cause", "get context cancellation cause"),
]:
    add_func("context", fn, "go-context", purpose, "go_context")

# --- errors ---
for fn, purpose in [
    ("New", "create new error value"),
    ("Is", "check error chain for match"),
    ("As", "extract typed error from chain"),
    ("Unwrap", "unwrap error one level"),
    ("Join", "join multiple errors"),
]:
    add_func("errors", fn, "go-errors", purpose, "go_error")

# --- path/filepath ---
for fn, purpose in [
    ("Abs", "get absolute path"),
    ("Base", "get last path element"),
    ("Clean", "clean path"),
    ("Dir", "get directory component"),
    ("EvalSymlinks", "evaluate symlinks"),
    ("Ext", "get file extension"),
    ("FromSlash", "convert slashes to OS separator"),
    ("Glob", "glob pattern matching"),
    ("HasPrefix", "check path prefix (deprecated)"),
    ("IsAbs", "check if path is absolute"),
    ("IsLocal", "check if path is local"),
    ("Join", "join path elements"),
    ("Match", "match path against pattern"),
    ("Rel", "get relative path"),
    ("Split", "split path into dir and file"),
    ("SplitList", "split PATH list"),
    ("ToSlash", "convert OS separator to slashes"),
    ("VolumeName", "get volume name (Windows)"),
    ("Walk", "walk directory tree"),
    ("WalkDir", "walk directory tree (efficient)"),
]:
    add_func("path/filepath", fn, "go-filepath", purpose, "go_os")

# --- path ---
for fn, purpose in [
    ("Base", "get last path element"),
    ("Clean", "clean path"),
    ("Dir", "get directory component"),
    ("Ext", "get file extension"),
    ("IsAbs", "check if path is absolute"),
    ("Join", "join path elements"),
    ("Match", "match path against pattern"),
    ("Split", "split path"),
]:
    add_func("path", fn, "go-path", purpose, "go_os")

# --- regexp ---
for fn, purpose in [
    ("Compile", "compile regular expression"),
    ("CompilePOSIX", "compile POSIX regex"),
    ("Match", "test if bytes match regex"),
    ("MatchReader", "test if reader matches regex"),
    ("MatchString", "test if string matches regex"),
    ("MustCompile", "compile regex (panic on error)"),
    ("MustCompilePOSIX", "compile POSIX regex (panic on error)"),
    ("QuoteMeta", "escape regex metacharacters"),
]:
    add_func("regexp", fn, "go-regexp", purpose, "go_regex")

for method, purpose in [
    ("Copy", "copy regex"),
    ("Expand", "expand template from match"),
    ("ExpandString", "expand string template from match"),
    ("Find", "find first match"),
    ("FindAll", "find all matches"),
    ("FindAllIndex", "find all match indices"),
    ("FindAllString", "find all string matches"),
    ("FindAllStringIndex", "find all string match indices"),
    ("FindAllStringSubmatch", "find all string submatches"),
    ("FindAllStringSubmatchIndex", "find all submatch indices"),
    ("FindAllSubmatch", "find all submatches"),
    ("FindAllSubmatchIndex", "find all submatch indices"),
    ("FindIndex", "find first match index"),
    ("FindReaderIndex", "find match index in reader"),
    ("FindReaderSubmatchIndex", "find submatch index in reader"),
    ("FindString", "find first string match"),
    ("FindStringIndex", "find string match index"),
    ("FindStringSubmatch", "find string submatches"),
    ("FindStringSubmatchIndex", "find string submatch index"),
    ("FindSubmatch", "find submatches"),
    ("FindSubmatchIndex", "find submatch index"),
    ("LiteralPrefix", "get literal prefix"),
    ("Longest", "set longest match mode"),
    ("Match", "test if bytes match"),
    ("MatchReader", "test if reader matches"),
    ("MatchString", "test if string matches"),
    ("NumSubexp", "get number of subexpressions"),
    ("ReplaceAll", "replace all matches"),
    ("ReplaceAllFunc", "replace matches with function"),
    ("ReplaceAllLiteral", "replace with literal"),
    ("ReplaceAllLiteralString", "replace string with literal"),
    ("ReplaceAllString", "replace all string matches"),
    ("ReplaceAllStringFunc", "replace string matches with function"),
    ("Split", "split by regex"),
    ("String", "get regex string"),
    ("SubexpIndex", "get subexpression index"),
    ("SubexpNames", "get subexpression names"),
]:
    add_method("regexp", "Regexp", method, "go-regexp", purpose, "go_regex")

# --- sort ---
for fn, purpose in [
    ("Find", "binary search with comparison function"),
    ("Float64s", "sort float64 slice"),
    ("Float64sAreSorted", "check if float64s sorted"),
    ("Ints", "sort int slice"),
    ("IntsAreSorted", "check if ints sorted"),
    ("IsSorted", "check if sorted"),
    ("Search", "binary search"),
    ("SearchFloat64s", "binary search float64s"),
    ("SearchInts", "binary search ints"),
    ("SearchStrings", "binary search strings"),
    ("Slice", "sort slice with less function"),
    ("SliceIsSorted", "check if slice is sorted"),
    ("SliceStable", "stable sort slice"),
    ("Sort", "sort interface"),
    ("Stable", "stable sort interface"),
    ("Strings", "sort string slice"),
    ("StringsAreSorted", "check if strings sorted"),
    ("Reverse", "reverse sort order"),
]:
    add_func("sort", fn, "go-sort", purpose, "go_sort")

# --- log ---
for fn, purpose in [
    ("Fatal", "log + os.Exit(1)"),
    ("Fatalf", "formatted log + exit"),
    ("Fatalln", "log line + exit"),
    ("Flags", "get log flags"),
    ("Output", "write log output"),
    ("Panic", "log + panic"),
    ("Panicf", "formatted log + panic"),
    ("Panicln", "log line + panic"),
    ("Prefix", "get log prefix"),
    ("Print", "log output"),
    ("Printf", "formatted log output"),
    ("Println", "log line output"),
    ("SetFlags", "set log flags"),
    ("SetOutput", "set log output writer"),
    ("SetPrefix", "set log prefix"),
    ("Writer", "get log writer"),
    ("Default", "get default logger"),
    ("New", "create new logger"),
]:
    add_func("log", fn, "go-log", purpose, "go_log")

for method in ["Fatal", "Fatalf", "Fatalln", "Flags", "Output", "Panic", "Panicf",
               "Panicln", "Prefix", "Print", "Printf", "Println", "SetFlags",
               "SetOutput", "SetPrefix", "Writer"]:
    add_method("log", "Logger", method, "go-log", f"logger {method.lower()}", "go_log")

# --- log/slog (Go 1.21+) ---
for fn, purpose in [
    ("Debug", "log debug message"),
    ("DebugContext", "log debug with context"),
    ("Error", "log error message"),
    ("ErrorContext", "log error with context"),
    ("Group", "create attribute group"),
    ("Info", "log info message"),
    ("InfoContext", "log info with context"),
    ("Log", "log at level"),
    ("LogAttrs", "log with attributes"),
    ("New", "create new logger"),
    ("NewJSONHandler", "create JSON log handler"),
    ("NewLogLogger", "create log.Logger from slog"),
    ("NewTextHandler", "create text log handler"),
    ("SetDefault", "set default logger"),
    ("SetLogLoggerLevel", "set log logger level"),
    ("Warn", "log warning message"),
    ("WarnContext", "log warning with context"),
    ("With", "create logger with attributes"),
    ("Default", "get default logger"),
    ("Any", "create any attribute"),
    ("Bool", "create bool attribute"),
    ("Duration", "create duration attribute"),
    ("Float64", "create float64 attribute"),
    ("Int", "create int attribute"),
    ("Int64", "create int64 attribute"),
    ("String", "create string attribute"),
    ("Time", "create time attribute"),
    ("Uint64", "create uint64 attribute"),
]:
    add_func("log/slog", fn, "go-slog", purpose, "go_log")

# --- time ---
for fn, purpose in [
    ("After", "channel send after duration"),
    ("AfterFunc", "call function after duration"),
    ("Date", "create time from components"),
    ("FixedZone", "create fixed timezone"),
    ("LoadLocation", "load timezone by name"),
    ("LoadLocationFromTZData", "load timezone from data"),
    ("NewTicker", "create periodic ticker"),
    ("NewTimer", "create one-shot timer"),
    ("Now", "get current time"),
    ("Parse", "parse time string"),
    ("ParseDuration", "parse duration string"),
    ("ParseInLocation", "parse time in location"),
    ("Since", "time elapsed since given time"),
    ("Sleep", "pause goroutine for duration"),
    ("Tick", "convenience wrapper for NewTicker"),
    ("Unix", "create time from unix timestamp"),
    ("UnixMicro", "create time from unix microseconds"),
    ("UnixMilli", "create time from unix milliseconds"),
    ("Until", "duration until given time"),
]:
    add_func("time", fn, "go-time", purpose, "go_time")

for method, purpose in [
    ("Add", "add duration to time"),
    ("AddDate", "add years/months/days"),
    ("After", "check if time is after"),
    ("AppendFormat", "append formatted time"),
    ("Before", "check if time is before"),
    ("Clock", "get hour/minute/second"),
    ("Compare", "compare times"),
    ("Date", "get year/month/day"),
    ("Day", "get day"),
    ("Equal", "check if times are equal"),
    ("Format", "format time as string"),
    ("GoString", "Go syntax representation"),
    ("GobDecode", "gob decode time"),
    ("GobEncode", "gob encode time"),
    ("Hour", "get hour"),
    ("ISOWeek", "get ISO week number"),
    ("In", "convert to timezone"),
    ("IsDST", "check daylight saving time"),
    ("IsZero", "check if zero time"),
    ("Local", "convert to local time"),
    ("Location", "get timezone"),
    ("MarshalBinary", "binary marshal time"),
    ("MarshalJSON", "JSON marshal time"),
    ("MarshalText", "text marshal time"),
    ("Minute", "get minute"),
    ("Month", "get month"),
    ("Nanosecond", "get nanosecond"),
    ("Round", "round time"),
    ("Second", "get second"),
    ("String", "format time as string"),
    ("Sub", "subtract times"),
    ("Truncate", "truncate time"),
    ("UTC", "convert to UTC"),
    ("Unix", "get unix timestamp"),
    ("UnixMicro", "get unix microseconds"),
    ("UnixMilli", "get unix milliseconds"),
    ("UnixNano", "get unix nanoseconds"),
    ("UnmarshalBinary", "binary unmarshal time"),
    ("UnmarshalJSON", "JSON unmarshal time"),
    ("UnmarshalText", "text unmarshal time"),
    ("Weekday", "get weekday"),
    ("Year", "get year"),
    ("YearDay", "get day of year"),
    ("Zone", "get timezone name and offset"),
    ("ZoneBounds", "get timezone transition bounds"),
]:
    add_method("time", "Time", method, "go-time", purpose, "go_time")

for method, purpose in [
    ("Hours", "get duration in hours"),
    ("Microseconds", "get duration in microseconds"),
    ("Milliseconds", "get duration in milliseconds"),
    ("Minutes", "get duration in minutes"),
    ("Nanoseconds", "get duration in nanoseconds"),
    ("Round", "round duration"),
    ("Seconds", "get duration in seconds"),
    ("String", "format duration as string"),
    ("Truncate", "truncate duration"),
    ("Abs", "absolute duration value"),
]:
    add_method("time", "Duration", method, "go-time", purpose, "go_time")

for method, purpose in [
    ("Reset", "reset timer"),
    ("Stop", "stop timer"),
]:
    add_method("time", "Timer", method, "go-time", purpose, "go_time")
    add_method("time", "Ticker", method, "go-time", purpose, "go_time")

# --- os/exec ---
for fn, purpose in [
    ("Command", "create command for execution"),
    ("CommandContext", "create command with context"),
    ("LookPath", "find executable in PATH"),
]:
    add_func("os/exec", fn, "go-exec", purpose, "go_exec")

for method, purpose in [
    ("CombinedOutput", "run and capture stdout+stderr"),
    ("Environ", "get command environment"),
    ("Output", "run command and capture stdout"),
    ("Run", "run command and wait"),
    ("Start", "start command asynchronously"),
    ("StderrPipe", "create stderr pipe"),
    ("StdinPipe", "create stdin pipe"),
    ("StdoutPipe", "create stdout pipe"),
    ("String", "get command string"),
    ("Wait", "wait for started command"),
]:
    add_method("os/exec", "Cmd", method, "go-exec", purpose, "go_exec")

# --- os/signal ---
for fn, purpose in [
    ("Ignore", "ignore signals"),
    ("Ignored", "check if signal ignored"),
    ("Notify", "relay signals to channel"),
    ("NotifyContext", "signal notification with context"),
    ("Reset", "reset signal handlers"),
    ("Stop", "stop relaying signals"),
]:
    add_func("os/signal", fn, "go-os", purpose, "go_os")

# --- syscall (frequently seen in Go binaries) ---
syscalls = [
    "Accept", "Accept4", "Access", "Acct", "Bind", "Chdir", "Chmod", "Chown",
    "Chroot", "Close", "Connect", "Dup", "Dup2", "Dup3", "Environ", "Exec",
    "Exit", "Fchdir", "Fchmod", "Fchown", "Fcntl", "Flock", "Fork",
    "Fstat", "Fstatfs", "Fsync", "Ftruncate", "Getcwd", "Getdents",
    "Getegid", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpid",
    "Getppid", "Getpriority", "Getrlimit", "Getrusage", "Getsockname",
    "Getsockopt", "Gettimeofday", "Getuid", "Getwd", "Ioperm", "Iopl",
    "Kill", "Klogctl", "Lchown", "Link", "Listen", "Lstat", "Madvise",
    "Mkdir", "Mkdirat", "Mkfifo", "Mknod", "Mlock", "Mlockall", "Mmap",
    "Mount", "Mprotect", "Munlock", "Munlockall", "Munmap", "Nanosleep",
    "Open", "Openat", "Pause", "Pipe", "Pipe2", "PivotRoot", "Pread",
    "Pwrite", "RawSyscall", "RawSyscall6", "Read", "ReadDirent",
    "Readlink", "Reboot", "Recvfrom", "Recvmsg", "Removexattr", "Rename",
    "Renameat", "Rmdir", "Seek", "Select", "Sendfile", "Sendmsg",
    "Sendto", "SetLsfPromisc", "Setdomainname", "Setegid", "Setenv",
    "Seteuid", "Setfsgid", "Setfsuid", "Setgid", "Setgroups",
    "Sethostname", "Setpgid", "Setpriority", "Setregid", "Setresgid",
    "Setresuid", "Setreuid", "Setrlimit", "Setsid", "Setsockopt",
    "Settimeofday", "Setuid", "Shutdown", "Socket", "Socketpair",
    "Splice", "Stat", "Statfs", "Symlink", "Sync", "SyncFileRange",
    "Syscall", "Syscall6", "Sysinfo", "Tee", "Tgkill", "Times",
    "Truncate", "Umask", "Uname", "Unlink", "Unlinkat", "Unmount",
    "Unshare", "Ustat", "Utime", "Utimes", "Wait4", "Write",
]
for sc in syscalls:
    add_func("syscall", sc, "go-syscall", f"syscall {sc}", "go_syscall")

# --- math ---
math_funcs = [
    ("Abs", "absolute value"), ("Acos", "arccosine"), ("Acosh", "inverse hyperbolic cosine"),
    ("Asin", "arcsine"), ("Asinh", "inverse hyperbolic sine"), ("Atan", "arctangent"),
    ("Atan2", "arctangent of y/x"), ("Atanh", "inverse hyperbolic tangent"),
    ("Cbrt", "cube root"), ("Ceil", "ceiling"), ("Copysign", "copy sign"),
    ("Cos", "cosine"), ("Cosh", "hyperbolic cosine"), ("Dim", "max(x-y, 0)"),
    ("Erf", "error function"), ("Erfc", "complementary error function"),
    ("Erfcinv", "inverse complementary error function"), ("Erfinv", "inverse error function"),
    ("Exp", "e^x"), ("Exp2", "2^x"), ("Expm1", "e^x - 1"),
    ("FMA", "fused multiply-add"), ("Float32bits", "float32 to bits"),
    ("Float32frombits", "bits to float32"), ("Float64bits", "float64 to bits"),
    ("Float64frombits", "bits to float64"), ("Floor", "floor"),
    ("Frexp", "split into fraction and exponent"), ("Gamma", "gamma function"),
    ("Hypot", "hypotenuse (sqrt(x^2+y^2))"), ("Ilogb", "integer log base 2"),
    ("Inf", "positive infinity"), ("IsInf", "check if infinity"),
    ("IsNaN", "check if NaN"), ("J0", "Bessel J0"), ("J1", "Bessel J1"),
    ("Jn", "Bessel Jn"), ("Ldexp", "fraction * 2^exp"),
    ("Lgamma", "log-gamma function"), ("Log", "natural log"),
    ("Log10", "log base 10"), ("Log1p", "log(1+x)"), ("Log2", "log base 2"),
    ("Logb", "binary exponent"), ("Max", "maximum"), ("Min", "minimum"),
    ("Mod", "modulo"), ("Modf", "split into integer and fraction"),
    ("NaN", "not-a-number"), ("Nextafter", "next representable float"),
    ("Nextafter32", "next representable float32"), ("Pow", "x^y"),
    ("Pow10", "10^n"), ("Remainder", "IEEE remainder"),
    ("Round", "round to nearest integer"), ("RoundToEven", "round to even"),
    ("Signbit", "check sign bit"), ("Sin", "sine"), ("Sincos", "sine and cosine"),
    ("Sinh", "hyperbolic sine"), ("Sqrt", "square root"), ("Tan", "tangent"),
    ("Tanh", "hyperbolic tangent"), ("Trunc", "truncate to integer"),
    ("Y0", "Bessel Y0"), ("Y1", "Bessel Y1"), ("Yn", "Bessel Yn"),
]
for fn, purpose in math_funcs:
    add_func("math", fn, "go-math", purpose, "go_math")

# --- math/big ---
for method, purpose in [
    ("Abs", "absolute value"), ("Add", "addition"), ("And", "bitwise AND"),
    ("AndNot", "bitwise AND NOT"), ("Append", "append to buffer"),
    ("Binomial", "binomial coefficient"), ("Bit", "get bit"),
    ("BitLen", "bit length"), ("Bits", "get word slice"), ("Bytes", "get bytes"),
    ("Cmp", "compare"), ("CmpAbs", "compare absolute values"),
    ("Div", "division"), ("DivMod", "division and modulo"),
    ("Exp", "exponentiation"), ("FillBytes", "fill byte slice"),
    ("Format", "format as string"), ("GCD", "greatest common divisor"),
    ("GobDecode", "gob decode"), ("GobEncode", "gob encode"),
    ("Int64", "convert to int64"), ("IsInt64", "check if fits in int64"),
    ("IsUint64", "check if fits in uint64"), ("Lsh", "left shift"),
    ("MarshalJSON", "JSON marshal"), ("MarshalText", "text marshal"),
    ("Mod", "modulo"), ("ModInverse", "modular inverse"),
    ("ModSqrt", "modular square root"), ("Mul", "multiplication"),
    ("MulRange", "product of range"), ("Neg", "negate"),
    ("Not", "bitwise NOT"), ("Or", "bitwise OR"),
    ("ProbablyPrime", "probabilistic primality test"),
    ("Quo", "quotient"), ("QuoRem", "quotient and remainder"),
    ("Rand", "random number"), ("Rem", "remainder"), ("Rsh", "right shift"),
    ("Scan", "scan from reader"), ("Set", "set value"), ("SetBit", "set bit"),
    ("SetBits", "set from word slice"), ("SetBytes", "set from bytes"),
    ("SetInt64", "set from int64"), ("SetString", "set from string"),
    ("SetUint64", "set from uint64"), ("Sign", "get sign"),
    ("Sqrt", "integer square root"), ("String", "convert to string"),
    ("Sub", "subtraction"), ("Text", "format as text"), ("TrailingZeroBits", "trailing zeros"),
    ("Uint64", "convert to uint64"), ("UnmarshalJSON", "JSON unmarshal"),
    ("UnmarshalText", "text unmarshal"), ("Xor", "bitwise XOR"),
]:
    add_method("math/big", "Int", method, "go-math-big", purpose, "go_math")

for method, purpose in [
    ("Abs", "absolute value"), ("Acc", "accuracy"),
    ("Add", "addition"), ("Append", "append to buffer"),
    ("Cmp", "compare"), ("Copy", "copy value"),
    ("Float32", "convert to float32"), ("Float64", "convert to float64"),
    ("Format", "format as string"), ("GobDecode", "gob decode"),
    ("GobEncode", "gob encode"), ("Int", "convert to big.Int"),
    ("Int64", "convert to int64"), ("IsInf", "check infinity"),
    ("IsInt", "check if integer"), ("MantExp", "mantissa and exponent"),
    ("MarshalText", "text marshal"), ("MinPrec", "minimum precision"),
    ("Mode", "rounding mode"), ("Mul", "multiplication"),
    ("Neg", "negate"), ("Parse", "parse string"),
    ("Prec", "precision"), ("Quo", "quotient"),
    ("Rat", "convert to Rat"), ("Scan", "scan from reader"),
    ("Set", "set value"), ("SetFloat64", "set from float64"),
    ("SetInf", "set to infinity"), ("SetInt", "set from Int"),
    ("SetInt64", "set from int64"), ("SetMantExp", "set mantissa and exponent"),
    ("SetMode", "set rounding mode"), ("SetPrec", "set precision"),
    ("SetRat", "set from Rat"), ("SetString", "set from string"),
    ("SetUint64", "set from uint64"), ("Sign", "get sign"),
    ("Signbit", "check sign bit"), ("Sqrt", "square root"),
    ("String", "convert to string"), ("Sub", "subtraction"),
    ("Text", "format as text"), ("Uint64", "convert to uint64"),
    ("UnmarshalText", "text unmarshal"),
]:
    add_method("math/big", "Float", method, "go-math-big", purpose, "go_math")

add_func("math/big", "NewInt", "go-math-big", "create new big.Int", "go_math")
add_func("math/big", "NewFloat", "go-math-big", "create new big.Float", "go_math")
add_func("math/big", "NewRat", "go-math-big", "create new big.Rat", "go_math")

# --- math/rand ---
for fn, purpose in [
    ("ExpFloat64", "exponential distribution float64"),
    ("Float32", "random float32 [0.0, 1.0)"),
    ("Float64", "random float64 [0.0, 1.0)"),
    ("Int", "random non-negative int"),
    ("Int31", "random non-negative int31"),
    ("Int31n", "random int31 [0, n)"),
    ("Int63", "random non-negative int63"),
    ("Int63n", "random int63 [0, n)"),
    ("Intn", "random int [0, n)"),
    ("New", "create random source"),
    ("NewSource", "create random source from seed"),
    ("NormFloat64", "normal distribution float64"),
    ("Perm", "random permutation"),
    ("Read", "random bytes (deprecated)"),
    ("Seed", "seed random (deprecated)"),
    ("Shuffle", "shuffle slice"),
    ("Uint32", "random uint32"),
    ("Uint64", "random uint64"),
]:
    add_func("math/rand", fn, "go-math-rand", purpose, "go_math")

# math/rand/v2
for fn, purpose in [
    ("Float32", "random float32"),
    ("Float64", "random float64"),
    ("Int", "random int"),
    ("Int32", "random int32"),
    ("Int32N", "random int32 [0, n)"),
    ("Int64", "random int64"),
    ("Int64N", "random int64 [0, n)"),
    ("IntN", "random int [0, n)"),
    ("N", "random value [0, n)"),
    ("New", "create new random generator"),
    ("NewChaCha8", "create ChaCha8 source"),
    ("NewPCG", "create PCG source"),
    ("NormFloat64", "normal distribution"),
    ("Perm", "random permutation"),
    ("Shuffle", "shuffle slice"),
    ("Uint32", "random uint32"),
    ("Uint64", "random uint64"),
    ("UintN", "random uint [0, n)"),
    ("Uint32N", "random uint32 [0, n)"),
    ("Uint64N", "random uint64 [0, n)"),
]:
    add_func("math/rand/v2", fn, "go-math-rand", purpose, "go_math")

# --- math/bits ---
for fn, purpose in [
    ("Add", "add with carry"), ("Add32", "add32 with carry"), ("Add64", "add64 with carry"),
    ("Div", "divide with remainder"), ("Div32", "div32 with remainder"), ("Div64", "div64 with remainder"),
    ("LeadingZeros", "count leading zeros"), ("LeadingZeros8", "leading zeros uint8"),
    ("LeadingZeros16", "leading zeros uint16"), ("LeadingZeros32", "leading zeros uint32"),
    ("LeadingZeros64", "leading zeros uint64"), ("Len", "bit length"),
    ("Len8", "bit length uint8"), ("Len16", "bit length uint16"),
    ("Len32", "bit length uint32"), ("Len64", "bit length uint64"),
    ("Mul", "multiply returning high/low"), ("Mul32", "mul32 high/low"), ("Mul64", "mul64 high/low"),
    ("OnesCount", "count set bits"), ("OnesCount8", "popcount uint8"),
    ("OnesCount16", "popcount uint16"), ("OnesCount32", "popcount uint32"),
    ("OnesCount64", "popcount uint64"),
    ("Rem", "remainder"), ("Rem32", "rem32"), ("Rem64", "rem64"),
    ("Reverse", "reverse bits"), ("Reverse8", "reverse uint8"), ("Reverse16", "reverse uint16"),
    ("Reverse32", "reverse uint32"), ("Reverse64", "reverse uint64"),
    ("ReverseBytes", "reverse bytes"), ("ReverseBytes16", "reverse bytes uint16"),
    ("ReverseBytes32", "reverse bytes uint32"), ("ReverseBytes64", "reverse bytes uint64"),
    ("RotateLeft", "rotate left"), ("RotateLeft8", "rotate left uint8"),
    ("RotateLeft16", "rotate left uint16"), ("RotateLeft32", "rotate left uint32"),
    ("RotateLeft64", "rotate left uint64"),
    ("Sub", "subtract with borrow"), ("Sub32", "sub32 with borrow"), ("Sub64", "sub64 with borrow"),
    ("TrailingZeros", "count trailing zeros"), ("TrailingZeros8", "trailing zeros uint8"),
    ("TrailingZeros16", "trailing zeros uint16"), ("TrailingZeros32", "trailing zeros uint32"),
    ("TrailingZeros64", "trailing zeros uint64"),
]:
    add_func("math/bits", fn, "go-math-bits", purpose, "go_math")

# --- reflect ---
for fn, purpose in [
    ("Append", "reflect append to slice"),
    ("AppendSlice", "reflect append slice to slice"),
    ("ArrayOf", "create array type"),
    ("ChanOf", "create channel type"),
    ("Copy", "reflect copy slice"),
    ("DeepEqual", "deep comparison"),
    ("FuncOf", "create function type"),
    ("Indirect", "dereference pointer"),
    ("MakeChan", "make channel"),
    ("MakeFunc", "create function from closure"),
    ("MakeMap", "make map"),
    ("MakeMapWithSize", "make map with size hint"),
    ("MakeSlice", "make slice"),
    ("MapOf", "create map type"),
    ("New", "allocate new value"),
    ("NewAt", "create value at address"),
    ("PtrTo", "create pointer type (deprecated)"),
    ("PointerTo", "create pointer type"),
    ("Select", "reflect select statement"),
    ("SliceOf", "create slice type"),
    ("StructOf", "create struct type"),
    ("Swapper", "create swap function for slice"),
    ("TypeOf", "get type of value"),
    ("ValueOf", "get reflect value"),
    ("VisibleFields", "get visible struct fields"),
    ("Zero", "zero value"),
]:
    add_func("reflect", fn, "go-reflect", purpose, "go_reflect")

for method, purpose in [
    ("Addr", "get address"), ("Bool", "get bool"), ("Bytes", "get bytes"),
    ("Call", "call function"), ("CanAddr", "check addressable"),
    ("CanComplex", "check complex"), ("CanConvert", "check convertible"),
    ("CanFloat", "check float"), ("CanInt", "check int"),
    ("CanInterface", "check interface"), ("CanSet", "check settable"),
    ("CanUint", "check uint"), ("Cap", "get capacity"),
    ("Close", "close channel"), ("Comparable", "check comparable"),
    ("Complex", "get complex"), ("Convert", "convert type"),
    ("Elem", "dereference pointer/interface"), ("Equal", "compare values"),
    ("Field", "get struct field"), ("FieldByIndex", "get nested field"),
    ("FieldByName", "get field by name"), ("FieldByNameFunc", "get field by function"),
    ("Float", "get float"), ("Grow", "grow slice"),
    ("Index", "get element by index"), ("Int", "get int"),
    ("Interface", "get interface value"), ("IsNil", "check if nil"),
    ("IsValid", "check if valid"), ("IsZero", "check if zero"),
    ("Kind", "get kind"), ("Len", "get length"),
    ("MapIndex", "get map value"), ("MapKeys", "get map keys"),
    ("MapRange", "get map iterator"), ("Method", "get method"),
    ("MethodByName", "get method by name"), ("NumField", "number of fields"),
    ("NumMethod", "number of methods"), ("OverflowComplex", "check overflow"),
    ("OverflowFloat", "check float overflow"), ("OverflowInt", "check int overflow"),
    ("OverflowUint", "check uint overflow"), ("Pointer", "get pointer"),
    ("Recv", "receive from channel"), ("Send", "send on channel"),
    ("Set", "set value"), ("SetBool", "set bool"), ("SetBytes", "set bytes"),
    ("SetCap", "set cap"), ("SetComplex", "set complex"),
    ("SetFloat", "set float"), ("SetInt", "set int"),
    ("SetIterKey", "set from iterator key"), ("SetIterValue", "set from iterator value"),
    ("SetLen", "set length"), ("SetMapIndex", "set map entry"),
    ("SetPointer", "set pointer"), ("SetString", "set string"),
    ("SetUint", "set uint"), ("SetZero", "set to zero"),
    ("Slice", "slice value"), ("Slice3", "3-index slice"),
    ("String", "get string"), ("TrySend", "try send on channel"),
    ("TryRecv", "try receive from channel"), ("Type", "get type"),
    ("Uint", "get uint"), ("UnsafeAddr", "get unsafe address"),
    ("UnsafePointer", "get unsafe pointer"),
]:
    add_method("reflect", "Value", method, "go-reflect", purpose, "go_reflect")

for method, purpose in [
    ("Align", "field alignment"), ("AssignableTo", "check assignable"),
    ("Bits", "type bit size"), ("ChanDir", "channel direction"),
    ("Comparable", "check comparable"), ("ConvertibleTo", "check convertible"),
    ("Elem", "element type"), ("Field", "get struct field"),
    ("FieldAlign", "struct field alignment"), ("FieldByIndex", "get nested field"),
    ("FieldByName", "get field by name"), ("FieldByNameFunc", "get field by function"),
    ("Implements", "check implements interface"), ("In", "input parameter type"),
    ("IsVariadic", "check variadic"), ("Key", "map key type"),
    ("Kind", "get kind"), ("Len", "array length"),
    ("Method", "get method"), ("MethodByName", "get method by name"),
    ("Name", "type name"), ("NumField", "number of fields"),
    ("NumIn", "number of input parameters"), ("NumMethod", "number of methods"),
    ("NumOut", "number of output parameters"), ("Out", "output parameter type"),
    ("PkgPath", "package path"), ("Size", "type size"),
    ("String", "type string"), ("Implements", "check interface implementation"),
]:
    add_method("reflect", "Type", method, "go-reflect", purpose, "go_reflect")

# --- unsafe ---
for fn, purpose in [
    ("unsafe.Sizeof", "size of type"),
    ("unsafe.Alignof", "alignment of type"),
    ("unsafe.Offsetof", "offset of struct field"),
    ("unsafe.Add", "pointer arithmetic add"),
    ("unsafe.Slice", "create slice from pointer"),
    ("unsafe.SliceData", "get slice data pointer"),
    ("unsafe.String", "create string from pointer"),
    ("unsafe.StringData", "get string data pointer"),
]:
    add(fn, "go-unsafe", purpose, "go_runtime")

# --- os/user ---
for fn, purpose in [
    ("Current", "get current user"),
    ("Lookup", "lookup user by name"),
    ("LookupId", "lookup user by ID"),
    ("LookupGroup", "lookup group by name"),
    ("LookupGroupId", "lookup group by ID"),
]:
    add_func("os/user", fn, "go-os", purpose, "go_os")

# --- flag ---
for fn, purpose in [
    ("Arg", "get non-flag argument"),
    ("Args", "get non-flag arguments"),
    ("Bool", "define bool flag"),
    ("BoolFunc", "define bool flag with function"),
    ("BoolVar", "define bool flag variable"),
    ("CommandLine", "get default flag set"),
    ("Duration", "define duration flag"),
    ("DurationVar", "define duration flag variable"),
    ("Float64", "define float64 flag"),
    ("Float64Var", "define float64 flag variable"),
    ("Func", "define flag with function"),
    ("Int", "define int flag"),
    ("Int64", "define int64 flag"),
    ("Int64Var", "define int64 flag variable"),
    ("IntVar", "define int flag variable"),
    ("NArg", "number of non-flag arguments"),
    ("NFlag", "number of flags set"),
    ("NewFlagSet", "create new flag set"),
    ("Parse", "parse command-line flags"),
    ("Parsed", "check if flags parsed"),
    ("PrintDefaults", "print flag defaults"),
    ("Set", "set flag value"),
    ("String", "define string flag"),
    ("StringVar", "define string flag variable"),
    ("TextVar", "define text flag variable"),
    ("Uint", "define uint flag"),
    ("Uint64", "define uint64 flag"),
    ("Uint64Var", "define uint64 flag variable"),
    ("UintVar", "define uint flag variable"),
    ("UnquoteUsage", "unquote flag usage"),
    ("Var", "define flag with Value interface"),
    ("Visit", "visit set flags"),
    ("VisitAll", "visit all flags"),
    ("Lookup", "lookup flag by name"),
]:
    add_func("flag", fn, "go-flag", purpose, "go_os")

# --- testing ---
for method, purpose in [
    ("Cleanup", "register cleanup function"),
    ("Error", "log error"),
    ("Errorf", "log formatted error"),
    ("Fail", "mark test failed"),
    ("FailNow", "mark failed and stop"),
    ("Failed", "check if failed"),
    ("Fatal", "log and fail"),
    ("Fatalf", "formatted fatal"),
    ("Helper", "mark test helper"),
    ("Log", "log message"),
    ("Logf", "log formatted"),
    ("Name", "get test name"),
    ("Parallel", "run test in parallel"),
    ("Run", "run subtest"),
    ("Setenv", "set env for test"),
    ("Skip", "skip test"),
    ("SkipNow", "skip test now"),
    ("Skipf", "skip with format"),
    ("Skipped", "check if skipped"),
    ("TempDir", "get test temp dir"),
]:
    add_method("testing", "T", method, "go-testing", purpose, "go_testing")

for method, purpose in [
    ("Cleanup", "register cleanup"),
    ("Error", "log error"),
    ("Errorf", "formatted error"),
    ("Fail", "mark failed"),
    ("FailNow", "fail and stop"),
    ("Failed", "check failed"),
    ("Fatal", "log and fail"),
    ("Fatalf", "formatted fatal"),
    ("Helper", "mark helper"),
    ("Log", "log message"),
    ("Logf", "formatted log"),
    ("Name", "get benchmark name"),
    ("ReportAllocs", "report allocations"),
    ("ReportMetric", "report custom metric"),
    ("ResetTimer", "reset timer"),
    ("Run", "run sub-benchmark"),
    ("RunParallel", "run parallel benchmark"),
    ("SetBytes", "set bytes processed"),
    ("SetParallelism", "set parallelism"),
    ("Skip", "skip benchmark"),
    ("SkipNow", "skip now"),
    ("Skipf", "skip formatted"),
    ("Skipped", "check skipped"),
    ("StartTimer", "start timer"),
    ("StopTimer", "stop timer"),
    ("TempDir", "get temp dir"),
]:
    add_method("testing", "B", method, "go-testing", purpose, "go_testing")

# --- compress/gzip, compress/flate, compress/zlib ---
for pkg, name in [("compress/gzip", "gzip"), ("compress/zlib", "zlib"), ("compress/flate", "flate")]:
    add_func(pkg, "NewReader", f"go-{name}", f"create {name} reader", "go_compress")
    add_func(pkg, "NewWriter", f"go-{name}", f"create {name} writer", "go_compress")
    if pkg != "compress/flate":
        add_func(pkg, "NewWriterLevel", f"go-{name}", f"create {name} writer with level", "go_compress")

for method, purpose in [
    ("Read", "read decompressed data"),
    ("Close", "close reader"),
    ("Multistream", "enable multistream"),
    ("Reset", "reset reader"),
]:
    add_method("compress/gzip", "Reader", method, "go-gzip", purpose, "go_compress")

for method, purpose in [
    ("Write", "write compressed data"),
    ("Close", "close writer"),
    ("Flush", "flush writer"),
    ("Reset", "reset writer"),
]:
    add_method("compress/gzip", "Writer", method, "go-gzip", purpose, "go_compress")

# compress/bzip2, compress/lzw
add_func("compress/bzip2", "NewReader", "go-bzip2", "create bzip2 reader", "go_compress")
add_func("compress/lzw", "NewReader", "go-lzw", "create LZW reader", "go_compress")
add_func("compress/lzw", "NewWriter", "go-lzw", "create LZW writer", "go_compress")

# --- archive/tar, archive/zip ---
for fn, purpose in [
    ("archive/tar.NewReader", "create tar reader"),
    ("archive/tar.NewWriter", "create tar writer"),
    ("archive/tar.FileInfoHeader", "create tar header from file info"),
    ("archive/zip.NewReader", "create zip reader"),
    ("archive/zip.NewWriter", "create zip writer"),
    ("archive/zip.OpenReader", "open zip file for reading"),
    ("archive/zip.FileInfoHeader", "create zip header from file info"),
]:
    add(fn, "go-archive", purpose, "go_compress")

# --- database/sql ---
for fn, purpose in [
    ("Open", "open database connection"),
    ("OpenDB", "open database from connector"),
    ("Drivers", "list registered drivers"),
    ("Register", "register database driver"),
    ("Named", "create named parameter"),
]:
    add_func("database/sql", fn, "go-sql", purpose, "go_database")

for method, purpose in [
    ("Begin", "start transaction"),
    ("BeginTx", "start transaction with context"),
    ("Close", "close database"),
    ("Conn", "get single connection"),
    ("Driver", "get database driver"),
    ("Exec", "execute statement"),
    ("ExecContext", "execute with context"),
    ("Ping", "ping database"),
    ("PingContext", "ping with context"),
    ("Prepare", "prepare statement"),
    ("PrepareContext", "prepare with context"),
    ("Query", "execute query"),
    ("QueryContext", "query with context"),
    ("QueryRow", "query single row"),
    ("QueryRowContext", "query row with context"),
    ("SetConnMaxIdleTime", "set max idle time"),
    ("SetConnMaxLifetime", "set max lifetime"),
    ("SetMaxIdleConns", "set max idle connections"),
    ("SetMaxOpenConns", "set max open connections"),
    ("Stats", "get database stats"),
]:
    add_method("database/sql", "DB", method, "go-sql", purpose, "go_database")

for method, purpose in [
    ("Close", "close rows"),
    ("ColumnTypes", "get column types"),
    ("Columns", "get column names"),
    ("Err", "get error"),
    ("Next", "advance to next row"),
    ("NextResultSet", "advance to next result set"),
    ("Scan", "scan current row"),
]:
    add_method("database/sql", "Rows", method, "go-sql", purpose, "go_database")

for method, purpose in [
    ("Scan", "scan single row"),
    ("Err", "get error"),
]:
    add_method("database/sql", "Row", method, "go-sql", purpose, "go_database")

for method, purpose in [
    ("Commit", "commit transaction"),
    ("Exec", "execute in transaction"),
    ("ExecContext", "execute with context"),
    ("Prepare", "prepare in transaction"),
    ("PrepareContext", "prepare with context"),
    ("Query", "query in transaction"),
    ("QueryContext", "query with context"),
    ("QueryRow", "query row in transaction"),
    ("QueryRowContext", "query row with context"),
    ("Rollback", "rollback transaction"),
    ("Stmt", "prepare statement for transaction"),
    ("StmtContext", "prepare with context"),
]:
    add_method("database/sql", "Tx", method, "go-sql", purpose, "go_database")

for method, purpose in [
    ("Close", "close statement"),
    ("Exec", "execute prepared"),
    ("ExecContext", "execute with context"),
    ("Query", "query prepared"),
    ("QueryContext", "query with context"),
    ("QueryRow", "query row prepared"),
    ("QueryRowContext", "query row with context"),
]:
    add_method("database/sql", "Stmt", method, "go-sql", purpose, "go_database")

# --- html/template, text/template ---
for pkg in ["html/template", "text/template"]:
    lib = "go-html-template" if "html" in pkg else "go-text-template"
    for fn, purpose in [
        ("HTMLEscaper", "HTML escape values") if "html" in pkg else ("HTMLEscapeString", "HTML escape string"),
        ("JSEscaper", "JS escape values") if "html" in pkg else ("JSEscapeString", "JS escape string"),
        ("Must", "wrap template with error check"),
        ("New", "create new template"),
        ("ParseFS", "parse template from FS"),
        ("ParseFiles", "parse template files"),
        ("ParseGlob", "parse templates by glob"),
    ]:
        add_func(pkg, fn, lib, purpose, "go_template")

    for method, purpose in [
        ("Clone", "clone template"),
        ("Delims", "set delimiters"),
        ("Execute", "execute template"),
        ("ExecuteTemplate", "execute named template"),
        ("Funcs", "add template functions"),
        ("Lookup", "lookup template by name"),
        ("Name", "get template name"),
        ("New", "create associated template"),
        ("Option", "set template option"),
        ("Parse", "parse template string"),
        ("ParseFS", "parse from FS"),
        ("ParseFiles", "parse files"),
        ("ParseGlob", "parse by glob"),
        ("Templates", "get associated templates"),
    ]:
        add_method(pkg, "Template", method, lib, purpose, "go_template")

# --- html ---
for fn, purpose in [
    ("EscapeString", "HTML escape string"),
    ("UnescapeString", "HTML unescape string"),
]:
    add_func("html", fn, "go-html", purpose, "go_template")

# --- net/smtp, net/mail ---
for fn, purpose in [
    ("net/smtp.Dial", "connect to SMTP server"),
    ("net/smtp.NewClient", "create SMTP client"),
    ("net/smtp.PlainAuth", "create plain auth"),
    ("net/smtp.CRAMMD5Auth", "create CRAM-MD5 auth"),
    ("net/smtp.SendMail", "send email"),
    ("net/mail.ParseAddress", "parse email address"),
    ("net/mail.ParseAddressList", "parse email address list"),
    ("net/mail.ReadMessage", "read email message"),
    ("net/mail.ParseDate", "parse email date"),
]:
    add(fn, "go-net", purpose, "go_net")

# --- image and image/... ---
for fn, purpose in [
    ("image.NewRGBA", "create RGBA image"),
    ("image.NewNRGBA", "create NRGBA image"),
    ("image.NewGray", "create grayscale image"),
    ("image.NewAlpha", "create alpha image"),
    ("image.NewPaletted", "create paletted image"),
    ("image.NewUniform", "create uniform color image"),
    ("image.Pt", "create point"),
    ("image.Rect", "create rectangle"),
    ("image.Decode", "decode image from reader"),
    ("image.DecodeConfig", "decode image config"),
    ("image.RegisterFormat", "register image format"),
    ("image/png.Decode", "decode PNG image"),
    ("image/png.Encode", "encode PNG image"),
    ("image/jpeg.Decode", "decode JPEG image"),
    ("image/jpeg.Encode", "encode JPEG image"),
    ("image/gif.Decode", "decode GIF image"),
    ("image/gif.DecodeAll", "decode all GIF frames"),
    ("image/gif.Encode", "encode GIF image"),
    ("image/gif.EncodeAll", "encode all GIF frames"),
    ("image/draw.Draw", "draw image"),
    ("image/draw.DrawMask", "draw with mask"),
    ("image/color.RGBA", "create RGBA color"),
    ("image/color.NRGBA", "create NRGBA color"),
    ("image/color.Gray", "create gray color"),
    ("image/color.ModelFunc", "create color model"),
]:
    add(fn, "go-image", purpose, "go_image")

# --- embed ---
for method, purpose in [
    ("Open", "open embedded file"),
    ("ReadDir", "read embedded directory"),
    ("ReadFile", "read embedded file"),
]:
    add_method("embed", "FS", method, "go-embed", purpose, "go_io")

# --- io/fs ---
for fn, purpose in [
    ("Glob", "glob pattern in filesystem"),
    ("ReadDir", "read directory"),
    ("ReadFile", "read file"),
    ("Stat", "get file info"),
    ("Sub", "subtree filesystem"),
    ("ValidPath", "check valid path"),
    ("WalkDir", "walk directory tree"),
]:
    add_func("io/fs", fn, "go-fs", purpose, "go_os")

# --- slices (Go 1.21+) ---
for fn, purpose in [
    ("BinarySearch", "binary search in sorted slice"),
    ("BinarySearchFunc", "binary search with comparison"),
    ("Clip", "clip slice to length"),
    ("Clone", "clone slice"),
    ("Compact", "compact consecutive equal elements"),
    ("CompactFunc", "compact with comparison"),
    ("Compare", "compare slices"),
    ("CompareFunc", "compare with function"),
    ("Concat", "concatenate slices"),
    ("Contains", "check if slice contains value"),
    ("ContainsFunc", "check with predicate"),
    ("Delete", "delete elements from slice"),
    ("DeleteFunc", "delete with predicate"),
    ("Equal", "check slice equality"),
    ("EqualFunc", "equality with function"),
    ("Grow", "grow slice capacity"),
    ("Index", "find first index"),
    ("IndexFunc", "find first matching index"),
    ("Insert", "insert elements"),
    ("IsSorted", "check if sorted"),
    ("IsSortedFunc", "check sorted with comparison"),
    ("Max", "get maximum element"),
    ("MaxFunc", "max with comparison"),
    ("Min", "get minimum element"),
    ("MinFunc", "min with comparison"),
    ("Replace", "replace slice range"),
    ("Reverse", "reverse slice"),
    ("Sort", "sort slice"),
    ("SortFunc", "sort with comparison"),
    ("SortStableFunc", "stable sort with comparison"),
]:
    add_func("slices", fn, "go-slices", purpose, "go_sort")

# --- maps (Go 1.21+) ---
for fn, purpose in [
    ("Clone", "clone map"),
    ("Collect", "collect from iter into map"),
    ("Copy", "copy map entries"),
    ("DeleteFunc", "delete with predicate"),
    ("Equal", "check map equality"),
    ("EqualFunc", "equality with function"),
    ("Insert", "insert from iter"),
    ("Keys", "get map keys"),
    ("Values", "get map values"),
]:
    add_func("maps", fn, "go-maps", purpose, "go_sort")

# --- cmp (Go 1.21+) ---
for fn, purpose in [
    ("Compare", "compare ordered values"),
    ("Less", "check less than"),
    ("Or", "return first non-zero value"),
]:
    add_func("cmp", fn, "go-cmp", purpose, "go_sort")

# --- mime, mime/multipart ---
for fn, purpose in [
    ("mime.FormatMediaType", "format media type"),
    ("mime.ParseMediaType", "parse media type"),
    ("mime.TypeByExtension", "get MIME type by extension"),
    ("mime.ExtensionsByType", "get extensions by MIME type"),
    ("mime.AddExtensionType", "add extension type mapping"),
    ("mime/multipart.NewReader", "create multipart reader"),
    ("mime/multipart.NewWriter", "create multipart writer"),
]:
    add(fn, "go-mime", purpose, "go_encoding")

# --- net/textproto ---
for fn, purpose in [
    ("CanonicalMIMEHeaderKey", "canonical MIME header key"),
    ("NewConn", "create textproto connection"),
    ("NewReader", "create textproto reader"),
    ("NewWriter", "create textproto writer"),
    ("TrimString", "trim CRLF"),
]:
    add_func("net/textproto", fn, "go-net", purpose, "go_net")

# --- hash, hash/crc32, hash/crc64, hash/fnv, hash/adler32, hash/maphash ---
for fn, purpose in [
    ("hash/crc32.New", "create CRC-32 hash"),
    ("hash/crc32.NewIEEE", "create IEEE CRC-32"),
    ("hash/crc32.ChecksumIEEE", "IEEE CRC-32 checksum"),
    ("hash/crc32.MakeTable", "make CRC-32 table"),
    ("hash/crc32.Update", "update CRC-32"),
    ("hash/crc64.New", "create CRC-64 hash"),
    ("hash/crc64.MakeTable", "make CRC-64 table"),
    ("hash/crc64.Update", "update CRC-64"),
    ("hash/fnv.New32", "create FNV-1 32-bit hash"),
    ("hash/fnv.New32a", "create FNV-1a 32-bit hash"),
    ("hash/fnv.New64", "create FNV-1 64-bit hash"),
    ("hash/fnv.New64a", "create FNV-1a 64-bit hash"),
    ("hash/fnv.New128", "create FNV-1 128-bit hash"),
    ("hash/fnv.New128a", "create FNV-1a 128-bit hash"),
    ("hash/adler32.New", "create Adler-32 hash"),
    ("hash/adler32.Checksum", "Adler-32 checksum"),
    ("hash/maphash.Bytes", "hash bytes"),
    ("hash/maphash.String", "hash string"),
]:
    add(fn, "go-hash", purpose, "go_crypto")

# --- net/rpc ---
for fn, purpose in [
    ("Accept", "accept RPC connections"),
    ("HandleHTTP", "register RPC HTTP handler"),
    ("NewClient", "create RPC client"),
    ("NewClientWithCodec", "create RPC client with codec"),
    ("NewServer", "create RPC server"),
    ("Register", "register RPC service"),
    ("RegisterName", "register named RPC service"),
    ("ServeCodec", "serve RPC with codec"),
    ("ServeConn", "serve RPC on connection"),
    ("ServeRequest", "serve single RPC request"),
    ("Dial", "connect to RPC server"),
    ("DialHTTP", "connect to HTTP RPC server"),
    ("DialHTTPPath", "connect to HTTP RPC path"),
]:
    add_func("net/rpc", fn, "go-rpc", purpose, "go_net")

# --- expvar ---
for fn, purpose in [
    ("Do", "iterate exported variables"),
    ("Get", "get exported variable"),
    ("Handler", "get HTTP handler"),
    ("NewFloat", "create exported float"),
    ("NewInt", "create exported int"),
    ("NewMap", "create exported map"),
    ("NewString", "create exported string"),
    ("Publish", "publish exported variable"),
]:
    add_func("expvar", fn, "go-expvar", purpose, "go_net")

# --- debug/elf, debug/macho, debug/pe, debug/dwarf, debug/gosym, debug/buildinfo, debug/plan9obj ---
for fn, purpose in [
    ("debug/elf.NewFile", "parse ELF file"),
    ("debug/elf.Open", "open ELF file"),
    ("debug/macho.NewFile", "parse Mach-O file"),
    ("debug/macho.Open", "open Mach-O file"),
    ("debug/macho.NewFatFile", "parse universal Mach-O"),
    ("debug/macho.OpenFat", "open universal Mach-O"),
    ("debug/pe.NewFile", "parse PE file"),
    ("debug/pe.Open", "open PE file"),
    ("debug/dwarf.New", "create DWARF data"),
    ("debug/gosym.NewLineTable", "create Go line table"),
    ("debug/gosym.NewTable", "create Go symbol table"),
    ("debug/buildinfo.Read", "read Go build info"),
    ("debug/buildinfo.ReadFile", "read Go build info from file"),
    ("debug/plan9obj.NewFile", "parse Plan 9 file"),
    ("debug/plan9obj.Open", "open Plan 9 file"),
]:
    add(fn, "go-debug", purpose, "go_debug")

# --- runtime/debug ---
for fn, purpose in [
    ("FreeOSMemory", "free OS memory"),
    ("PrintStack", "print stack trace"),
    ("ReadBuildInfo", "read build info"),
    ("ReadGCStats", "read GC statistics"),
    ("SetGCPercent", "set GC target percentage"),
    ("SetMaxStack", "set max stack size"),
    ("SetMaxThreads", "set max threads"),
    ("SetMemoryLimit", "set memory limit"),
    ("SetPanicOnFault", "set panic on fault"),
    ("SetTraceback", "set traceback level"),
    ("Stack", "get goroutine stack trace"),
    ("WriteHeapDump", "write heap dump"),
]:
    add_func("runtime/debug", fn, "go-runtime-debug", purpose, "go_debug")

# --- runtime/pprof ---
for fn, purpose in [
    ("Do", "execute with pprof labels"),
    ("ForLabels", "iterate pprof labels"),
    ("Label", "get pprof label value"),
    ("Labels", "create pprof label set"),
    ("Lookup", "lookup named profile"),
    ("NewProfile", "create named profile"),
    ("Profiles", "list all profiles"),
    ("SetGoroutineLabels", "set goroutine labels"),
    ("StartCPUProfile", "start CPU profiling"),
    ("StopCPUProfile", "stop CPU profiling"),
    ("WithLabels", "add labels to context"),
    ("WriteHeapProfile", "write heap profile"),
]:
    add_func("runtime/pprof", fn, "go-pprof", purpose, "go_debug")

# --- runtime/trace ---
for fn, purpose in [
    ("IsEnabled", "check if tracing enabled"),
    ("Log", "log trace event"),
    ("Logf", "formatted trace log"),
    ("NewTask", "create trace task"),
    ("StartRegion", "start trace region"),
    ("Start", "start tracing"),
    ("Stop", "stop tracing"),
    ("WithRegion", "execute with trace region"),
]:
    add_func("runtime/trace", fn, "go-trace", purpose, "go_debug")

# --- plugin ---
for fn, purpose in [
    ("Open", "open Go plugin"),
]:
    add_func("plugin", fn, "go-plugin", purpose, "go_runtime")

for method, purpose in [
    ("Lookup", "lookup plugin symbol"),
]:
    add_method("plugin", "Plugin", method, "go-plugin", purpose, "go_runtime")

# --- net/http/pprof ---
for fn, purpose in [
    ("Cmdline", "serve pprof cmdline"),
    ("Handler", "serve named pprof handler"),
    ("Index", "serve pprof index"),
    ("Profile", "serve CPU profile"),
    ("Symbol", "serve pprof symbol lookup"),
    ("Trace", "serve execution trace"),
]:
    add_func("net/http/pprof", fn, "go-pprof", purpose, "go_debug")

# --- crypto/x509/pkix ---
# This appears in Go binaries with certificate handling
add("crypto/x509/pkix.Name.String", "go-crypto", "X.509 distinguished name string", "go_crypto")

# =============================================================================
# PART 3: COMMON THIRD-PARTY PACKAGES
# =============================================================================

# --- github.com/spf13/cobra ---
cobra_pkg = "github.com/spf13/cobra"
for fn, purpose in [
    ("AddCommand", "add subcommand"),
    ("ArbitraryArgs", "allow arbitrary arguments"),
    ("CheckErr", "check and exit on error"),
    ("EnableCommandSorting", "enable command sorting"),
    ("EnablePrefixMatching", "enable prefix matching"),
    ("ExactArgs", "require exact N arguments"),
    ("ExactValidArgs", "require exact valid arguments"),
    ("MaximumNArgs", "allow max N arguments"),
    ("MinimumNArgs", "require min N arguments"),
    ("MousetrapHelpText", "Windows mousetrap text"),
    ("NoArgs", "disallow arguments"),
    ("OnInitialize", "register init function"),
    ("OnFinalize", "register finalize function"),
    ("RangeArgs", "require N-M arguments"),
]:
    add_func(cobra_pkg, fn, "cobra", purpose, "go_cli")

for method, purpose in [
    ("AddCommand", "add subcommand"),
    ("ArgsFunction", "get args function"),
    ("CalledAs", "get command alias used"),
    ("CommandPath", "get full command path"),
    ("Context", "get command context"),
    ("Execute", "execute root command"),
    ("ExecuteC", "execute and return command"),
    ("ExecuteContext", "execute with context"),
    ("ExecuteContextC", "execute context and return command"),
    ("Flags", "get command flags"),
    ("HasSubCommands", "check for subcommands"),
    ("Help", "print help"),
    ("InheritedFlags", "get inherited flags"),
    ("InitDefaultCompletionCmd", "init completion command"),
    ("InitDefaultHelpCmd", "init help command"),
    ("InitDefaultHelpFlag", "init help flag"),
    ("InitDefaultVersionFlag", "init version flag"),
    ("IsAdditionalHelpTopicCommand", "check help topic"),
    ("IsAvailableCommand", "check available"),
    ("LocalFlags", "get local flags"),
    ("MarkFlagRequired", "mark flag required"),
    ("MarkPersistentFlagRequired", "mark persistent flag required"),
    ("Name", "get command name"),
    ("OutOrStderr", "get output or stderr"),
    ("OutOrStdout", "get output or stdout"),
    ("Parent", "get parent command"),
    ("PersistentFlags", "get persistent flags"),
    ("Print", "print to output"),
    ("PrintErr", "print to error output"),
    ("PrintErrf", "formatted error print"),
    ("PrintErrln", "error print line"),
    ("Printf", "formatted print"),
    ("Println", "print line"),
    ("RegisterFlagCompletionFunc", "register flag completion"),
    ("Root", "get root command"),
    ("RunE", "get run error function"),
    ("SetArgs", "set command arguments"),
    ("SetContext", "set command context"),
    ("SetErr", "set error output"),
    ("SetHelpCommand", "set help command"),
    ("SetHelpFunc", "set help function"),
    ("SetHelpTemplate", "set help template"),
    ("SetIn", "set input"),
    ("SetOut", "set output"),
    ("SetUsageFunc", "set usage function"),
    ("SetUsageTemplate", "set usage template"),
    ("SetVersionTemplate", "set version template"),
    ("TraverseChildren", "traverse child commands"),
    ("Usage", "print usage"),
    ("UsageString", "get usage string"),
    ("UseLine", "get usage line"),
    ("ValidateArgs", "validate arguments"),
    ("ValidateRequiredFlags", "validate required flags"),
    ("VisitParents", "visit parent commands"),
]:
    add_method(cobra_pkg, "Command", method, "cobra", purpose, "go_cli")

# --- github.com/spf13/pflag ---
pflag_pkg = "github.com/spf13/pflag"
for fn_purpose in [
    ("Bool", "define bool flag"), ("BoolP", "bool flag with shorthand"),
    ("BoolVar", "bool flag variable"), ("BoolVarP", "bool var with shorthand"),
    ("Count", "define count flag"), ("CountP", "count with shorthand"),
    ("CountVar", "count variable"), ("CountVarP", "count var shorthand"),
    ("Duration", "duration flag"), ("DurationP", "duration shorthand"),
    ("DurationVar", "duration variable"), ("DurationVarP", "duration var shorthand"),
    ("Float32", "float32 flag"), ("Float32P", "float32 shorthand"),
    ("Float64", "float64 flag"), ("Float64P", "float64 shorthand"),
    ("Int", "int flag"), ("IntP", "int shorthand"),
    ("IntVar", "int variable"), ("IntVarP", "int var shorthand"),
    ("Int32", "int32 flag"), ("Int64", "int64 flag"),
    ("IP", "IP address flag"), ("IPMask", "IP mask flag"),
    ("IPNet", "IP network flag"), ("IPSlice", "IP slice flag"),
    ("Lookup", "lookup flag"), ("MarkDeprecated", "mark flag deprecated"),
    ("MarkHidden", "mark flag hidden"),
    ("Parse", "parse flags"), ("Parsed", "check if parsed"),
    ("Set", "set flag value"), ("String", "string flag"),
    ("StringP", "string shorthand"), ("StringVar", "string variable"),
    ("StringVarP", "string var shorthand"), ("StringArray", "string array flag"),
    ("StringSlice", "string slice flag"),
    ("Uint", "uint flag"), ("Uint32", "uint32 flag"), ("Uint64", "uint64 flag"),
    ("Var", "generic flag variable"), ("VarP", "generic flag var shorthand"),
    ("Visit", "visit set flags"), ("VisitAll", "visit all flags"),
    ("Changed", "check if flag changed"), ("GetBool", "get bool value"),
    ("GetFloat64", "get float64 value"), ("GetInt", "get int value"),
    ("GetString", "get string value"), ("GetStringSlice", "get string slice"),
]:
    fn, purpose = fn_purpose
    add_func(pflag_pkg, fn, "pflag", purpose, "go_cli")

# --- github.com/spf13/viper ---
viper_pkg = "github.com/spf13/viper"
for fn, purpose in [
    ("AddConfigPath", "add config search path"),
    ("AllKeys", "get all config keys"),
    ("AllSettings", "get all settings"),
    ("AutomaticEnv", "bind env vars automatically"),
    ("BindEnv", "bind env variable"),
    ("BindFlagValue", "bind flag value"),
    ("BindFlagValues", "bind flag values"),
    ("BindPFlag", "bind pflag"),
    ("BindPFlags", "bind pflags"),
    ("ConfigFileUsed", "get config file path"),
    ("Debug", "debug config"),
    ("Get", "get config value"),
    ("GetBool", "get bool config"),
    ("GetDuration", "get duration config"),
    ("GetFloat64", "get float64 config"),
    ("GetInt", "get int config"),
    ("GetInt32", "get int32 config"),
    ("GetInt64", "get int64 config"),
    ("GetIntSlice", "get int slice config"),
    ("GetSizeInBytes", "get size in bytes"),
    ("GetString", "get string config"),
    ("GetStringMap", "get string map config"),
    ("GetStringMapString", "get string-string map"),
    ("GetStringMapStringSlice", "get string-string slice map"),
    ("GetStringSlice", "get string slice config"),
    ("GetTime", "get time config"),
    ("GetUint", "get uint config"),
    ("GetUint32", "get uint32 config"),
    ("GetUint64", "get uint64 config"),
    ("InConfig", "check if key in config"),
    ("IsSet", "check if key set"),
    ("MergeConfig", "merge config reader"),
    ("MergeConfigMap", "merge config map"),
    ("MergeInConfig", "merge config file"),
    ("New", "create new viper instance"),
    ("OnConfigChange", "register config change callback"),
    ("ReadConfig", "read config from reader"),
    ("ReadInConfig", "read config file"),
    ("ReadRemoteConfig", "read remote config"),
    ("RegisterAlias", "register key alias"),
    ("Reset", "reset viper to defaults"),
    ("SafeWriteConfig", "write config (no overwrite)"),
    ("SafeWriteConfigAs", "write config as (no overwrite)"),
    ("Set", "set config value"),
    ("SetConfigFile", "set config file path"),
    ("SetConfigName", "set config name"),
    ("SetConfigType", "set config type"),
    ("SetDefault", "set default value"),
    ("SetEnvKeyReplacer", "set env key replacer"),
    ("SetEnvPrefix", "set env prefix"),
    ("SetTypeByDefaultValue", "set type by default"),
    ("Sub", "get sub-config"),
    ("Unmarshal", "unmarshal config to struct"),
    ("UnmarshalExact", "unmarshal exact config"),
    ("UnmarshalKey", "unmarshal config key"),
    ("WatchConfig", "watch config for changes"),
    ("WatchRemoteConfig", "watch remote config"),
    ("WriteConfig", "write config file"),
    ("WriteConfigAs", "write config to path"),
]:
    add_func(viper_pkg, fn, "viper", purpose, "go_config")

# --- github.com/sirupsen/logrus ---
logrus_pkg = "github.com/sirupsen/logrus"
for fn, purpose in [
    ("Debug", "debug log"), ("Debugf", "formatted debug"), ("Debugln", "debug line"),
    ("Error", "error log"), ("Errorf", "formatted error"), ("Errorln", "error line"),
    ("Fatal", "fatal log"), ("Fatalf", "formatted fatal"), ("Fatalln", "fatal line"),
    ("Info", "info log"), ("Infof", "formatted info"), ("Infoln", "info line"),
    ("Panic", "panic log"), ("Panicf", "formatted panic"), ("Panicln", "panic line"),
    ("Print", "print log"), ("Printf", "formatted print"), ("Println", "print line"),
    ("Trace", "trace log"), ("Tracef", "formatted trace"), ("Traceln", "trace line"),
    ("Warn", "warning log"), ("Warnf", "formatted warning"), ("Warnln", "warning line"),
    ("Warning", "warning log"), ("Warningf", "formatted warning"), ("Warningln", "warning line"),
    ("New", "create new logger"),
    ("SetFormatter", "set log formatter"),
    ("SetLevel", "set log level"),
    ("SetOutput", "set log output"),
    ("SetReportCaller", "set report caller"),
    ("StandardLogger", "get standard logger"),
    ("WithContext", "logger with context"),
    ("WithError", "logger with error"),
    ("WithField", "logger with field"),
    ("WithFields", "logger with fields"),
    ("WithTime", "logger with time"),
    ("AddHook", "add log hook"),
    ("GetLevel", "get log level"),
    ("IsLevelEnabled", "check if level enabled"),
    ("ParseLevel", "parse log level string"),
]:
    add_func(logrus_pkg, fn, "logrus", purpose, "go_log")

# --- go.uber.org/zap ---
zap_pkg = "go.uber.org/zap"
for fn, purpose in [
    ("New", "create logger"),
    ("NewDevelopment", "create development logger"),
    ("NewDevelopmentConfig", "development config"),
    ("NewExample", "create example logger"),
    ("NewNop", "create no-op logger"),
    ("NewProduction", "create production logger"),
    ("NewProductionConfig", "production config"),
    ("NewStdLog", "create std log from zap"),
    ("NewStdLogAt", "create std log at level"),
    ("RedirectStdLog", "redirect std log to zap"),
    ("ReplaceGlobals", "replace global logger"),
    ("L", "get global logger"),
    ("S", "get global sugar logger"),
    ("Any", "create any field"),
    ("Binary", "create binary field"),
    ("Bool", "create bool field"),
    ("ByteString", "create byte string field"),
    ("Complex128", "create complex128 field"),
    ("Complex64", "create complex64 field"),
    ("Duration", "create duration field"),
    ("Error", "create error field"),
    ("Float32", "create float32 field"),
    ("Float64", "create float64 field"),
    ("Int", "create int field"),
    ("Int8", "create int8 field"),
    ("Int16", "create int16 field"),
    ("Int32", "create int32 field"),
    ("Int64", "create int64 field"),
    ("NamedError", "create named error field"),
    ("Namespace", "create namespace field"),
    ("Reflect", "create reflect field"),
    ("Skip", "skip field"),
    ("Stack", "create stack field"),
    ("StackSkip", "create stack skip field"),
    ("Stringer", "create stringer field"),
    ("String", "create string field"),
    ("Strings", "create string slice field"),
    ("Time", "create time field"),
    ("Uint", "create uint field"),
    ("Uint8", "create uint8 field"),
    ("Uint16", "create uint16 field"),
    ("Uint32", "create uint32 field"),
    ("Uint64", "create uint64 field"),
]:
    add_func(zap_pkg, fn, "zap", purpose, "go_log")

for method, purpose in [
    ("Check", "check log level"),
    ("Core", "get logger core"),
    ("DPanic", "development panic log"),
    ("Debug", "debug log"),
    ("Error", "error log"),
    ("Fatal", "fatal log"),
    ("Info", "info log"),
    ("Named", "create named logger"),
    ("Panic", "panic log"),
    ("Sugar", "create sugar logger"),
    ("Sync", "flush logger"),
    ("Warn", "warning log"),
    ("With", "logger with fields"),
    ("WithOptions", "logger with options"),
]:
    add_method(zap_pkg, "Logger", method, "zap", purpose, "go_log")

for method, purpose in [
    ("DPanic", "development panic log"),
    ("DPanicf", "formatted dpanic"),
    ("DPanicw", "dpanic with kvs"),
    ("Debug", "debug log"),
    ("Debugf", "formatted debug"),
    ("Debugw", "debug with kvs"),
    ("Desugar", "convert to Logger"),
    ("Error", "error log"),
    ("Errorf", "formatted error"),
    ("Errorw", "error with kvs"),
    ("Fatal", "fatal log"),
    ("Fatalf", "formatted fatal"),
    ("Fatalw", "fatal with kvs"),
    ("Info", "info log"),
    ("Infof", "formatted info"),
    ("Infow", "info with kvs"),
    ("Named", "create named sugar logger"),
    ("Panic", "panic log"),
    ("Panicf", "formatted panic"),
    ("Panicw", "panic with kvs"),
    ("Sync", "flush sugar logger"),
    ("Warn", "warning log"),
    ("Warnf", "formatted warning"),
    ("Warnw", "warning with kvs"),
    ("With", "sugar with fields"),
]:
    add_method(zap_pkg, "SugaredLogger", method, "zap", purpose, "go_log")

# --- google.golang.org/grpc ---
grpc_pkg = "google.golang.org/grpc"
for fn, purpose in [
    ("Dial", "dial gRPC server (deprecated)"),
    ("DialContext", "dial gRPC server with context (deprecated)"),
    ("NewClient", "create gRPC client"),
    ("NewServer", "create gRPC server"),
    ("NewClientStream", "create client stream"),
    ("NewServerStream", "create server stream"),
    ("ClientConnInterface", "client connection interface"),
    ("StreamClientInterceptor", "stream client interceptor"),
    ("StreamServerInterceptor", "stream server interceptor"),
    ("UnaryClientInterceptor", "unary client interceptor"),
    ("UnaryServerInterceptor", "unary server interceptor"),
    ("WithBlock", "dial option: block until connected"),
    ("WithInsecure", "dial option: no TLS (deprecated)"),
    ("WithTransportCredentials", "dial option: transport credentials"),
    ("WithPerRPCCredentials", "dial option: per-RPC credentials"),
    ("WithDefaultCallOptions", "dial option: default call options"),
    ("WithUserAgent", "dial option: user agent"),
    ("WithKeepaliveParams", "dial option: keepalive parameters"),
    ("WithStreamInterceptor", "dial option: stream interceptor"),
    ("WithUnaryInterceptor", "dial option: unary interceptor"),
    ("WithChainStreamInterceptor", "dial option: chain stream interceptors"),
    ("WithChainUnaryInterceptor", "dial option: chain unary interceptors"),
    ("Creds", "server option: credentials"),
    ("MaxRecvMsgSize", "server option: max receive message"),
    ("MaxSendMsgSize", "server option: max send message"),
    ("ChainStreamInterceptor", "server option: chain stream"),
    ("ChainUnaryInterceptor", "server option: chain unary"),
    ("KeepaliveEnforcementPolicy", "server option: keepalive enforcement"),
    ("KeepaliveParams", "server option: keepalive parameters"),
]:
    add_func(grpc_pkg, fn, "grpc", purpose, "go_grpc")

for method, purpose in [
    ("Close", "close client connection"),
    ("GetState", "get connection state"),
    ("Invoke", "invoke unary RPC"),
    ("NewStream", "create new stream"),
    ("Target", "get connection target"),
    ("WaitForStateChange", "wait for state change"),
]:
    add_method(grpc_pkg, "ClientConn", method, "grpc", purpose, "go_grpc")

for method, purpose in [
    ("GetServiceInfo", "get service info"),
    ("GracefulStop", "graceful shutdown"),
    ("RegisterService", "register gRPC service"),
    ("Serve", "start gRPC server"),
    ("ServeHTTP", "serve gRPC over HTTP"),
    ("Stop", "stop gRPC server"),
]:
    add_method(grpc_pkg, "Server", method, "grpc", purpose, "go_grpc")

# --- google.golang.org/grpc/status ---
for fn, purpose in [
    ("Code", "get gRPC status code"),
    ("Convert", "convert error to status"),
    ("Error", "create gRPC error"),
    ("Errorf", "create formatted gRPC error"),
    ("FromError", "extract status from error"),
    ("New", "create new status"),
    ("Newf", "create formatted status"),
]:
    add_func("google.golang.org/grpc/status", fn, "grpc-status", purpose, "go_grpc")

# --- google.golang.org/grpc/codes ---
for code in [
    "OK", "Canceled", "Unknown", "InvalidArgument", "DeadlineExceeded",
    "NotFound", "AlreadyExists", "PermissionDenied", "ResourceExhausted",
    "FailedPrecondition", "Aborted", "OutOfRange", "Unimplemented",
    "Internal", "Unavailable", "DataLoss", "Unauthenticated",
]:
    add(f"google.golang.org/grpc/codes.{code}", "grpc-codes", f"gRPC status code: {code}", "go_grpc")

# --- google.golang.org/grpc/metadata ---
for fn, purpose in [
    ("FromIncomingContext", "get metadata from incoming context"),
    ("FromOutgoingContext", "get metadata from outgoing context"),
    ("New", "create metadata from map"),
    ("NewIncomingContext", "create context with incoming metadata"),
    ("NewOutgoingContext", "create context with outgoing metadata"),
    ("Pairs", "create metadata from key-value pairs"),
    ("AppendToOutgoingContext", "append to outgoing metadata"),
    ("ValueFromIncomingContext", "get value from incoming metadata"),
]:
    add_func("google.golang.org/grpc/metadata", fn, "grpc-metadata", purpose, "go_grpc")

# --- google.golang.org/protobuf / github.com/golang/protobuf ---
for fn, purpose in [
    ("google.golang.org/protobuf/proto.Marshal", "protobuf marshal"),
    ("google.golang.org/protobuf/proto.Unmarshal", "protobuf unmarshal"),
    ("google.golang.org/protobuf/proto.MarshalOptions.Marshal", "protobuf marshal with options"),
    ("google.golang.org/protobuf/proto.UnmarshalOptions.Unmarshal", "protobuf unmarshal with options"),
    ("google.golang.org/protobuf/proto.Clone", "clone protobuf message"),
    ("google.golang.org/protobuf/proto.Equal", "compare protobuf messages"),
    ("google.golang.org/protobuf/proto.Merge", "merge protobuf messages"),
    ("google.golang.org/protobuf/proto.Reset", "reset protobuf message"),
    ("google.golang.org/protobuf/proto.Size", "protobuf encoded size"),
    ("google.golang.org/protobuf/proto.HasExtension", "check protobuf extension"),
    ("google.golang.org/protobuf/proto.GetExtension", "get protobuf extension"),
    ("google.golang.org/protobuf/proto.SetExtension", "set protobuf extension"),
    ("google.golang.org/protobuf/proto.MessageName", "get message name"),
    ("google.golang.org/protobuf/encoding/protojson.Marshal", "protobuf to JSON"),
    ("google.golang.org/protobuf/encoding/protojson.Unmarshal", "JSON to protobuf"),
    ("google.golang.org/protobuf/encoding/prototext.Marshal", "protobuf to text"),
    ("google.golang.org/protobuf/encoding/prototext.Unmarshal", "text to protobuf"),
    ("github.com/golang/protobuf/proto.Marshal", "protobuf marshal (v1)"),
    ("github.com/golang/protobuf/proto.Unmarshal", "protobuf unmarshal (v1)"),
    ("github.com/golang/protobuf/proto.MarshalTextString", "protobuf to text (v1)"),
    ("github.com/golang/protobuf/proto.Clone", "clone protobuf (v1)"),
    ("github.com/golang/protobuf/proto.Equal", "compare protobuf (v1)"),
    ("github.com/golang/protobuf/proto.Merge", "merge protobuf (v1)"),
    ("github.com/golang/protobuf/proto.Size", "protobuf size (v1)"),
    ("github.com/golang/protobuf/jsonpb.Marshal", "protobuf to JSON (v1)"),
    ("github.com/golang/protobuf/jsonpb.Unmarshal", "JSON to protobuf (v1)"),
]:
    add(fn, "protobuf", purpose, "go_grpc")

# --- github.com/gorilla/mux ---
mux_pkg = "github.com/gorilla/mux"
for fn, purpose in [
    ("NewRouter", "create new HTTP router"),
    ("Vars", "get route variables"),
    ("CurrentRoute", "get current route"),
    ("SetURLVars", "set URL variables (testing)"),
]:
    add_func(mux_pkg, fn, "gorilla-mux", purpose, "go_http")

for method, purpose in [
    ("Get", "get named route"),
    ("GetRoute", "get route by name"),
    ("Handle", "register handler"),
    ("HandleFunc", "register handler function"),
    ("Headers", "match by headers"),
    ("Host", "match by host"),
    ("Methods", "match by HTTP methods"),
    ("Name", "name the route"),
    ("NewRoute", "create new route"),
    ("NotFoundHandler", "set 404 handler"),
    ("Path", "match by path"),
    ("PathPrefix", "match by path prefix"),
    ("Queries", "match by query parameters"),
    ("Schemes", "match by schemes"),
    ("ServeHTTP", "dispatch request"),
    ("StrictSlash", "set strict slash"),
    ("Subrouter", "create subrouter"),
    ("Use", "add middleware"),
    ("Walk", "walk route tree"),
]:
    add_method(mux_pkg, "Router", method, "gorilla-mux", purpose, "go_http")

# --- github.com/gin-gonic/gin ---
gin_pkg = "github.com/gin-gonic/gin"
for fn, purpose in [
    ("Default", "create default gin engine"),
    ("New", "create gin engine"),
    ("CreateTestContext", "create test context"),
    ("DisableConsoleColor", "disable console color"),
    ("ForceConsoleColor", "force console color"),
    ("IsDebugging", "check debug mode"),
    ("Mode", "get gin mode"),
    ("Recovery", "recovery middleware"),
    ("Logger", "logger middleware"),
    ("SetMode", "set gin mode"),
    ("BasicAuth", "basic auth middleware"),
    ("BasicAuthForRealm", "basic auth with realm"),
]:
    add_func(gin_pkg, fn, "gin", purpose, "go_http")

for method, purpose in [
    ("Any", "register all HTTP methods"),
    ("DELETE", "register DELETE handler"),
    ("GET", "register GET handler"),
    ("Group", "create route group"),
    ("HEAD", "register HEAD handler"),
    ("Handle", "register handler"),
    ("HandleContext", "handle with context"),
    ("LoadHTMLFiles", "load HTML templates"),
    ("LoadHTMLGlob", "load HTML templates by glob"),
    ("NoMethod", "set no-method handler"),
    ("NoRoute", "set no-route handler"),
    ("OPTIONS", "register OPTIONS handler"),
    ("PATCH", "register PATCH handler"),
    ("POST", "register POST handler"),
    ("PUT", "register PUT handler"),
    ("Routes", "get all routes"),
    ("Run", "start HTTP server"),
    ("RunTLS", "start HTTPS server"),
    ("RunUnix", "start Unix socket server"),
    ("SecureJsonPrefix", "set secure JSON prefix"),
    ("ServeHTTP", "serve HTTP"),
    ("SetHTMLTemplate", "set HTML template"),
    ("SetTrustedProxies", "set trusted proxies"),
    ("Static", "serve static files"),
    ("StaticFS", "serve static filesystem"),
    ("StaticFile", "serve static file"),
    ("Use", "add middleware"),
]:
    add_method(gin_pkg, "Engine", method, "gin", purpose, "go_http")

for method, purpose in [
    ("Abort", "abort request"),
    ("AbortWithError", "abort with error"),
    ("AbortWithStatus", "abort with status"),
    ("AbortWithStatusJSON", "abort with JSON"),
    ("Bind", "bind request data"),
    ("BindJSON", "bind JSON body"),
    ("BindQuery", "bind query parameters"),
    ("BindXML", "bind XML body"),
    ("BindYAML", "bind YAML body"),
    ("ClientIP", "get client IP"),
    ("ContentType", "get content type"),
    ("Cookie", "get cookie"),
    ("Copy", "copy context"),
    ("Data", "write raw data"),
    ("DefaultPostForm", "get post form with default"),
    ("DefaultQuery", "get query with default"),
    ("Error", "add error to context"),
    ("File", "serve file"),
    ("FileFromFS", "serve file from FS"),
    ("FullPath", "get full route path"),
    ("Get", "get context value"),
    ("GetBool", "get bool value"),
    ("GetFloat64", "get float64 value"),
    ("GetHeader", "get request header"),
    ("GetInt", "get int value"),
    ("GetInt64", "get int64 value"),
    ("GetPostForm", "get post form value"),
    ("GetPostFormArray", "get post form array"),
    ("GetQuery", "get query parameter"),
    ("GetQueryArray", "get query array"),
    ("GetString", "get string value"),
    ("GetStringMap", "get string map value"),
    ("GetStringSlice", "get string slice value"),
    ("HTML", "render HTML template"),
    ("Header", "set response header"),
    ("IndentedJSON", "write indented JSON"),
    ("IsAborted", "check if aborted"),
    ("JSON", "write JSON response"),
    ("JSONP", "write JSONP response"),
    ("MustGet", "get value or panic"),
    ("Next", "call next handler"),
    ("Param", "get URL parameter"),
    ("PostForm", "get post form value"),
    ("PostFormArray", "get post form array"),
    ("ProtobufJSON", "write protobuf JSON"),
    ("PureJSON", "write pure JSON"),
    ("Query", "get query parameter"),
    ("QueryArray", "get query array"),
    ("Redirect", "redirect request"),
    ("Render", "render response"),
    ("SSEvent", "send SSE event"),
    ("SaveUploadedFile", "save uploaded file"),
    ("SecureJSON", "write secure JSON"),
    ("Set", "set context value"),
    ("SetAccepted", "set accepted formats"),
    ("SetCookie", "set response cookie"),
    ("SetSameSite", "set cookie SameSite"),
    ("ShouldBind", "bind or return error"),
    ("ShouldBindJSON", "bind JSON or error"),
    ("ShouldBindQuery", "bind query or error"),
    ("ShouldBindXML", "bind XML or error"),
    ("ShouldBindYAML", "bind YAML or error"),
    ("Status", "set response status"),
    ("Stream", "stream response"),
    ("String", "write string response"),
    ("Writer", "get response writer"),
    ("XML", "write XML response"),
    ("YAML", "write YAML response"),
]:
    add_method(gin_pkg, "Context", method, "gin", purpose, "go_http")

# --- github.com/labstack/echo ---
echo_pkg = "github.com/labstack/echo/v4"
for fn, purpose in [
    ("New", "create echo instance"),
    ("MustSubFS", "must get sub filesystem"),
    ("NotFoundHandler", "default 404 handler"),
    ("MethodNotAllowedHandler", "default 405 handler"),
    ("WrapHandler", "wrap http.Handler"),
    ("WrapMiddleware", "wrap http middleware"),
]:
    add_func(echo_pkg, fn, "echo", purpose, "go_http")

# --- github.com/go-chi/chi ---
chi_pkg = "github.com/go-chi/chi/v5"
for fn, purpose in [
    ("NewRouter", "create chi router"),
    ("NewMux", "create chi mux"),
    ("URLParam", "get URL parameter"),
    ("URLParamFromCtx", "get URL param from context"),
    ("RouteContext", "get route context"),
]:
    add_func(chi_pkg, fn, "chi", purpose, "go_http")

# --- gorm.io/gorm ---
gorm_pkg = "gorm.io/gorm"
for fn, purpose in [
    ("Open", "open GORM database"),
]:
    add_func(gorm_pkg, fn, "gorm", purpose, "go_database")

for method, purpose in [
    ("AutoMigrate", "auto migrate schema"),
    ("Begin", "start transaction"),
    ("Clauses", "add SQL clauses"),
    ("Commit", "commit transaction"),
    ("Count", "count records"),
    ("Create", "insert record"),
    ("CreateInBatches", "batch insert"),
    ("DB", "get underlying *sql.DB"),
    ("Debug", "enable debug logging"),
    ("Delete", "delete records"),
    ("Distinct", "add DISTINCT"),
    ("Error", "get last error"),
    ("Exec", "execute raw SQL"),
    ("Find", "find records"),
    ("First", "find first record"),
    ("FirstOrCreate", "find or create"),
    ("FirstOrInit", "find or initialize"),
    ("Group", "add GROUP BY"),
    ("Having", "add HAVING"),
    ("InnerJoins", "add INNER JOIN"),
    ("Joins", "add JOIN"),
    ("Last", "find last record"),
    ("Limit", "add LIMIT"),
    ("Model", "specify model"),
    ("Not", "add NOT condition"),
    ("Offset", "add OFFSET"),
    ("Omit", "omit columns"),
    ("Or", "add OR condition"),
    ("Order", "add ORDER BY"),
    ("Pluck", "query single column"),
    ("Preload", "preload associations"),
    ("Raw", "raw SQL query"),
    ("Rollback", "rollback transaction"),
    ("Row", "query single row"),
    ("Rows", "query rows"),
    ("Save", "save record"),
    ("Scan", "scan result"),
    ("Scopes", "apply scopes"),
    ("Select", "select columns"),
    ("Session", "create session"),
    ("Set", "set value in context"),
    ("Table", "specify table"),
    ("Take", "take one record"),
    ("Transaction", "execute in transaction"),
    ("Unscoped", "remove soft delete scope"),
    ("Update", "update column"),
    ("UpdateColumn", "update without callbacks"),
    ("UpdateColumns", "update multiple columns"),
    ("Updates", "update multiple fields"),
    ("Where", "add WHERE condition"),
    ("WithContext", "add context"),
]:
    add_method(gorm_pkg, "DB", method, "gorm", purpose, "go_database")

# --- github.com/go-redis/redis ---
redis_pkg = "github.com/go-redis/redis/v8"
for fn, purpose in [
    ("NewClient", "create Redis client"),
    ("NewClusterClient", "create Redis cluster client"),
    ("NewFailoverClient", "create Redis failover client"),
    ("NewRing", "create Redis ring client"),
    ("NewSentinelClient", "create Redis sentinel client"),
    ("NewUniversalClient", "create universal Redis client"),
]:
    add_func(redis_pkg, fn, "go-redis", purpose, "go_database")

for method, purpose in [
    ("Append", "append to key"), ("BLPop", "blocking left pop"),
    ("BRPop", "blocking right pop"), ("BRPopLPush", "blocking rotate"),
    ("Close", "close client"), ("Cluster", "cluster commands"),
    ("DBSize", "get database size"), ("Debug", "debug command"),
    ("Decr", "decrement key"), ("DecrBy", "decrement by value"),
    ("Del", "delete keys"), ("Dump", "dump key value"),
    ("Echo", "echo message"), ("Eval", "evaluate Lua script"),
    ("EvalSha", "evaluate Lua by SHA"), ("Exists", "check key existence"),
    ("Expire", "set key expiration"), ("ExpireAt", "set key expiration time"),
    ("FlushAll", "flush all databases"), ("FlushDB", "flush current database"),
    ("Get", "get key value"), ("GetBit", "get bit value"),
    ("GetDel", "get and delete"), ("GetEx", "get with expiration"),
    ("GetRange", "get string range"), ("GetSet", "get and set"),
    ("HDel", "hash delete field"), ("HExists", "hash field exists"),
    ("HGet", "hash get field"), ("HGetAll", "hash get all"),
    ("HIncrBy", "hash increment by"), ("HIncrByFloat", "hash increment float"),
    ("HKeys", "hash get keys"), ("HLen", "hash length"),
    ("HMGet", "hash multi get"), ("HMSet", "hash multi set"),
    ("HSet", "hash set field"), ("HSetNX", "hash set if not exists"),
    ("HVals", "hash get values"),
    ("Incr", "increment key"), ("IncrBy", "increment by value"),
    ("IncrByFloat", "increment by float"),
    ("Keys", "list keys by pattern"), ("LIndex", "list get by index"),
    ("LInsert", "list insert"), ("LInsertAfter", "list insert after"),
    ("LInsertBefore", "list insert before"), ("LLen", "list length"),
    ("LPop", "list left pop"), ("LPos", "list find position"),
    ("LPush", "list left push"), ("LPushX", "list left push if exists"),
    ("LRange", "list get range"), ("LRem", "list remove"),
    ("LSet", "list set by index"), ("LTrim", "list trim"),
    ("MGet", "multi get"), ("MSet", "multi set"),
    ("MSetNX", "multi set if not exists"),
    ("Persist", "remove key expiration"), ("PExpire", "set ms expiration"),
    ("PExpireAt", "set ms expiration time"),
    ("Ping", "ping server"), ("Pipeline", "create pipeline"),
    ("Pipelined", "execute pipeline"), ("PSubscribe", "pattern subscribe"),
    ("PTTL", "get ms TTL"), ("Publish", "publish message"),
    ("RPop", "list right pop"), ("RPopLPush", "list rotate"),
    ("RPush", "list right push"), ("RPushX", "list right push if exists"),
    ("Rename", "rename key"), ("RenameNX", "rename if not exists"),
    ("SAdd", "set add member"), ("SCard", "set cardinality"),
    ("SDiff", "set difference"), ("SInter", "set intersection"),
    ("SIsMember", "set check member"), ("SMembers", "set get members"),
    ("SMove", "set move member"), ("SPop", "set random pop"),
    ("SRandMember", "set random member"), ("SRem", "set remove member"),
    ("SScan", "set scan"), ("SUnion", "set union"),
    ("Scan", "scan keys"), ("ScriptExists", "check script exists"),
    ("ScriptFlush", "flush scripts"), ("ScriptLoad", "load script"),
    ("Set", "set key value"), ("SetBit", "set bit"),
    ("SetEX", "set with expiration"), ("SetNX", "set if not exists"),
    ("SetRange", "set string range"),
    ("Sort", "sort key"), ("StrLen", "string length"),
    ("Subscribe", "subscribe to channels"),
    ("TTL", "get key TTL"), ("Time", "get server time"),
    ("Touch", "touch key"), ("TxPipeline", "create transaction pipeline"),
    ("TxPipelined", "execute transaction pipeline"),
    ("Type", "get key type"), ("Unlink", "unlink keys"),
    ("Wait", "wait for replication"), ("Watch", "watch keys"),
    ("XAck", "stream acknowledge"), ("XAdd", "stream add"),
    ("XClaim", "stream claim"), ("XDel", "stream delete"),
    ("XGroupCreate", "stream create group"),
    ("XGroupCreateMkStream", "create group and stream"),
    ("XGroupDelConsumer", "delete consumer"),
    ("XGroupDestroy", "destroy group"),
    ("XLen", "stream length"), ("XPending", "stream pending"),
    ("XRange", "stream range"), ("XRead", "stream read"),
    ("XReadGroup", "stream read group"), ("XRevRange", "stream reverse range"),
    ("XTrimMaxLen", "stream trim by max length"),
    ("ZAdd", "sorted set add"), ("ZCard", "sorted set cardinality"),
    ("ZCount", "sorted set count"), ("ZIncrBy", "sorted set increment"),
    ("ZRange", "sorted set range"), ("ZRangeByLex", "sorted set range by lex"),
    ("ZRangeByScore", "sorted set range by score"),
    ("ZRank", "sorted set rank"), ("ZRem", "sorted set remove"),
    ("ZRemRangeByLex", "remove by lex range"),
    ("ZRemRangeByRank", "remove by rank range"),
    ("ZRemRangeByScore", "remove by score range"),
    ("ZRevRange", "sorted set reverse range"),
    ("ZRevRangeByScore", "reverse range by score"),
    ("ZRevRank", "sorted set reverse rank"),
    ("ZScan", "sorted set scan"), ("ZScore", "sorted set score"),
]:
    add_method(redis_pkg, "Client", method, "go-redis", purpose, "go_database")

# --- github.com/aws/aws-sdk-go-v2 (common packages) ---
aws_pkg = "github.com/aws/aws-sdk-go-v2"
for fn, purpose in [
    (f"{aws_pkg}/config.LoadDefaultConfig", "load AWS default config"),
    (f"{aws_pkg}/credentials.NewStaticCredentialsProvider", "create static AWS credentials"),
    (f"{aws_pkg}/service/s3.NewFromConfig", "create S3 client"),
    (f"{aws_pkg}/service/s3.New", "create S3 client"),
    (f"{aws_pkg}/service/dynamodb.NewFromConfig", "create DynamoDB client"),
    (f"{aws_pkg}/service/sqs.NewFromConfig", "create SQS client"),
    (f"{aws_pkg}/service/sns.NewFromConfig", "create SNS client"),
    (f"{aws_pkg}/service/lambda.NewFromConfig", "create Lambda client"),
    (f"{aws_pkg}/service/ec2.NewFromConfig", "create EC2 client"),
    (f"{aws_pkg}/service/iam.NewFromConfig", "create IAM client"),
    (f"{aws_pkg}/service/sts.NewFromConfig", "create STS client"),
    (f"{aws_pkg}/service/cloudwatch.NewFromConfig", "create CloudWatch client"),
    (f"{aws_pkg}/service/secretsmanager.NewFromConfig", "create Secrets Manager client"),
    (f"{aws_pkg}/service/kms.NewFromConfig", "create KMS client"),
]:
    add(fn, "aws-sdk-go", purpose, "go_cloud")

# S3 client methods
for method, purpose in [
    ("CopyObject", "copy S3 object"),
    ("CreateBucket", "create S3 bucket"),
    ("DeleteBucket", "delete S3 bucket"),
    ("DeleteObject", "delete S3 object"),
    ("DeleteObjects", "delete multiple S3 objects"),
    ("GetBucketAcl", "get bucket ACL"),
    ("GetBucketLocation", "get bucket region"),
    ("GetObject", "download S3 object"),
    ("HeadBucket", "check bucket exists"),
    ("HeadObject", "get S3 object metadata"),
    ("ListBuckets", "list S3 buckets"),
    ("ListObjectsV2", "list S3 objects"),
    ("PutBucketAcl", "set bucket ACL"),
    ("PutObject", "upload S3 object"),
]:
    add(f"{aws_pkg}/service/s3.(*Client).{method}", "aws-sdk-go", purpose, "go_cloud")

# --- github.com/prometheus/client_golang ---
prom_pkg = "github.com/prometheus/client_golang/prometheus"
for fn, purpose in [
    ("NewCounter", "create Prometheus counter"),
    ("NewCounterFunc", "create counter with function"),
    ("NewCounterVec", "create counter vector"),
    ("NewGauge", "create Prometheus gauge"),
    ("NewGaugeFunc", "create gauge with function"),
    ("NewGaugeVec", "create gauge vector"),
    ("NewHistogram", "create Prometheus histogram"),
    ("NewHistogramVec", "create histogram vector"),
    ("NewSummary", "create Prometheus summary"),
    ("NewSummaryVec", "create summary vector"),
    ("MustRegister", "register metrics (panic on error)"),
    ("Register", "register metric"),
    ("Unregister", "unregister metric"),
    ("DefaultRegisterer", "get default registerer"),
    ("NewPedanticRegistry", "create pedantic registry"),
    ("NewRegistry", "create metric registry"),
]:
    add_func(prom_pkg, fn, "prometheus", purpose, "go_metrics")

add_func(f"{prom_pkg}/promhttp", "Handler", "prometheus", "Prometheus HTTP handler", "go_metrics")
add_func(f"{prom_pkg}/promhttp", "HandlerFor", "prometheus", "Prometheus handler for registry", "go_metrics")
add_func(f"{prom_pkg}/promhttp", "InstrumentHandlerCounter", "prometheus", "instrument handler with counter", "go_metrics")
add_func(f"{prom_pkg}/promhttp", "InstrumentHandlerDuration", "prometheus", "instrument handler with duration", "go_metrics")

# --- github.com/stretchr/testify ---
testify_assert = "github.com/stretchr/testify/assert"
testify_require = "github.com/stretchr/testify/require"
for pkg, lib in [(testify_assert, "testify-assert"), (testify_require, "testify-require")]:
    for fn, purpose in [
        ("Contains", "assert contains"),
        ("DirExists", "assert directory exists"),
        ("ElementsMatch", "assert elements match"),
        ("Empty", "assert empty"),
        ("Equal", "assert equal"),
        ("EqualError", "assert equal error"),
        ("EqualValues", "assert equal values"),
        ("Error", "assert error"),
        ("ErrorAs", "assert error as type"),
        ("ErrorContains", "assert error contains"),
        ("ErrorIs", "assert error is"),
        ("Eventually", "assert eventually true"),
        ("Fail", "fail test"),
        ("FailNow", "fail test now"),
        ("False", "assert false"),
        ("FileExists", "assert file exists"),
        ("Greater", "assert greater"),
        ("GreaterOrEqual", "assert greater or equal"),
        ("Implements", "assert implements interface"),
        ("InDelta", "assert within delta"),
        ("InEpsilon", "assert within epsilon"),
        ("IsType", "assert type"),
        ("JSONEq", "assert JSON equal"),
        ("Len", "assert length"),
        ("Less", "assert less"),
        ("LessOrEqual", "assert less or equal"),
        ("Negative", "assert negative"),
        ("Never", "assert never true"),
        ("Nil", "assert nil"),
        ("NoError", "assert no error"),
        ("NotContains", "assert not contains"),
        ("NotEmpty", "assert not empty"),
        ("NotEqual", "assert not equal"),
        ("NotEqualValues", "assert not equal values"),
        ("NotNil", "assert not nil"),
        ("NotPanics", "assert no panic"),
        ("NotSame", "assert not same pointer"),
        ("NotZero", "assert not zero"),
        ("Panics", "assert panics"),
        ("PanicsWithError", "assert panics with error"),
        ("PanicsWithValue", "assert panics with value"),
        ("Positive", "assert positive"),
        ("Regexp", "assert matches regexp"),
        ("Same", "assert same pointer"),
        ("Subset", "assert subset"),
        ("True", "assert true"),
        ("WithinDuration", "assert within duration"),
        ("Zero", "assert zero value"),
        ("New", "create assertions instance"),
    ]:
        add_func(pkg, fn, lib, purpose, "go_testing")

# --- github.com/stretchr/testify/mock ---
for method, purpose in [
    ("AssertCalled", "assert mock called"),
    ("AssertExpectations", "assert all expectations met"),
    ("AssertNotCalled", "assert mock not called"),
    ("Called", "record mock call"),
    ("IsMethodCallable", "check method callable"),
    ("Maybe", "set optional call"),
    ("MethodCalled", "get method call"),
    ("On", "set expectation"),
    ("Test", "set test"),
    ("Unset", "unset expectation"),
]:
    add_method("github.com/stretchr/testify/mock", "Mock", method, "testify-mock", purpose, "go_testing")

# --- golang.org/x/crypto, x/net, x/text, x/sync, x/time ---
for fn, purpose in [
    ("golang.org/x/crypto/bcrypt.GenerateFromPassword", "bcrypt hash password"),
    ("golang.org/x/crypto/bcrypt.CompareHashAndPassword", "bcrypt compare password"),
    ("golang.org/x/crypto/bcrypt.Cost", "get bcrypt cost"),
    ("golang.org/x/crypto/argon2.IDKey", "Argon2id key derivation"),
    ("golang.org/x/crypto/argon2.Key", "Argon2i key derivation"),
    ("golang.org/x/crypto/chacha20poly1305.New", "create ChaCha20-Poly1305"),
    ("golang.org/x/crypto/chacha20poly1305.NewX", "create XChaCha20-Poly1305"),
    ("golang.org/x/crypto/nacl/box.Open", "NaCl box open"),
    ("golang.org/x/crypto/nacl/box.Seal", "NaCl box seal"),
    ("golang.org/x/crypto/nacl/box.GenerateKey", "NaCl generate key pair"),
    ("golang.org/x/crypto/nacl/secretbox.Open", "NaCl secretbox open"),
    ("golang.org/x/crypto/nacl/secretbox.Seal", "NaCl secretbox seal"),
    ("golang.org/x/crypto/pbkdf2.Key", "PBKDF2 key derivation"),
    ("golang.org/x/crypto/scrypt.Key", "scrypt key derivation"),
    ("golang.org/x/crypto/ssh.Dial", "SSH dial"),
    ("golang.org/x/crypto/ssh.NewClient", "create SSH client"),
    ("golang.org/x/crypto/ssh.NewClientConn", "create SSH client connection"),
    ("golang.org/x/crypto/ssh.ParsePrivateKey", "parse SSH private key"),
    ("golang.org/x/crypto/ssh.ParseAuthorizedKey", "parse SSH authorized key"),
    ("golang.org/x/crypto/ssh.PublicKeys", "SSH public key auth"),
    ("golang.org/x/crypto/ssh.Password", "SSH password auth"),
    ("golang.org/x/crypto/hkdf.New", "create HKDF reader"),
    ("golang.org/x/crypto/hkdf.Expand", "HKDF expand"),
    ("golang.org/x/crypto/hkdf.Extract", "HKDF extract"),
    ("golang.org/x/crypto/blake2b.New256", "create BLAKE2b-256"),
    ("golang.org/x/crypto/blake2b.New384", "create BLAKE2b-384"),
    ("golang.org/x/crypto/blake2b.New512", "create BLAKE2b-512"),
    ("golang.org/x/crypto/blake2b.Sum256", "BLAKE2b-256 sum"),
    ("golang.org/x/crypto/blake2b.Sum384", "BLAKE2b-384 sum"),
    ("golang.org/x/crypto/blake2b.Sum512", "BLAKE2b-512 sum"),
    ("golang.org/x/crypto/blake2s.New128", "create BLAKE2s-128"),
    ("golang.org/x/crypto/blake2s.New256", "create BLAKE2s-256"),
    ("golang.org/x/crypto/blake2s.Sum256", "BLAKE2s-256 sum"),
    ("golang.org/x/crypto/curve25519.ScalarMult", "Curve25519 scalar mult"),
    ("golang.org/x/crypto/curve25519.ScalarBaseMult", "Curve25519 base mult"),
    ("golang.org/x/crypto/curve25519.X25519", "X25519 key exchange"),
    ("golang.org/x/net/context.Background", "x/net context background"),
    ("golang.org/x/net/context.TODO", "x/net context TODO"),
    ("golang.org/x/net/http2.ConfigureServer", "configure HTTP/2 server"),
    ("golang.org/x/net/http2.ConfigureTransport", "configure HTTP/2 transport"),
    ("golang.org/x/net/http2.ConfigureTransports", "configure HTTP/2 transports"),
    ("golang.org/x/net/proxy.FromURL", "create proxy dialer from URL"),
    ("golang.org/x/net/proxy.SOCKS5", "create SOCKS5 proxy"),
    ("golang.org/x/net/websocket.Dial", "websocket dial"),
    ("golang.org/x/net/websocket.Handler", "websocket handler"),
    ("golang.org/x/text/encoding.Nop", "no-op encoding"),
    ("golang.org/x/text/transform.NewReader", "create transform reader"),
    ("golang.org/x/text/transform.NewWriter", "create transform writer"),
    ("golang.org/x/text/unicode/norm.NFC.String", "NFC normalize string"),
    ("golang.org/x/text/unicode/norm.NFD.String", "NFD normalize string"),
    ("golang.org/x/text/unicode/norm.NFKC.String", "NFKC normalize string"),
    ("golang.org/x/text/unicode/norm.NFKD.String", "NFKD normalize string"),
]:
    add(fn, "go-x", purpose, "go_crypto" if "crypto" in fn else ("go_net" if "net" in fn else "go_string"))

# x/sync
for fn, purpose in [
    ("golang.org/x/sync/errgroup.WithContext", "create error group with context"),
    ("golang.org/x/sync/semaphore.NewWeighted", "create weighted semaphore"),
    ("golang.org/x/sync/singleflight.(*Group).Do", "deduplicate function calls"),
    ("golang.org/x/sync/singleflight.(*Group).DoChan", "deduplicate with channel"),
    ("golang.org/x/sync/singleflight.(*Group).Forget", "forget singleflight key"),
]:
    add(fn, "go-x-sync", purpose, "go_sync")

for method, purpose in [
    ("Go", "launch goroutine with error tracking"),
    ("SetLimit", "set concurrency limit"),
    ("Wait", "wait for all goroutines"),
]:
    add_method("golang.org/x/sync/errgroup", "Group", method, "go-x-sync", purpose, "go_sync")

for method, purpose in [
    ("Acquire", "acquire semaphore"),
    ("Release", "release semaphore"),
    ("TryAcquire", "try acquire semaphore"),
]:
    add_method("golang.org/x/sync/semaphore", "Weighted", method, "go-x-sync", purpose, "go_sync")

# x/time/rate
add("golang.org/x/time/rate.NewLimiter", "go-x-time", "create rate limiter", "go_time")
for method, purpose in [
    ("Allow", "check rate limit"),
    ("AllowN", "check N events allowed"),
    ("Burst", "get burst size"),
    ("Limit", "get rate limit"),
    ("Reserve", "reserve rate limit"),
    ("ReserveN", "reserve N events"),
    ("SetBurst", "set burst size"),
    ("SetBurstAt", "set burst at time"),
    ("SetLimit", "set rate limit"),
    ("SetLimitAt", "set limit at time"),
    ("Tokens", "get available tokens"),
    ("TokensAt", "get tokens at time"),
    ("Wait", "wait for rate limit"),
    ("WaitN", "wait for N events"),
]:
    add_method("golang.org/x/time/rate", "Limiter", method, "go-x-time", purpose, "go_time")

# --- github.com/gorilla/websocket ---
ws_pkg = "github.com/gorilla/websocket"
for fn, purpose in [
    ("DefaultDialer.Dial", "websocket dial"),
    ("DefaultDialer.DialContext", "websocket dial with context"),
    ("IsCloseError", "check websocket close error"),
    ("IsUnexpectedCloseError", "check unexpected close"),
    ("IsWebSocketUpgrade", "check websocket upgrade"),
    ("NewPreparedMessage", "create prepared message"),
    ("Subprotocols", "get subprotocols"),
    ("Upgrade", "upgrade HTTP to websocket"),
]:
    add_func(ws_pkg, fn, "gorilla-websocket", purpose, "go_net")

for method, purpose in [
    ("Close", "close websocket"),
    ("CloseHandler", "get close handler"),
    ("EnableWriteCompression", "enable write compression"),
    ("LocalAddr", "get local address"),
    ("NextReader", "get next message reader"),
    ("NextWriter", "get next message writer"),
    ("PingHandler", "get ping handler"),
    ("PongHandler", "get pong handler"),
    ("ReadJSON", "read JSON message"),
    ("ReadMessage", "read websocket message"),
    ("RemoteAddr", "get remote address"),
    ("SetCloseHandler", "set close handler"),
    ("SetCompressionLevel", "set compression level"),
    ("SetPingHandler", "set ping handler"),
    ("SetPongHandler", "set pong handler"),
    ("SetReadDeadline", "set read deadline"),
    ("SetReadLimit", "set read limit"),
    ("SetWriteDeadline", "set write deadline"),
    ("Subprotocol", "get negotiated subprotocol"),
    ("UnderlyingConn", "get underlying connection"),
    ("WriteControl", "write control message"),
    ("WriteJSON", "write JSON message"),
    ("WriteMessage", "write websocket message"),
    ("WritePreparedMessage", "write prepared message"),
]:
    add_method(ws_pkg, "Conn", method, "gorilla-websocket", purpose, "go_net")

for method, purpose in [
    ("CheckOrigin", "check origin"),
    ("Upgrade", "upgrade to websocket"),
]:
    add_method(ws_pkg, "Upgrader", method, "gorilla-websocket", purpose, "go_net")

# --- github.com/dgrijalva/jwt-go / github.com/golang-jwt/jwt ---
for pkg in ["github.com/dgrijalva/jwt-go", "github.com/golang-jwt/jwt/v5"]:
    lib = "jwt-go" if "dgrijalva" in pkg else "golang-jwt"
    for fn, purpose in [
        ("New", "create new JWT token"),
        ("NewWithClaims", "create JWT with claims"),
        ("Parse", "parse JWT string"),
        ("ParseWithClaims", "parse JWT with claims"),
        ("SigningMethodHS256.Sign", "HMAC-SHA256 sign"),
        ("SigningMethodHS384.Sign", "HMAC-SHA384 sign"),
        ("SigningMethodHS512.Sign", "HMAC-SHA512 sign"),
        ("SigningMethodRS256.Sign", "RSA-SHA256 sign"),
        ("SigningMethodRS384.Sign", "RSA-SHA384 sign"),
        ("SigningMethodRS512.Sign", "RSA-SHA512 sign"),
        ("SigningMethodES256.Sign", "ECDSA-SHA256 sign"),
        ("SigningMethodES384.Sign", "ECDSA-SHA384 sign"),
        ("SigningMethodES512.Sign", "ECDSA-SHA512 sign"),
    ]:
        add_func(pkg, fn, lib, purpose, "go_crypto")

# --- github.com/docker/docker ---
docker_pkg = "github.com/docker/docker/client"
for fn, purpose in [
    ("NewClientWithOpts", "create Docker client"),
    ("NewEnvClient", "create Docker client from env"),
    ("FromEnv", "Docker client option from env"),
    ("WithAPIVersionNegotiation", "enable API version negotiation"),
    ("WithHost", "set Docker host"),
    ("WithTLSClientConfig", "set Docker TLS config"),
]:
    add_func(docker_pkg, fn, "docker-client", purpose, "go_container")

for method, purpose in [
    ("Close", "close Docker client"),
    ("ContainerAttach", "attach to container"),
    ("ContainerCommit", "commit container"),
    ("ContainerCreate", "create container"),
    ("ContainerExecAttach", "attach to exec"),
    ("ContainerExecCreate", "create exec"),
    ("ContainerExecInspect", "inspect exec"),
    ("ContainerExecStart", "start exec"),
    ("ContainerInspect", "inspect container"),
    ("ContainerKill", "kill container"),
    ("ContainerList", "list containers"),
    ("ContainerLogs", "get container logs"),
    ("ContainerPause", "pause container"),
    ("ContainerRemove", "remove container"),
    ("ContainerResize", "resize container TTY"),
    ("ContainerRestart", "restart container"),
    ("ContainerStart", "start container"),
    ("ContainerStats", "get container stats"),
    ("ContainerStop", "stop container"),
    ("ContainerTop", "get container processes"),
    ("ContainerUnpause", "unpause container"),
    ("ContainerWait", "wait for container"),
    ("CopyFromContainer", "copy from container"),
    ("CopyToContainer", "copy to container"),
    ("ImageBuild", "build Docker image"),
    ("ImageList", "list Docker images"),
    ("ImagePull", "pull Docker image"),
    ("ImagePush", "push Docker image"),
    ("ImageRemove", "remove Docker image"),
    ("ImageTag", "tag Docker image"),
    ("Info", "get Docker info"),
    ("NetworkCreate", "create network"),
    ("NetworkInspect", "inspect network"),
    ("NetworkList", "list networks"),
    ("NetworkRemove", "remove network"),
    ("Ping", "ping Docker daemon"),
    ("ServerVersion", "get Docker version"),
    ("VolumeCreate", "create volume"),
    ("VolumeInspect", "inspect volume"),
    ("VolumeList", "list volumes"),
    ("VolumeRemove", "remove volume"),
]:
    add_method(docker_pkg, "Client", method, "docker-client", purpose, "go_container")

# --- k8s.io/client-go (Kubernetes) ---
k8s_pkg = "k8s.io/client-go"
for fn, purpose in [
    (f"{k8s_pkg}/kubernetes.NewForConfig", "create Kubernetes clientset"),
    (f"{k8s_pkg}/kubernetes.NewForConfigOrDie", "create clientset or die"),
    (f"{k8s_pkg}/rest.InClusterConfig", "get in-cluster config"),
    (f"{k8s_pkg}/tools/clientcmd.BuildConfigFromFlags", "build config from flags"),
    (f"{k8s_pkg}/tools/clientcmd.NewDefaultClientConfigLoadingRules", "default config loading"),
    (f"{k8s_pkg}/tools/clientcmd.NewNonInteractiveDeferredLoadingClientConfig", "deferred loading config"),
    (f"{k8s_pkg}/tools/cache.NewInformer", "create Kubernetes informer"),
    (f"{k8s_pkg}/tools/cache.NewSharedIndexInformer", "create shared index informer"),
    (f"{k8s_pkg}/tools/cache.WaitForCacheSync", "wait for informer cache sync"),
    (f"{k8s_pkg}/tools/leaderelection.RunOrDie", "run leader election"),
    (f"{k8s_pkg}/tools/record.NewBroadcaster", "create event broadcaster"),
    (f"{k8s_pkg}/util/homedir.HomeDir", "get home directory"),
    (f"{k8s_pkg}/util/retry.RetryOnConflict", "retry on conflict"),
]:
    add(fn, "k8s-client-go", purpose, "go_k8s")

# --- github.com/hashicorp/consul ---
for fn, purpose in [
    ("github.com/hashicorp/consul/api.NewClient", "create Consul client"),
    ("github.com/hashicorp/consul/api.DefaultConfig", "default Consul config"),
]:
    add(fn, "consul", purpose, "go_cloud")

# --- github.com/hashicorp/vault ---
for fn, purpose in [
    ("github.com/hashicorp/vault/api.NewClient", "create Vault client"),
    ("github.com/hashicorp/vault/api.DefaultConfig", "default Vault config"),
]:
    add(fn, "vault", purpose, "go_crypto")

# --- github.com/nats-io/nats.go ---
nats_pkg = "github.com/nats-io/nats.go"
for fn, purpose in [
    ("Connect", "connect to NATS server"),
    ("GetDefaultOptions", "get default NATS options"),
]:
    add_func(nats_pkg, fn, "nats", purpose, "go_messaging")

for method, purpose in [
    ("Close", "close NATS connection"),
    ("Drain", "drain NATS connection"),
    ("Flush", "flush NATS connection"),
    ("Publish", "publish NATS message"),
    ("PublishMsg", "publish NATS message object"),
    ("QueueSubscribe", "queue subscribe"),
    ("Request", "request-reply"),
    ("RequestMsg", "request-reply with message"),
    ("Subscribe", "subscribe to subject"),
    ("ChanSubscribe", "subscribe with channel"),
]:
    add_method(nats_pkg, "Conn", method, "nats", purpose, "go_messaging")

# --- github.com/Shopify/sarama (Kafka) ---
sarama_pkg = "github.com/Shopify/sarama"
for fn, purpose in [
    ("NewAsyncProducer", "create async Kafka producer"),
    ("NewClient", "create Kafka client"),
    ("NewConfig", "create Kafka config"),
    ("NewConsumer", "create Kafka consumer"),
    ("NewConsumerGroup", "create consumer group"),
    ("NewSyncProducer", "create sync Kafka producer"),
]:
    add_func(sarama_pkg, fn, "sarama", purpose, "go_messaging")

# --- github.com/olivere/elastic (Elasticsearch) ---
elastic_pkg = "github.com/olivere/elastic/v7"
for fn, purpose in [
    ("NewClient", "create Elasticsearch client"),
    ("NewBoolQuery", "create bool query"),
    ("NewMatchQuery", "create match query"),
    ("NewTermQuery", "create term query"),
    ("NewRangeQuery", "create range query"),
    ("NewMatchAllQuery", "create match all query"),
    ("NewMultiMatchQuery", "create multi match query"),
    ("NewNestedQuery", "create nested query"),
    ("NewWildcardQuery", "create wildcard query"),
    ("NewRegexpQuery", "create regexp query"),
    ("NewFuzzyQuery", "create fuzzy query"),
]:
    add_func(elastic_pkg, fn, "elastic", purpose, "go_database")

# --- github.com/go-playground/validator ---
validator_pkg = "github.com/go-playground/validator/v10"
for fn, purpose in [
    ("New", "create validator"),
]:
    add_func(validator_pkg, fn, "validator", purpose, "go_validation")

for method, purpose in [
    ("RegisterCustomTypeFunc", "register custom type"),
    ("RegisterStructValidation", "register struct validation"),
    ("RegisterValidation", "register custom validation"),
    ("Struct", "validate struct"),
    ("StructExcept", "validate struct except fields"),
    ("StructFiltered", "validate filtered struct"),
    ("StructPartial", "validate partial struct"),
    ("Var", "validate variable"),
    ("VarWithValue", "validate variable with value"),
]:
    add_method(validator_pkg, "Validate", method, "validator", purpose, "go_validation")

# --- github.com/mitchellh/mapstructure ---
for fn, purpose in [
    ("Decode", "decode map to struct"),
    ("NewDecoder", "create mapstructure decoder"),
    ("WeakDecode", "weak decode map to struct"),
]:
    add_func("github.com/mitchellh/mapstructure", fn, "mapstructure", purpose, "go_encoding")

# --- github.com/pelletier/go-toml ---
for fn, purpose in [
    ("Marshal", "TOML marshal"),
    ("Unmarshal", "TOML unmarshal"),
    ("Load", "load TOML string"),
    ("LoadFile", "load TOML file"),
]:
    add_func("github.com/pelletier/go-toml/v2", fn, "go-toml", purpose, "go_encoding")

# --- gopkg.in/yaml.v3 ---
for fn, purpose in [
    ("Marshal", "YAML marshal"),
    ("Unmarshal", "YAML unmarshal"),
    ("NewDecoder", "create YAML decoder"),
    ("NewEncoder", "create YAML encoder"),
]:
    add_func("gopkg.in/yaml.v3", fn, "yaml-v3", purpose, "go_encoding")

# --- github.com/fatih/color ---
for fn, purpose in [
    ("New", "create color printer"),
    ("BlackString", "format black string"),
    ("BlueString", "format blue string"),
    ("CyanString", "format cyan string"),
    ("GreenString", "format green string"),
    ("HiBlackString", "format bright black string"),
    ("HiBlueString", "format bright blue string"),
    ("HiCyanString", "format bright cyan string"),
    ("HiGreenString", "format bright green string"),
    ("HiMagentaString", "format bright magenta string"),
    ("HiRedString", "format bright red string"),
    ("HiWhiteString", "format bright white string"),
    ("HiYellowString", "format bright yellow string"),
    ("MagentaString", "format magenta string"),
    ("RedString", "format red string"),
    ("WhiteString", "format white string"),
    ("YellowString", "format yellow string"),
    ("NoColor", "disable color output"),
    ("Unset", "unset color"),
]:
    add_func("github.com/fatih/color", fn, "fatih-color", purpose, "go_cli")

# --- github.com/urfave/cli ---
for fn, purpose in [
    ("NewApp", "create CLI app"),
]:
    add_func("github.com/urfave/cli/v2", fn, "urfave-cli", purpose, "go_cli")

# --- Additional commonly-seen Go internal functions that appear in binaries ---

# runtime/cgo
for fn, purpose in [
    ("runtime/cgo._cgo_init", "cgo initialization"),
    ("runtime/cgo._cgo_thread_start", "cgo thread start"),
    ("runtime/cgo._cgo_callers", "cgo callers"),
    ("runtime/cgo._cgo_notify_runtime_init_done", "cgo runtime init done"),
    ("runtime/cgo._cgo_set_context_function", "cgo set context function"),
    ("runtime/cgo._cgo_yield", "cgo yield"),
    ("runtime/cgo.crosscall2", "cgo crosscall C to Go"),
    ("runtime/cgo.crosscall_amd64", "cgo crosscall amd64"),
    ("runtime/cgo.crosscall_arm64", "cgo crosscall arm64"),
]:
    add(fn, "go-cgo", purpose, "go_runtime")

# type.* and go.* symbols
for fn, purpose in [
    ("type.eq", "type equality check"),
    ("type.hash", "type hash function"),
    ("go.buildid", "Go build identifier"),
    ("go.string.*", "Go string constant"),
    ("go.func.*", "Go function metadata"),
    ("go.info.*", "Go type info metadata"),
    ("go.loc.*", "Go location metadata"),
    ("go.range.*", "Go range metadata"),
    ("go.stmp.*", "Go string temp"),
    ("go.itab.*", "Go interface table entry"),
    ("go.shape.*", "Go generic shape type"),
    ("main.main", "Go program entry point"),
    ("main.init", "Go main package init"),
    ("main.init.0", "Go main init function 0"),
]:
    add(fn, "go-runtime", purpose, "go_runtime")

# Common init functions pattern
for pkg in ["fmt", "os", "io", "net", "sync", "time", "strings", "bytes", "strconv",
            "encoding/json", "encoding/xml", "encoding/binary", "crypto/tls",
            "crypto/x509", "net/http", "database/sql", "html/template",
            "text/template", "regexp", "sort", "log", "flag", "testing",
            "compress/gzip", "compress/flate", "compress/zlib", "context",
            "errors", "path/filepath", "math", "math/big", "math/rand",
            "reflect", "unsafe", "bufio", "unicode/utf8", "unicode"]:
    add(f"{pkg}.init", f"go-{pkg.split('/')[0]}", f"package {pkg} initialization", "go_runtime")
    add(f"{pkg}.init.0", f"go-{pkg.split('/')[0]}", f"package {pkg} init function 0", "go_runtime")

# --- Additional runtime functions seen in real Go binaries ---
extra_runtime = [
    ("gcDrain", "drain GC mark work"), ("gcFlushBgCredit", "flush BG credit"),
    ("pollWork", "check for poll work"), ("netpoll", "network poller"),
    ("netpollBreak", "break network poller"), ("netpollGenericInit", "init network poller"),
    ("netpollInit", "init platform network poller"), ("netpollinited", "check poller initialized"),
    ("netpollIsPollDescriptor", "check poll descriptor"), ("netpollReady", "signal poll ready"),
    ("netpollBlock", "block on poll"), ("netpollUnblock", "unblock poll"),
    ("netpollWait", "wait on network poll"), ("netpollWaitCanceled", "canceled poll wait"),
    ("netpollopen", "open poll descriptor"), ("netpollclose", "close poll descriptor"),
    ("netpollarm", "arm poll descriptor"),
    ("epollcreate", "epoll create (Linux)"), ("epollcreate1", "epoll create1 (Linux)"),
    ("epollctl", "epoll control (Linux)"), ("epollwait", "epoll wait (Linux)"),
    ("kqueue", "kqueue create (BSD/macOS)"), ("kevent", "kqueue event (BSD/macOS)"),
    ("closeonexec", "set close-on-exec"),
    ("cpuinit", "CPU feature detection"), ("getproccount", "get CPU count"),
    ("procPin", "pin to proc"), ("procUnpin", "unpin from proc"),
    ("casgstatus", "CAS goroutine status"), ("casGToWaiting", "set G waiting"),
    ("gfget", "get free goroutine"), ("gfput", "put free goroutine"),
    ("gfpurge", "purge free goroutines"),
    ("acquireSudog", "acquire sudog for channel"), ("releaseSudog", "release sudog"),
    ("newstack", "allocate new stack"), ("nilfunc", "nil function call"),
    ("mProf_Malloc", "malloc profiling"), ("mProf_Free", "free profiling"),
    ("mProf_Flush", "flush profiling"), ("mProf_FlushLocked", "flush profiling locked"),
    ("mProf_PostSweep", "post-sweep profiling"), ("mProf_NextCycle", "next profiling cycle"),
    ("blocksampled", "sampled block event"), ("saveblockevent", "save block event"),
    ("traceGomaxprocs", "trace GOMAXPROCS change"), ("traceGCStart", "trace GC start"),
    ("traceGCDone", "trace GC done"), ("traceGCSweepStart", "trace GC sweep start"),
    ("traceGCSweepDone", "trace GC sweep done"), ("traceGCSweepSpan", "trace GC sweep span"),
    ("traceGoCreate", "trace goroutine create"), ("traceGoEnd", "trace goroutine end"),
    ("traceGoSched", "trace goroutine schedule"), ("traceGoStart", "trace goroutine start"),
    ("traceGoSysBlock", "trace goroutine syscall block"),
    ("traceGoSysCall", "trace goroutine syscall"), ("traceGoSysExit", "trace syscall exit"),
    ("traceGoUnpark", "trace goroutine unpark"), ("traceProcStart", "trace proc start"),
    ("traceProcStop", "trace proc stop"), ("traceEvent", "trace runtime event"),
    ("traceAcquire", "trace acquire"), ("traceRelease", "trace release"),
    ("traceFlush", "flush trace buffer"), ("traceReader", "trace reader goroutine"),
    ("traceString", "trace register string"),
    ("typesEqual", "check types equal"), ("typehash", "hash type"),
    ("ifaceIndir", "check indirect interface"), ("getitab", "get interface table"),
    ("hashInit", "initialize hash"), ("fastrand", "fast random number"),
    ("fastrandn", "fast random number [0,n)"), ("fastrand64", "fast random 64-bit"),
    ("abs", "absolute value"),
    ("cmpstring", "compare strings"), ("findnull", "find null in byte slice"),
    ("gostringnocopy", "create string without copy"), ("gostring", "create Go string"),
    ("intstring", "int to string"), ("rawmem", "raw memory access"),
    ("add", "pointer add"), ("noescape", "prevent escape analysis"),
]
for fn, purpose in extra_runtime:
    add(f"runtime.{fn}", "go-runtime", purpose, "go_runtime")


# =============================================================================
# PART 4: Generate method variants for common receivers
# =============================================================================

# Many Go stdlib types have methods that follow patterns.
# Generate common io.Reader/Writer/Closer methods for many types
io_types = [
    ("os", "File"), ("net", "TCPConn"), ("net", "UDPConn"),
    ("crypto/tls", "Conn"), ("compress/gzip", "Reader"),
    ("compress/gzip", "Writer"), ("compress/flate", "Writer"),
    ("compress/zlib", "Writer"),
    ("encoding/json", "Decoder"), ("encoding/json", "Encoder"),
    ("encoding/xml", "Decoder"), ("encoding/xml", "Encoder"),
    ("bufio", "Reader"), ("bufio", "Writer"),
    ("net/http", "Client"), ("net/http", "Server"),
    ("net/http", "Transport"),
]

# =============================================================================
# PART 5: Write output
# =============================================================================
print(f"Total Go signatures generated: {len(sigs)}")

# Verify categories
cats = {}
for v in sigs.values():
    cats[v["category"]] = cats.get(v["category"], 0) + 1
for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {count}")

# Write JSON
out_path = Path("/Users/apple/Desktop/black-widow/sigs/go_stdlib_signatures.json")
out_path.parent.mkdir(parents=True, exist_ok=True)

with open(out_path, "w") as f:
    json.dump(sigs, f, indent=2, ensure_ascii=False)

print(f"\nWritten to: {out_path}")
print(f"File size: {out_path.stat().st_size / 1024:.1f} KB")
