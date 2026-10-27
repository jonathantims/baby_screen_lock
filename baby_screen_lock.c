/*
 * Baby screen lock.
 *
 * A fullscreen topmost overlay plus low-level keyboard and mouse hooks.
 * Physical input is eaten so a toddler can mash the machine during a call.
 * Hold Z and M together to leave. Touchpad gestures that the hooks cannot
 * see are undone by a watchdog. A window-event hook posts a repair as soon
 * as focus, move, switch, minimize, or the virtual desktop changes, and a
 * 250 ms timer repeats that check. The repair forces the lock back to
 * fullscreen. Other windows are corrected with as few messages as possible:
 * only a placement that drifted, and only the z-order moves outside the
 * longest run that is already in snapshot order. Those messages go to one
 * window at a time. Normal placements are written first, then maximized
 * placements, then z-order. Each show brings that window forward, so the
 * z-order pass runs after the last show and puts the snapshot order back.
 * It does not clear a maximized window. A move under another snapshot
 * window is inserted after that window. The top snapshot window is
 * inserted after the lock: HWND_TOP with SWP_NOACTIVATE returns success
 * and does not move a window while the lock is the foreground window.
 * If that insert does not land, the window is promoted and immediately
 * dropped back to the top of the ordinary band, and the lock and the hint
 * are raised again. Those calls keep SWP_NOACTIVATE, so the lock keeps
 * the foreground. If the stack is still wrong after an attempt, the next
 * attempt waits longer between windows and moves only the ones still out
 * of place, so a slow window can finish before the next instruction.
 * The lock takes the foreground before the z-order moves so the window
 * a swipe focused does not stay active.
 * A virtual-desktop swipe is walked back with Ctrl+Win+Left /
 * Ctrl+Win+Right on the 250 ms timer only, so a burst of events cannot
 * run that walk faster than the animation.
 * A trace file, baby_screen_lock_log.txt, is created next to the exe.
 * It records the launch z-order and the live z-order after each restore
 * step, with the show state of every tracked window, so a minimize-all
 * run can be read back afterwards. Idle watchdog ticks are not logged.
 *
 * This file is the whole program: the decisions, the bump allocator, the
 * GUI, and the fuzzing self-test. It includes no system header. The link
 * is /NODEFAULTLIB, so there is no C runtime and no __chkstk.
 * WinMainCRTStartup commits the stack with commit_stack_pages before any
 * other work. A command line that contains --self-test runs the fuzz and
 * writes out\self_test.txt instead of locking the screen.
 *
 * Memory is two VirtualAlloc blocks, both reserved and committed up front.
 * Windows supplies physical pages when those bytes are first written, so the
 * large sizes cost address space and commit charge, not a pile of resident
 * RAM. Each block has a bump cursor that refuses to walk past the end.
 *
 *   Permanent block (64 MiB). LockPermanent is a static layout at the front.
 *   The tracked-window table and the exit-hint string are bump-allocated
 *   after it. That bump is never reset and the block is never freed. The
 *   process exit throws the address space away faster than a walk of frees.
 *
 *   Tick block (16 MiB). One planning visit bump-allocates its observation
 *   list, the tracked Z-order walk, and the scratch for the move plan.
 *   The cursor is set back to zero when that plan has been copied into the
 *   fixed pace tables. Those tables have to outlive the visit: a timer
 *   sends one window instruction at a time. The block itself stays. That
 *   is the free for a long-lived GUI: drop a scope, do not return the
 *   block to the kernel between visits.
 *
 * The low-level keyboard and mouse hooks are removed on the way out.
 * They run on this thread, and ExitProcess does not pump, so a key or
 * click that arrives while they are still installed stalls the desktop
 * until the system times the hook out. The window-event hook, the cursor
 * show count, and the arenas are not released here. Process rundown
 * reclaims them in one kernel pass.
 */

/*
 * Decisions, bump arenas, and the permanent memory layout.
 *
 * The functions below are static. This file is one translation unit, with
 * no extra object file and no C runtime. Nothing in this section calls
 * Win32. The window procedure and the hooks further down call these.
 *
 * Two kinds of memory sit on top of these helpers:
 *
 *   Permanent. A struct laid over the front of a block, plus a bump cursor
 *   over the bytes after that struct. The tracked-window table and the exit
 *   hint live there until the process ends. Nothing here frees them.
 *   Resetting that cursor would throw away the table, so callers leave
 *   the permanent bump alone.
 *
 *   Per operation. A second bump whose caller resets the cursor to zero when
 *   the operation (one watchdog tick) is finished. The bytes stay reserved
 *   for the next tick.
 */

/* How many user top-level windows the snapshot table can hold. */
#define LOCK_MAX_TRACKED 512

/* snapshot_classify results. */
#define LOCK_SNAP_STOP 0
#define LOCK_SNAP_SKIP 1
#define LOCK_SNAP_TAKE 2

/* Key transitions the low-level hook reports, collapsed to three values. */
#define LOCK_KEY_DOWN 1
#define LOCK_KEY_UP 2
#define LOCK_KEY_OTHER 0

/* Virtual-key codes the chord and the desktop switch use. */
#define LOCK_VK_Z 0x5Au
#define LOCK_VK_M 0x4Du
#define LOCK_VK_CONTROL 0x11u
#define LOCK_VK_LWIN 0x5Bu
#define LOCK_VK_LEFT 0x25u
#define LOCK_VK_RIGHT 0x27u

/* Virtual-desktop sweep. Phase values and the caps from the original walk. */
#define LOCK_VD_PHASE_HOME 0
#define LOCK_VD_PHASE_LEFT 1
#define LOCK_VD_PHASE_RIGHT 2
#define LOCK_VD_LEFT_CAP 8
#define LOCK_VD_TOTAL_CAP 64

/* What the desktop-manager query told us on this check. */
#define LOCK_VD_QUERY_FAILED 0
#define LOCK_VD_ON_CURRENT 1
#define LOCK_VD_ON_OTHER 2

/* What the sweep wants the caller to inject. NONE includes "give up". */
#define LOCK_VD_ACT_NONE 0
#define LOCK_VD_ACT_LEFT 1
#define LOCK_VD_ACT_RIGHT 2

/* Ctrl+Win+Arrow is six events: three downs, then three ups. */
#define LOCK_STROKE_COUNT 6

/* Hint pill geometry, in pixels. It is centered on the top edge. */
#define LOCK_HINT_W 280
#define LOCK_HINT_H 32
#define LOCK_HINT_Y 5

/* WM_TOUCH. Compared by message_is_touch so the pump can drop the packet. */
#define LOCK_WM_TOUCH 0x0240u

/*
 * WinEvents that mean a touchpad gesture changed the desktop.
 * A three-finger swipe switches the foreground window without moving it.
 * Task View and show-desktop also raise SWITCH and MINIMIZE. The hook
 * range is wider than this list; lock_event_needs_repair drops the rest.
 */
#define LOCK_EVENT_FOREGROUND 0x0003u
#define LOCK_EVENT_MOVESIZESTART 0x000Au
#define LOCK_EVENT_MOVESIZEEND 0x000Bu
#define LOCK_EVENT_SWITCHSTART 0x0014u
#define LOCK_EVENT_SWITCHEND 0x0015u
#define LOCK_EVENT_MINIMIZESTART 0x0016u
#define LOCK_EVENT_MINIMIZEEND 0x0017u
#define LOCK_EVENT_DESKTOPSWITCH 0x0020u

/* Gap before each window instruction on the first repair attempt, in ms.
   Later attempts double this until LOCK_Z_DELAY_MAX_MS. */
#define LOCK_Z_DELAY_BASE_MS 40

/* Longest gap between window instructions. Slow windows settle inside this. */
#define LOCK_Z_DELAY_MAX_MS 640

/* Highest attempt index. The delay stops growing here and stays at the max. */
#define LOCK_Z_ATTEMPT_CAP 4

/* SW_SHOWMAXIMIZED. The same value as SW_MAXIMIZE. A window whose snapshot
   uses this show command is restored after the normal placements and before
   z-order. A later SetWindowPos with SWP_NOMOVE and SWP_NOSIZE leaves the
   maximized state in place. */
#define LOCK_SHOW_MAXIMIZED 3

/* lock_placement_move_slots filter. NORMAL skips maximized snapshots.
   MAXIMIZED lists only those, so the caller can restore them after the
   normal placements and before the z-order pass. */
#define LOCK_PLACE_NORMAL 0
#define LOCK_PLACE_MAXIMIZED 1

/* Cursor over a caller-owned byte range. Allocation only advances `used`. */
typedef struct LockBump {
    /* First byte of the range. Null means every allocation fails. */
    unsigned char *base;

    /* Strict ceiling, in bytes. bump_alloc never hands out past this. */
    unsigned long long capacity;

    /* Next free offset. Resetting an operation arena stores zero here. */
    unsigned long long used;
} LockBump;

/* Z and M latch for the exit chord. One means that key is currently down. */
typedef struct LockKeyLatch {
    /* Physical Z is down. Injected Z does not change this. */
    int zHeld;

    /* Physical M is down. Injected M does not change this. */
    int mHeld;
} LockKeyLatch;

/* What the keyboard hook should do with one event. */
typedef struct LockKeyDecision {
    /* 1: call the next hook and return its result. The event is not eaten. */
    int callNext;

    /* 1: return 1 from the hook so the event never reaches other programs. */
    int swallow;

    /* 1: Z and M are both down after this event, so the lock should close. */
    int requestExit;
} LockKeyDecision;

/*
 * Snapshot of one WINDOWPLACEMENT.
 * The watchdog treats the window as moved when showCmd or the restored
 * rectangle changes. flags and the min/max points are kept so a restore
 * can write the original placement back whole.
 */
typedef struct LockPlacement {
    /* Show command captured with the window: normal, minimized, maximized. */
    int showCmd;

    /* WINDOWPLACEMENT.flags, written back unchanged and not compared. */
    int flags;

    /* X of the minimized position, written back unchanged and not compared. */
    int minX;

    /* Y of the minimized position, written back unchanged and not compared. */
    int minY;

    /* X of the maximized position, written back unchanged and not compared. */
    int maxX;

    /* Y of the maximized position, written back unchanged and not compared. */
    int maxY;

    /* Left edge of the restored (normal) rectangle, in screen pixels. */
    int left;

    /* Top edge of the restored rectangle, in screen pixels. */
    int top;

    /* Right edge of the restored rectangle, in screen pixels. */
    int right;

    /* Bottom edge of the restored rectangle, in screen pixels. */
    int bottom;
} LockPlacement;

/* One user window remembered from the launch snapshot. */
typedef struct LockTrackedSlot {
    /* HWND stored as an opaque pointer. This section never calls Win32 on it. */
    void *hwnd;

    /* Placement to put back if a gesture moves or minimizes this window. */
    LockPlacement place;
} LockTrackedSlot;

/* What the watchdog observed for one tracked slot on this tick. */
typedef struct LockObserved {
    /* 1 if the HWND still exists and GetWindowPlacement succeeded. */
    int alive;

    /* Current placement. Compared only when alive is 1. */
    LockPlacement place;
} LockObserved;

/* Facts the enumerator gathered for one top-level window. */
typedef struct LockWindowFacts {
    /* 1 if this HWND is the fullscreen lock window itself. */
    int isSelf;

    /* 1 if this HWND is the small exit-hint window. */
    int isHint;

    /* 1 if the window is visible. Hidden windows are not part of the desktop. */
    int visible;

    /* 1 if GetWindow(GW_OWNER) returned an owner. Owned popups are skipped. */
    int hasOwner;

    /* 1 if WS_EX_TOOLWINDOW is set. Tool windows are skipped unless they are also app windows. */
    int isToolWindow;

    /* 1 if WS_EX_APPWINDOW is set. Combined with isToolWindow, this keeps Alt+Tab tools. */
    int isAppWindow;

    /* Character count from GetWindowTextLengthW. Empty titles are skipped. */
    int titleLength;

    /* 1 if GetWindowPlacement filled a placement we can store. */
    int placementOk;
} LockWindowFacts;

/* Progress of the walk back to the lock's original virtual desktop. */
typedef struct LockVdSweep {
    /* HOME, LEFT, or RIGHT. HOME means the lock is on the current desktop. */
    int phase;

    /* How many Ctrl+Win+Left chords have been injected in this walk. */
    int leftSteps;

    /* Left steps plus right steps. The walk stops at LOCK_VD_TOTAL_CAP. */
    int totalSteps;
} LockVdSweep;

/* One key of the injected desktop-switch chord. */
typedef struct LockKeyStroke {
    /* Virtual-key code: left win, control, or an arrow. */
    unsigned int vk;

    /* 0 for a key-down event, 1 for a key-up event. */
    int keyUp;
} LockKeyStroke;

/* What ReassertLock should do to the lock window and the hint window. */
typedef struct LockReassert {
    /* 1 if the lock window is minimized and ShowWindow(SW_RESTORE) is required. */
    int unminimize;

    /* 1 if the lock window exists and should be forced fullscreen and topmost. */
    int reposition;

    /* 1 if the hint window exists and should be raised above the lock. */
    int raiseHint;
} LockReassert;

/* Pixel rectangle of the exit-hint pill. */
typedef struct LockHintRect {
    /* Left edge, in screen pixels. May be negative when the screen is narrower than the pill. */
    int x;

    /* Top edge, in screen pixels. This is LOCK_HINT_Y. */
    int y;

    /* Width in pixels. This is LOCK_HINT_W. */
    int w;

    /* Height in pixels. This is LOCK_HINT_H. */
    int h;
} LockHintRect;

/*
 * Process-lifetime state laid over the front of the permanent block.
 * The tracked table and the exit hint are bump-allocated from `tail`,
 * which covers the bytes after this struct. `tail` is never reset.
 */
typedef struct LockPermanent {
    /* Snapshot table. Points into this same block, after the struct. */
    LockTrackedSlot *tracked;

    /* How many slots in `tracked` hold a window from the launch snapshot. */
    int trackedCount;

    /* Capacity of `tracked`, in slots. The enumerator stops at this count. */
    int trackedCap;

    /* Virtual-desktop walk. Updated only through the sweep helpers. */
    LockVdSweep vd;

    /* Physical Z/M latch for the exit chord. */
    LockKeyLatch keys;

    /* Primary-screen width in pixels, from GetSystemMetrics at launch. */
    int screenW;

    /* Primary-screen height in pixels, from GetSystemMetrics at launch. */
    int screenH;

    /* Watchdog ticks so far. Desktop checks run on even values after increment. */
    int vdTick;

    /* Exit-hint text, copied into this block. Null when exitHintChars is 0. */
    unsigned short *exitHint;

    /* Characters in exitHint, not counting the terminating zero. */
    int exitHintChars;

    /* Bump over the remainder of the permanent block. Never reset, never freed. */
    LockBump tail;
} LockPermanent;

/* Round `value` up to a multiple of `align`. `align` must be a power of two.
   Returns ~0ull when the alignment is unusable or the rounded value would wrap. */
static unsigned long long lock_align_up(unsigned long long value, unsigned long long align) {
    unsigned long long mask;

    /* Reject a zero or a non-power-of-two. Callers treat ~0ull as failure. */
    if (align == 0ull || (align & (align - 1ull)) != 0ull) {
        return ~0ull;
    }

    mask = align - 1ull;

    /* The add would wrap, so there is no aligned address at or above value. */
    if (value > ~mask) {
        return ~0ull;
    }

    return (value + mask) & ~mask;
}

/* Write `n` zero bytes at `dst`. `dst` may be null only when `n` is zero. */
static void lock_zero(void *dst, unsigned long long n) {
    unsigned char *bytes;
    unsigned long long i;

    bytes = (unsigned char *)dst;

    /* Walk the range one byte at a time. There is no C runtime memset. */
    for (i = 0; i < n; i++) {
        bytes[i] = 0;
    }
}

/* Copy `n` bytes from `src` to `dst`. The ranges must not overlap.
   Either pointer may be null only when `n` is zero. */
static void lock_copy(void *dst, const void *src, unsigned long long n) {
    unsigned char *out;
    const unsigned char *in;
    unsigned long long i;

    out = (unsigned char *)dst;
    in = (const unsigned char *)src;

    /* Byte copy. The compiler memcpy is defined later. This copy does not call it. */
    for (i = 0; i < n; i++) {
        out[i] = in[i];
    }
}

/* Point `bump` at `mem` and set the cursor to zero. A null `bump` is ignored.
   A null `mem` becomes an empty arena that refuses every allocation. */
static void lock_bump_init(LockBump *bump, void *mem, unsigned long long capacity) {
    /* No record to fill. */
    if (!bump) {
        return;
    }

    /* An absent block is stored as an empty arena rather than a crash. */
    if (!mem) {
        bump->base = 0;
        bump->capacity = 0;
        bump->used = 0;
        return;
    }

    /* The caller owns `mem` for `capacity` bytes. The cursor starts at the front. */
    bump->base = (unsigned char *)mem;
    bump->capacity = capacity;
    bump->used = 0;
}

/* Hand out `bytes` from `bump`, aligned up to `align` (a power of two).
   Returns null without moving the cursor when the request does not fit,
   when `bytes` is zero, or when `align` is not a power of two.
   Individual allocations are never freed. A scope drops them with bump_reset. */
static void *lock_bump_alloc(LockBump *bump, unsigned long long bytes, unsigned long long align) {
    unsigned long long mask;
    unsigned long long aligned;

    /* Missing arena, empty request, or a cursor with no backing store. */
    if (!bump || !bump->base || bytes == 0ull) {
        return 0;
    }

    /* Alignment has to be a power of two so the mask math below is exact. */
    if (align == 0ull || (align & (align - 1ull)) != 0ull) {
        return 0;
    }

    mask = align - 1ull;

    /* Rounding the cursor up would wrap past the end of the address space. */
    if (bump->used > ~mask) {
        return 0;
    }

    aligned = (bump->used + mask) & ~mask;

    /* Strict use limit: the object must end at or before `capacity`. */
    if (aligned > bump->capacity || bytes > bump->capacity - aligned) {
        return 0;
    }

    /* Advance past the object. The padding in front of it stays unused. */
    bump->used = aligned + bytes;
    return bump->base + aligned;
}

/* Drop every allocation in an operation arena by moving the cursor to zero.
   The bytes are not cleared and the block is not released. A permanent bump
   must not be passed here: its table would become unreachable. */
static void lock_bump_reset(LockBump *bump) {
    /* Nothing to rewind. */
    if (!bump) {
        return;
    }

    bump->used = 0;
}

/* Bytes handed out so far, including alignment padding. Null returns zero. */
static unsigned long long lock_bump_used(const LockBump *bump) {
    /* A missing bump has handed out nothing. */
    if (!bump) {
        return 0ull;
    }

    return bump->used;
}

/* Clear the exit-chord latch so neither key is considered held. */
static void lock_key_latch_clear(LockKeyLatch *latch) {
    /* No latch yet. Permanent bind calls this only with a real latch. */
    if (!latch) {
        return;
    }

    latch->zHeld = 0;
    latch->mHeld = 0;
}

/* Update the chord latch for one low-level keyboard event and say whether
   the hook should eat it, pass it on, or ask the window to close.
   Injected events and events that are not HC_ACTION leave the latch alone
   and request a pass-through, so the desktop-switch chord can land.
   Physical events are eaten. Z and M update the latch on down and up.
   requestExit is set only when both keys are held after this event. */
static LockKeyDecision lock_key_on_event(LockKeyLatch *latch, int isAction, int isInjected,
                                        int transition, unsigned int vk) {
    LockKeyDecision decision;

    decision.callNext = 0;
    decision.swallow = 0;
    decision.requestExit = 0;

    /* Pass the event on. Our own injected chord uses this path. */
    if (!isAction || isInjected) {
        decision.callNext = 1;
        return decision;
    }

    /* A missing latch still eats the physical key, and it cannot request exit. */
    if (latch) {
        /* Record a physical press of Z or M. Other keys leave the latch as it is. */
        if (transition == LOCK_KEY_DOWN) {
            /* Arm Z. A repeat while it is already down stays down. */
            if (vk == LOCK_VK_Z) {
                latch->zHeld = 1;
            }
            /* Arm M the same way. Z and M can both be set by one check. */
            if (vk == LOCK_VK_M) {
                latch->mHeld = 1;
            }
        /* Record a physical release. A release of a key that was up stays up. */
        } else if (transition == LOCK_KEY_UP) {
            /* Clear Z. Releasing a key that was up leaves it up. */
            if (vk == LOCK_VK_Z) {
                latch->zHeld = 0;
            }
            /* Clear M. */
            if (vk == LOCK_VK_M) {
                latch->mHeld = 0;
            }
        }

        /* Both keys are down together: the documented exit chord. */
        if (latch->zHeld && latch->mHeld) {
            decision.requestExit = 1;
        }
    }

    /* Every physical action is eaten, including the chord that requests exit. */
    decision.swallow = 1;
    return decision;
}

/* 1 if the mouse hook should call the next hook. Low-level mouse actions
   are eaten, so an HC_ACTION event returns 0. Any other nCode returns 1. */
static int lock_mouse_should_call_next(int isAction) {
    /* Eat the action so clicks, moves, and wheels never reach the desktop. */
    if (isAction) {
        return 0;
    }

    /* Let the hook chain see codes other than HC_ACTION. */
    return 1;
}

/* 1 when the two placements differ in show command or normal rectangle.
   A null pointer differs from anything, including another null, so a caller
   with a missing sample does not treat it as "unchanged". */
static int lock_placement_differs(const LockPlacement *a, const LockPlacement *b) {
    /* Missing sample: do not report the placements as equal. */
    if (!a || !b) {
        return 1;
    }

    /* Minimized, maximized, and normal are different arrangements. */
    if (a->showCmd != b->showCmd) {
        return 1;
    }

    /* Any edge of the restored rectangle moved or was resized. */
    if (a->left != b->left || a->top != b->top || a->right != b->right || a->bottom != b->bottom) {
        return 1;
    }

    return 0;
}

/* 1 if any alive observed window differs from its snapshot slot.
   Dead windows (alive == 0) are ignored. A null table with a positive
   count returns 0 so a failed scratch allocation does not force a restore. */
static int lock_windows_need_restore(const LockTrackedSlot *slots, int slotCount,
                                     const LockObserved *observed) {
    int i;

    /* Nothing was tracked, or the caller could not build the observation. */
    if (!slots || !observed || slotCount <= 0) {
        return 0;
    }

    /* One difference is enough. The caller restores only the slots that differ. */
    for (i = 0; i < slotCount; i++) {
        /* A window that is gone cannot have been moved by a gesture. */
        if (!observed[i].alive) {
            continue;
        }

        /* Show command or restored rectangle drifted from the launch snapshot. */
        if (lock_placement_differs(&slots[i].place, &observed[i].place)) {
            return 1;
        }
    }

    return 0;
}

/* 1 when the tracked windows that still appear in `currentTopToBottom`
   are not in snapshot order. The snapshot order is the slot array, index 0
   on top. Handles in the current walk that are not in the snapshot are
   ignored, and snapshot handles missing from the walk are ignored too, so a
   destroyed window does not look like a reorder. A null table or a
   non-positive count returns 0 so a failed walk does not force a restore.
   A repeated handle is reported as a difference. */
static int lock_zorder_differs(const LockTrackedSlot *slots, int slotCount,
                               void **currentTopToBottom, int currentCount) {
    int lastSlot;
    int c;

    /* No snapshot, or the caller could not read a Z-order walk. */
    if (!slots || slotCount <= 0 || !currentTopToBottom || currentCount <= 0) {
        return 0;
    }

    lastSlot = -1;

    /* Each tracked window we meet must sit lower in the snapshot than the one before it. */
    for (c = 0; c < currentCount; c++) {
        int s;
        void *hwnd;

        hwnd = currentTopToBottom[c];

        /* A null entry is a gap in the walk, not a window. */
        if (!hwnd) {
            continue;
        }

        s = 0;
        while (s < slotCount && slots[s].hwnd != hwnd) {
            s += 1;
        }

        /* A window we never snapshotted does not affect the tracked order. */
        if (s == slotCount) {
            continue;
        }

        /* This window was above the previous match in the snapshot, so the stack changed. */
        if (s <= lastSlot) {
            return 1;
        }

        lastSlot = s;
    }

    return 0;
}

/* One z-order instruction. The caller moves `hwnd` to just after `insertAfter`. */
typedef struct LockZMove {
    /* Window to reposition. The planner does not emit a null hwnd. */
    void *hwnd;

    /* Window that should end up immediately above `hwnd`.
       Null means the top of the snapshot. The caller anchors that window
       under its own topmost lock. HWND_TOP with SWP_NOACTIVATE does not
       move a window while that lock is the foreground window. */
    void *insertAfter;
} LockZMove;

/* Milliseconds to wait between window instructions on this attempt.
   Attempt 0 uses the base. Each later attempt doubles the gap until the max.
   A negative attempt is treated as attempt 0. Values past the doubling cap
   stay at the max so a slow window is given time without the wait growing
   without bound. */
static int lock_z_attempt_delay_ms(int attempt) {
    int delay;
    int step;

    /* A negative attempt is the first try, not a longer one. */
    if (attempt < 0) {
        attempt = 0;
    }

    delay = LOCK_Z_DELAY_BASE_MS;

    /* Double once per attempt already spent. Stop before the multiply overflows. */
    for (step = 0; step < attempt; step++) {
        if (delay > LOCK_Z_DELAY_MAX_MS / 2) {
            return LOCK_Z_DELAY_MAX_MS;
        }
        delay *= 2;
    }

    /* The base itself is below the max. This catches a future base above the max. */
    if (delay > LOCK_Z_DELAY_MAX_MS) {
        return LOCK_Z_DELAY_MAX_MS;
    }

    return delay;
}

/* 1 when `slot` appears in the first `n` entries of `slotOf`. */
static int lock_z_slot_seen(const int *slotOf, int n, int slot) {
    int i;

    /* An empty map does not contain the slot. */
    if (!slotOf || n <= 0) {
        return 0;
    }

    /* The map is at most LOCK_MAX_TRACKED. A linear scan is enough. */
    for (i = 0; i < n; i++) {
        if (slotOf[i] == slot) {
            return 1;
        }
    }

    return 0;
}

/* Minimum set of z-order moves that put the tracked windows back in
   snapshot order. Windows already in increasing slot order relative to
   each other are a longest increasing subsequence of the live walk, and
   they are left alone. Every other tracked window that appears in the
   walk is one move: place it just after the nearest lower snapshot slot
   that is also in the walk, or at the top when it is the first of those.
   Moves are emitted in increasing slot order so each predecessor is
   either stable or already listed. A repeated handle in the walk is
   ignored after its first appearance. Unknown handles are ignored.
   Returns the number of moves written. Returns 0 when nothing needs to
   move or the walk is empty, so a failed observation does not restack.
   Returns -1 when the scratch bump cannot hold the plan or `outCap` is
   too small for the moves that are required. */
static int lock_z_minimum_moves(const LockTrackedSlot *slots, int slotCount,
                                void **currentTopToBottom, int currentCount,
                                LockBump *scratch, LockZMove *outMoves, int outCap) {
    int *slotOf;
    int *lisLen;
    int *lisPrev;
    unsigned char *stable;
    int mapped;
    int c;
    int best;
    int moves;
    int s;
    int w;

    /* No snapshot, or the caller could not read a walk. Do not invent moves. */
    if (!slots || slotCount <= 0 || !currentTopToBottom || currentCount <= 0) {
        return 0;
    }

    /* The plan needs scratch and, when there is anything to write, an output. */
    if (!scratch || outCap < 0) {
        return -1;
    }

    slotOf = (int *)lock_bump_alloc(scratch,
                                    (unsigned long long)sizeof(int) * (unsigned long long)currentCount,
                                    4ull);
    lisLen = (int *)lock_bump_alloc(scratch,
                                    (unsigned long long)sizeof(int) * (unsigned long long)currentCount,
                                    4ull);
    lisPrev = (int *)lock_bump_alloc(scratch,
                                     (unsigned long long)sizeof(int) * (unsigned long long)currentCount,
                                     4ull);
    stable = (unsigned char *)lock_bump_alloc(scratch, (unsigned long long)slotCount, 1ull);

    /* A short scratch bump is a failed plan, not a clean stack. */
    if (!slotOf || !lisLen || !lisPrev || !stable) {
        return -1;
    }

    lock_zero(stable, (unsigned long long)slotCount);
    mapped = 0;

    /* Collapse the walk to snapshot slot indexes, first occurrence only. */
    for (c = 0; c < currentCount; c++) {
        int found;
        void *hwnd;

        hwnd = currentTopToBottom[c];

        /* A null entry is a gap, not a window. */
        if (!hwnd) {
            continue;
        }

        found = 0;

        /* Match the handle to the launch table. */
        while (found < slotCount && slots[found].hwnd != hwnd) {
            found += 1;
        }

        /* A window we never snapshotted is not part of the order we restore. */
        if (found == slotCount) {
            continue;
        }

        /* The same window later in the walk would look like a cycle. Keep the first. */
        if (lock_z_slot_seen(slotOf, mapped, found)) {
            continue;
        }

        slotOf[mapped] = found;
        mapped += 1;
    }

    /* Nothing we track was in the walk. */
    if (mapped == 0) {
        return 0;
    }

    best = 0;

    /* Longest increasing subsequence of slot indexes. Earlier ties win. */
    for (c = 0; c < mapped; c++) {
        int earlier;

        lisLen[c] = 1;
        lisPrev[c] = -1;

        /* Extend a shorter chain that sits above this window and below it in the snapshot. */
        for (earlier = 0; earlier < c; earlier++) {
            if (slotOf[earlier] < slotOf[c] && lisLen[earlier] + 1 > lisLen[c]) {
                lisLen[c] = lisLen[earlier] + 1;
                lisPrev[c] = earlier;
            }
        }

        /* The first longest chain is the one we keep. */
        if (lisLen[c] > lisLen[best]) {
            best = c;
        }
    }

    /* Mark the stable windows. prev always points at a lower index, so this ends. */
    for (c = best; c >= 0; ) {
        stable[slotOf[c]] = 1;
        if (lisPrev[c] < 0) {
            break;
        }
        c = lisPrev[c];
    }

    moves = 0;

    /* Count windows that are in the walk and not already in snapshot order. */
    for (s = 0; s < slotCount; s++) {
        if (!lock_z_slot_seen(slotOf, mapped, s)) {
            continue;
        }
        if (stable[s]) {
            continue;
        }
        moves += 1;
    }

    /* The relative order already matches the snapshot. */
    if (moves == 0) {
        return 0;
    }

    /* Refuse a partial plan. The caller would otherwise move an arbitrary subset. */
    if (!outMoves || moves > outCap) {
        return -1;
    }

    w = 0;

    /* Emit the movers from the top of the snapshot down so each predecessor is ready. */
    for (s = 0; s < slotCount; s++) {
        int pred;

        if (!lock_z_slot_seen(slotOf, mapped, s) || stable[s]) {
            continue;
        }

        pred = s - 1;

        /* The nearest tracked window above this one in the snapshot that we can see. */
        while (pred >= 0 && !lock_z_slot_seen(slotOf, mapped, pred)) {
            pred -= 1;
        }

        outMoves[w].hwnd = slots[s].hwnd;

        /* No predecessor means this window belongs at the top. */
        if (pred < 0) {
            outMoves[w].insertAfter = 0;
        } else {
            outMoves[w].insertAfter = slots[pred].hwnd;
        }

        w += 1;
    }

    return w;
}

/* 1 when the snapshot show command is maximized.
   SW_SHOWMAXIMIZED is the only show command that means that. A minimized
   window that used to be maximized is show command 2, with a flag this
   helper does not read. The caller compares the snapshot, not the live
   minimized state. */
static int lock_placement_is_maximized(const LockPlacement *place) {
    /* No placement, so it is not a maximized snapshot. */
    if (!place) {
        return 0;
    }

    return place->showCmd == LOCK_SHOW_MAXIMIZED;
}

/* Slot indexes whose live placement differs from the snapshot.
   Dead windows are skipped. `maximized` selects the set: LOCK_PLACE_NORMAL
   leaves maximized snapshots out, LOCK_PLACE_MAXIMIZED lists only those.
   Within the set, indexes run from the bottom of the snapshot upward.
   Showing a window brings it forward, so the last show in this set ends
   on top of the earlier ones. The caller restores this set before z-order.
   That pass puts the snapshot order back without clearing a maximized
   show state. Returns how many were written. Returns 0
   when nothing in the set drifted or the tables are missing, so a failed
   observation does not rewrite windows. Returns -1 when `outCap` cannot
   hold every selected slot, so the caller does not apply a truncated list. */
static int lock_placement_move_slots(const LockTrackedSlot *slots, int slotCount,
                                     const LockObserved *observed,
                                     int *outSlots, int outCap, int maximized) {
    int i;
    int count;
    int wantMax;

    /* No snapshot, or the caller could not observe. Do not invent writes. */
    if (!slots || !observed || slotCount <= 0) {
        return 0;
    }

    /* A positive capacity with nowhere to write is not a plan. */
    if (outCap < 0 || (outCap > 0 && !outSlots)) {
        return -1;
    }

    /* Anything other than the maximized filter is the normal-window set. */
    wantMax = (maximized == LOCK_PLACE_MAXIMIZED) ? 1 : 0;
    count = 0;

    /* One pass to count, so a short buffer does not keep a partial list. */
    for (i = 0; i < slotCount; i++) {
        int isMax;

        if (!observed[i].alive) {
            continue;
        }
        if (!lock_placement_differs(&slots[i].place, &observed[i].place)) {
            continue;
        }

        isMax = lock_placement_is_maximized(&slots[i].place);

        /* The other set is sent in a different phase. */
        if (isMax != wantMax) {
            continue;
        }

        count += 1;
    }

    /* Already in place, or the caller asked for a list that cannot fit. */
    if (count == 0) {
        return 0;
    }
    if (count > outCap) {
        return -1;
    }

    count = 0;

    /* Bottom of the snapshot first. The paced sender shows the top window last. */
    for (i = slotCount - 1; i >= 0; i--) {
        int isMax;

        if (!observed[i].alive) {
            continue;
        }
        if (!lock_placement_differs(&slots[i].place, &observed[i].place)) {
            continue;
        }

        isMax = lock_placement_is_maximized(&slots[i].place);

        if (isMax != wantMax) {
            continue;
        }

        outSlots[count] = i;
        count += 1;
    }

    return count;
}

/* 1 when `event` is a gesture the watchdog should undo immediately.
   Scroll, capture, and menu events are not in this set. */
static int lock_event_needs_repair(unsigned int event) {
    /* The foreground window changed. A touchpad app-switch does this and nothing else. */
    if (event == LOCK_EVENT_FOREGROUND) {
        return 1;
    }

    /* A window started or finished a move or resize. */
    if (event == LOCK_EVENT_MOVESIZESTART || event == LOCK_EVENT_MOVESIZEEND) {
        return 1;
    }

    /* Alt+Tab and the three-finger switcher. */
    if (event == LOCK_EVENT_SWITCHSTART || event == LOCK_EVENT_SWITCHEND) {
        return 1;
    }

    /* Show-desktop and other minimize-all gestures. */
    if (event == LOCK_EVENT_MINIMIZESTART || event == LOCK_EVENT_MINIMIZEEND) {
        return 1;
    }

    /* A four-finger swipe landed on another virtual desktop. */
    if (event == LOCK_EVENT_DESKTOPSWITCH) {
        return 1;
    }

    return 0;
}

/* Decide whether the enumerator should stop, skip, or record this window.
   The checks follow the launch snapshot: stop when the table is full, skip
   our own windows, skip invisible and owned windows, skip tool windows that
   are not app windows, skip empty titles, and skip a failed placement read.
   A null `facts` pointer stops the walk. */
static int lock_snapshot_classify(const LockWindowFacts *facts, int trackedCount, int maxTracked) {
    /* The fixed table is full. Further windows would overflow it. */
    if (trackedCount >= maxTracked) {
        return LOCK_SNAP_STOP;
    }

    /* The caller has no facts to judge. Stopping is safer than recording. */
    if (!facts) {
        return LOCK_SNAP_STOP;
    }

    /* The lock and the hint are ours. They are not part of the user's desktop. */
    if (facts->isSelf || facts->isHint) {
        return LOCK_SNAP_SKIP;
    }

    /* Hidden top-level windows are not part of the arrangement we restore. */
    if (!facts->visible) {
        return LOCK_SNAP_SKIP;
    }

    /* Owned popups follow their owner. Restoring them independently fights that. */
    if (facts->hasOwner) {
        return LOCK_SNAP_SKIP;
    }

    /* Tool windows stay out of Alt+Tab unless they also asked to be app windows. */
    if (facts->isToolWindow && !facts->isAppWindow) {
        return LOCK_SNAP_SKIP;
    }

    /* Untitled windows are shell and helper surfaces, not documents the user arranged. */
    if (facts->titleLength <= 0) {
        return LOCK_SNAP_SKIP;
    }

    /* Without a placement there is nothing to put back later. */
    if (!facts->placementOk) {
        return LOCK_SNAP_SKIP;
    }

    return LOCK_SNAP_TAKE;
}

/* Set the sweep back to "we are on the lock's desktop". */
static void lock_vd_sweep_clear(LockVdSweep *sweep) {
    /* No sweep state to clear. */
    if (!sweep) {
        return;
    }

    sweep->phase = LOCK_VD_PHASE_HOME;
    sweep->leftSteps = 0;
    sweep->totalSteps = 0;
}

/* Advance the virtual-desktop walk from one observation.
   QUERY_FAILED changes nothing and injects nothing.
   ON_CURRENT clears the sweep.
   ON_OTHER (and any other code) walks left up to LOCK_VD_LEFT_CAP, switches
   to the rightward phase on the call that hits the cap without injecting,
   then walks right until LOCK_VD_TOTAL_CAP and stays silent after that.
   The silent cap transition matches the original one-step-per-check pacing. */
static int lock_vd_on_check(LockVdSweep *sweep, int observation) {
    /* No state, so there is no chord to inject. */
    if (!sweep) {
        return LOCK_VD_ACT_NONE;
    }

    /* A failed COM query must not be treated as "on another desktop". */
    if (observation == LOCK_VD_QUERY_FAILED) {
        return LOCK_VD_ACT_NONE;
    }

    /* The lock window is back on the active desktop. Drop the walk. */
    if (observation == LOCK_VD_ON_CURRENT) {
        lock_vd_sweep_clear(sweep);
        return LOCK_VD_ACT_NONE;
    }

    /* Start the leftward sweep the first time we notice we are away. */
    if (sweep->phase == LOCK_VD_PHASE_HOME) {
        sweep->phase = LOCK_VD_PHASE_LEFT;
        sweep->leftSteps = 0;
        sweep->totalSteps = 0;
    }

    /* Still walking left, or we just entered that phase above. */
    if (sweep->phase == LOCK_VD_PHASE_LEFT) {
        /* Room remains for another Ctrl+Win+Left. */
        if (sweep->leftSteps < LOCK_VD_LEFT_CAP) {
            sweep->leftSteps += 1;
            sweep->totalSteps += 1;
            return LOCK_VD_ACT_LEFT;
        }

        /* The left cap is exhausted. Switch phase and wait for the next check. */
        sweep->phase = LOCK_VD_PHASE_RIGHT;
        return LOCK_VD_ACT_NONE;
    }

    /* Walking right toward the original desktop, from the other side. */
    if (sweep->phase == LOCK_VD_PHASE_RIGHT) {
        /* Room remains under the total-step cap. */
        if (sweep->totalSteps < LOCK_VD_TOTAL_CAP) {
            sweep->totalSteps += 1;
            return LOCK_VD_ACT_RIGHT;
        }

        /* Giving up. Further checks stay silent until the desktop is current again. */
        return LOCK_VD_ACT_NONE;
    }

    return LOCK_VD_ACT_NONE;
}

/* Fill `out` with the six events of one Ctrl+Win+Arrow chord.
   goRight selects the right arrow. Any other value selects the left arrow.
   Returns LOCK_STROKE_COUNT, or 0 when `out` is null or `cap` is too small.
   On failure `out` is left untouched. */
static int lock_desktop_switch_strokes(int goRight, LockKeyStroke *out, int cap) {
    unsigned int arrow;

    /* A short or missing buffer cannot hold a whole chord. */
    if (!out || cap < LOCK_STROKE_COUNT) {
        return 0;
    }

    /* The arrow is the only key that depends on direction. */
    if (goRight) {
        arrow = LOCK_VK_RIGHT;
    } else {
        /* Left is the direction for zero and for every other non-right value. */
        arrow = LOCK_VK_LEFT;
    }

    /* Downs: left win, control, arrow. Windows treats this as the desktop shortcut. */
    out[0].vk = LOCK_VK_LWIN;
    out[0].keyUp = 0;
    out[1].vk = LOCK_VK_CONTROL;
    out[1].keyUp = 0;
    out[2].vk = arrow;
    out[2].keyUp = 0;

    /* Ups in reverse order so each key is released after the arrow. */
    out[3].vk = arrow;
    out[3].keyUp = 1;
    out[4].vk = LOCK_VK_CONTROL;
    out[4].keyUp = 1;
    out[5].vk = LOCK_VK_LWIN;
    out[5].keyUp = 1;

    return LOCK_STROKE_COUNT;
}

/* Fill the reassert actions for one watchdog visit.
   With no lock window every flag stays clear.
   Otherwise the window is repositioned, unminimized when `isIconic` is set,
   and the hint is raised when `hasHint` is set. */
static void lock_reassert_actions(int hasLock, int isIconic, int hasHint, LockReassert *out) {
    /* Nowhere to write the plan. */
    if (!out) {
        return;
    }

    out->unminimize = 0;
    out->reposition = 0;
    out->raiseHint = 0;

    /* The lock window has not been created yet. */
    if (!hasLock) {
        return;
    }

    /* Always reclaim fullscreen topmost while the lock exists. */
    out->reposition = 1;

    /* A minimized lock is put back before the move, matching SW_RESTORE. */
    if (isIconic) {
        out->unminimize = 1;
    }

    /* The hint follows the lock to the top of the Z-order. */
    if (hasHint) {
        out->raiseHint = 1;
    }
}

/* 1 when `msg` is WM_TOUCH and the pump should close the touch handle
   instead of dispatching the message. */
static int lock_message_is_touch(unsigned int msg) {
    /* Touch packets are consumed so a tap does not click through the overlay. */
    if (msg == LOCK_WM_TOUCH) {
        return 1;
    }

    return 0;
}

/* Place the exit-hint pill. It is LOCK_HINT_W by LOCK_HINT_H, centered
   horizontally, and pinned LOCK_HINT_Y pixels from the top of the screen.
   `screenH` is accepted so the caller can pass both system metrics. The
   pill does not use the height. A null `out` is ignored. */
static void lock_hint_rect(int screenW, int screenH, LockHintRect *out) {
    /* The caller passed both metrics. Height does not move a top-pinned pill. */
    (void)screenH;

    /* Nowhere to write the rectangle. */
    if (!out) {
        return;
    }

    out->w = LOCK_HINT_W;
    out->h = LOCK_HINT_H;
    out->x = (screenW - LOCK_HINT_W) / 2;
    out->y = LOCK_HINT_Y;
}

/* 1 when this watchdog tick should query the virtual desktop.
   `tick` is the counter after it has been incremented, starting at 1.
   Even ticks check, so the first timer (tick 1) waits and later checks
   land about one timer apart. */
static int lock_vd_check_this_tick(int tick) {
    /* Even tick: enough time has passed for the previous switch animation. */
    if ((tick & 1) == 0) {
        return 1;
    }

    return 0;
}

/* Lay a LockPermanent over `block` and bump-allocate its table and hint
   from the bytes after the struct. Those allocations live until the process
   ends: this function does not free them, and the tail bump is left with
   its cursor advanced so a later reset is the caller's mistake to avoid.

   `block` must be aligned for a pointer (VirtualAlloc's pages are).
   `trackedCap` is the slot count. `exitHint` is copied, so the caller may
   reuse its buffer afterwards. `exitHintChars` is the count without the NUL.
   Returns 1 and stores the state through `outState`. Returns 0 and stores
   null when the block cannot hold the layout. */
static int lock_permanent_bind(void *block, unsigned long long blockBytes, int trackedCap,
                               const unsigned short *exitHint, int exitHintChars,
                               LockPermanent **outState) {
    unsigned char *bytes;
    unsigned long long stateBytes;
    unsigned long long tailOffset;
    unsigned long long tailBytes;
    unsigned long long slotsBytes;
    unsigned long long hintBytes;
    LockPermanent *state;
    LockBump tail;
    LockTrackedSlot *slots;
    unsigned short *hintCopy;

    /* The output pointer is required. Every failure path clears it. */
    if (!outState) {
        return 0;
    }

    *outState = 0;

    /* A missing block, a non-positive table, or a negative hint length cannot be laid out. */
    if (!block || blockBytes == 0ull || trackedCap <= 0 || exitHintChars < 0) {
        return 0;
    }

    /* A positive hint length needs a source string to copy. */
    if (exitHintChars > 0 && !exitHint) {
        return 0;
    }

    stateBytes = (unsigned long long)sizeof(LockPermanent);

    /* The struct itself has to fit before any bump allocation. */
    if (stateBytes >= blockBytes) {
        return 0;
    }

    /* The tail starts on a 16-byte boundary so the first slot is aligned. */
    tailOffset = lock_align_up(stateBytes, 16ull);

    /* Alignment failed, or the aligned struct consumed the whole block. */
    if (tailOffset == ~0ull || tailOffset < stateBytes || tailOffset >= blockBytes) {
        return 0;
    }

    tailBytes = blockBytes - tailOffset;

    /* Slot table size, rejected when the multiply would wrap. */
    if ((unsigned long long)trackedCap > (~0ull) / (unsigned long long)sizeof(LockTrackedSlot)) {
        return 0;
    }
    slotsBytes = (unsigned long long)trackedCap * (unsigned long long)sizeof(LockTrackedSlot);

    /* Hint size counts the terminating zero. Reject a length that would wrap. */
    if (exitHintChars > 0) {
        /* Reject a length whose byte count, including the NUL, would wrap. */
        if ((unsigned long long)exitHintChars > (~0ull) / (unsigned long long)sizeof(unsigned short) - 1ull) {
            return 0;
        }
        hintBytes = ((unsigned long long)exitHintChars + 1ull) * (unsigned long long)sizeof(unsigned short);
    } else {
        /* No hint characters, so the tail does not reserve hint bytes. */
        hintBytes = 0ull;
    }

    bytes = (unsigned char *)block;

    /* Clear only the header. The rest of a large block stays untouched until allocated. */
    lock_zero(bytes, stateBytes);
    lock_bump_init(&tail, bytes + tailOffset, tailBytes);

    /* The tracked-window table is the first permanent allocation. */
    slots = (LockTrackedSlot *)lock_bump_alloc(&tail, slotsBytes, 8ull);
    /* The tracked table has to fit or the layout is not usable. */
    if (!slots) {
        return 0;
    }
    lock_zero(slots, slotsBytes);

    hintCopy = 0;

    /* Copy the hint into the block so the caller's buffer is not retained. */
    if (hintBytes != 0ull) {
        hintCopy = (unsigned short *)lock_bump_alloc(&tail, hintBytes, 2ull);
        /* A hint that does not fit after the table fails the bind. */
        if (!hintCopy) {
            return 0;
        }
        lock_copy(hintCopy, exitHint, (unsigned long long)exitHintChars * (unsigned long long)sizeof(unsigned short));
        hintCopy[exitHintChars] = 0;
    }

    state = (LockPermanent *)bytes;
    state->tracked = slots;
    state->trackedCount = 0;
    state->trackedCap = trackedCap;
    lock_vd_sweep_clear(&state->vd);
    lock_key_latch_clear(&state->keys);
    state->screenW = 0;
    state->screenH = 0;
    state->vdTick = 0;
    state->exitHint = hintCopy;
    state->exitHintChars = exitHintChars;

    /* Keep the advanced cursor. Later permanent allocations append after the hint. */
    state->tail = tail;
    *outState = state;
    return 1;
}


typedef unsigned short WCHAR;
typedef const WCHAR *LPCWSTR;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef long LONG;
typedef long long LONG_PTR;
typedef long long INT_PTR;
typedef unsigned long long UINT_PTR;
typedef unsigned long long size_t;
typedef LONG_PTR LRESULT;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef LONG HRESULT;
typedef unsigned char BYTE;
typedef DWORD COLORREF;
typedef void *HANDLE;
typedef void *HINSTANCE;
typedef void *HWND;
typedef void *HDC;
typedef void *HBRUSH;
typedef void *HFONT;
typedef void *HGDIOBJ;
typedef void *HHOOK;

/* Out-of-context WinEvent callback. The hook delivers this on the UI thread. */
typedef void (*WINEVENTPROC)(void *hook, DWORD event, HWND hwnd,
                                      LONG idObject, LONG idChild,
                                      DWORD eventThread, DWORD eventTime);
typedef void *HMENU;
typedef void *HCURSOR;
typedef void *HICON;
typedef void *HTOUCHINPUT;

#define NULL ((void *)0)
#define FALSE 0
#define TRUE 1

/* Window messages this program handles or filters. */
#define WM_DESTROY 0x0002u
#define WM_PAINT 0x000Fu
#define WM_CLOSE 0x0010u
#define WM_ERASEBKGND 0x0014u
#define WM_KEYDOWN 0x0100u
#define WM_KEYUP 0x0101u
#define WM_SYSKEYDOWN 0x0104u
#define WM_SYSKEYUP 0x0105u
#define WM_SIZE 0x0005u
#define WM_TIMER 0x0113u
#define SIZE_MINIMIZED 1

/* Styles for the borderless topmost layered lock and the hint popup. */
#define WS_POPUP 0x80000000u
#define WS_EX_TOPMOST 0x00000008u
#define WS_EX_TOOLWINDOW 0x00000080u
#define WS_EX_APPWINDOW 0x00040000u
#define WS_EX_LAYERED 0x00080000u

/* GetWindow / GetWindowLong selectors. */
#define GW_OWNER 4u
#define GWL_EXSTYLE (-20)

/* Layered-window alpha. The lock uses a near-zero alpha so it stays invisible. */
#define LWA_ALPHA 0x00000002u

/* Low-level hooks. Injected events are the desktop-switch chord we send. */
#define WH_KEYBOARD_LL 13
#define WH_MOUSE_LL 14
#define HC_ACTION 0
#define LLKHF_INJECTED 0x00000010u

/* SendInput keyboard event. */
#define INPUT_KEYBOARD 1u
#define KEYEVENTF_KEYUP 0x0002u

/* COM apartment and the "no outer unknown" create. */
#define S_OK 0
#define CLSCTX_ALL 0x17u
#define COINIT_APARTMENTTHREADED 0x2u

/* Primary monitor size. */
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1

/* ShowWindow. The watchdog uses SW_RESTORE when a gesture minimizes the lock. */
#define SW_SHOW 5
#define SW_RESTORE 9

/* SetWindowPos flags and the insert-after sentinels.
   HWND_TOP is not used to repair z-order. With SWP_NOACTIVATE it returns
   success and leaves the stack unchanged while the lock is foreground.
   HWND_NOTOPMOST is the fallback that drops a promoted window back to the
   top of the ordinary band, behind every topmost window. */
#define SWP_NOSIZE 0x0001u
#define SWP_NOMOVE 0x0002u
#define SWP_NOACTIVATE 0x0010u
#define SWP_SHOWWINDOW 0x0040u
#define HWND_TOPMOST ((HWND)(LONG_PTR)-1)
#define HWND_TOP ((HWND)(LONG_PTR)0)
#define HWND_NOTOPMOST ((HWND)(LONG_PTR)-2)

/* Next window down the Z-order from GetWindow. The walk starts at GetTopWindow. */
#define GW_HWNDNEXT 2u

/* Posted by the WinEvent hook so a gesture is undone on the UI thread. */
#define WM_LOCK_REPAIR 0x8001u

/* Out-of-context delivery, and skip events this process caused itself. */
#define WINEVENT_OUTOFCONTEXT 0x0000u
#define WINEVENT_SKIPOWNPROCESS 0x0002u

/* Safety stop for a Z-order walk whose next-pointer loops. */
#define ZORDER_WALK_CAP 8192

/* Watchdog timer id. 250 ms is the reassert period. */
#define IDT_REASSERT 1u
#define WATCHDOG_MS 250u

/* One-window pace timer. Its period is the current attempt's gap. */
#define IDT_PACE 2u

/* Pace phases. IDLE means no window instructions are queued. */
#define PACE_IDLE 0
#define PACE_PLACE 1
#define PACE_PLACE_SETTLE 2
#define PACE_Z 3
#define PACE_Z_SETTLE 4
#define PACE_MAX 5
#define PACE_MAX_SETTLE 6

/* Font and text drawing for the hint pill. */
#define FW_BOLD 700
#define DEFAULT_CHARSET 1u
#define OUT_DEFAULT_PRECIS 0u
#define CLIP_DEFAULT_PRECIS 0u
#define CLEARTYPE_QUALITY 5u
#define DEFAULT_PITCH 0u
#define FF_SWISS 0x20u
#define TRANSPARENT 1
#define DT_CENTER 0x00000001u
#define DT_NOCLIP 0x00000100u

/* VirtualAlloc. Both flags together reserve the range and mark it committed. */
#define MEM_COMMIT 0x00001000u
#define MEM_RESERVE 0x00002000u
#define PAGE_READWRITE 0x04u

/*
 * Permanent block. Large on purpose: the bump's capacity is the use limit,
 * and pages past the cursor are not written, so they are not resident.
 */
#define PERMANENT_BLOCK_BYTES (64ull * 1024ull * 1024ull)

/* Tick block. One watchdog visit uses a few kilobytes and then resets. */
#define TICK_BLOCK_BYTES (16ull * 1024ull * 1024ull)

/* commit_stack_pages step. 180 * 2500 stays inside the default 1 MiB reserve. */
#define STACK_PROBE_CHUNK 2500
#define STACK_PROBE_STEPS 180

#define RGB(r, g, b) ((COLORREF)(((BYTE)(r) | ((DWORD)((BYTE)(g)) << 8)) | ((DWORD)((BYTE)(b)) << 16)))

/* Inclusive-exclusive rectangle in pixels. Used by paint, placement, and the hint. */
typedef struct RECT {
    /* Left edge, inclusive. */
    LONG left;

    /* Top edge, inclusive. */
    LONG top;

    /* Right edge, exclusive. */
    LONG right;

    /* Bottom edge, exclusive. */
    LONG bottom;
} RECT;

/* A screen point in pixels. WINDOWPLACEMENT stores the minimized and maximized points. */
typedef struct POINT {
    /* Horizontal position. */
    LONG x;

    /* Vertical position. */
    LONG y;
} POINT;

/* Win32 window placement. length must be set to the struct size before the get call. */
typedef struct WINDOWPLACEMENT {
    /* Size of this struct, in bytes. The API uses it as a version. */
    UINT length;

    /* Placement flags. Stored and written back unchanged. */
    UINT flags;

    /* SW_SHOWNORMAL, SW_SHOWMINIMIZED, SW_SHOWMAXIMIZED, or another show command. */
    UINT showCmd;

    /* Top-left of the window when it is minimized. */
    POINT ptMinPosition;

    /* Top-left of the window when it is maximized. */
    POINT ptMaxPosition;

    /* Restored rectangle. This is the rectangle the watchdog compares. */
    RECT rcNormalPosition;
} WINDOWPLACEMENT;

/* Enumerator callback. Returning FALSE stops EnumWindows. */
typedef BOOL (*WNDENUMPROC)(HWND, LPARAM);

/* 128-bit COM identifier. Data4 is the last eight bytes in wire order. */
typedef struct GUID {
    /* First four bytes of the UUID. */
    DWORD Data1;

    /* Next two bytes. */
    WORD Data2;

    /* Next two bytes. */
    WORD Data3;

    /* Final eight bytes. */
    BYTE Data4[8];
} GUID;

/* One key event inside INPUT. Layout matches the x64 KEYBDINPUT (24 bytes). */
typedef struct KEYBDINPUT {
    /* Virtual-key code. Zero when the event is scan-code only. We set the code. */
    WORD wVk;

    /* Hardware scan code. Left zero so Windows uses wVk. */
    WORD wScan;

    /* KEYEVENTF_KEYUP on releases. Other flags stay zero. */
    DWORD dwFlags;

    /* Event timestamp. Zero asks the system to stamp it. */
    DWORD time;

    /* Extra value delivered with the event. Zero for our chord. */
    UINT_PTR dwExtraInfo;
} KEYBDINPUT;

/* Mouse half of the INPUT union. Present so the union is the right size (32 bytes). */
typedef struct MOUSEINPUT {
    /* Horizontal motion or absolute position. Unused by this program. */
    LONG dx;

    /* Vertical motion or absolute position. Unused by this program. */
    LONG dy;

    /* Wheel delta or x-button. Unused by this program. */
    DWORD mouseData;

    /* Mouse-event flags. Unused by this program. */
    DWORD dwFlags;

    /* Event timestamp. Unused by this program. */
    DWORD time;

    /* Extra value. The 8-byte field is what pads MOUSEINPUT to 32 bytes. */
    UINT_PTR dwExtraInfo;
} MOUSEINPUT;

/* Hardware half of the INPUT union. Eight bytes, smaller than the mouse half. */
typedef struct HARDWAREINPUT {
    /* Hardware message. Unused by this program. */
    DWORD uMsg;

    /* Low half of the hardware wParam. Unused by this program. */
    WORD wParamL;

    /* High half of the hardware wParam. Unused by this program. */
    WORD wParamH;
} HARDWAREINPUT;

/* SendInput record. On x64 the union starts at offset 8 and the struct is 40 bytes. */
typedef struct INPUT {
    /* INPUT_KEYBOARD for every event this program injects. */
    DWORD type;

    /* The three event kinds. Keyboard uses u.ki. */
    union {
        /* Mouse event. Occupies the union so sizeof(INPUT) matches the system. */
        MOUSEINPUT mi;

        /* Keyboard event. The desktop-switch chord fills this member. */
        KEYBDINPUT ki;

        /* Hardware event. Unused. Kept so the union matches the SDK. */
        HARDWAREINPUT hi;
    } u;
} INPUT;

/* COM vtable for the documented IVirtualDesktopManager. */
typedef struct IVirtualDesktopManager IVirtualDesktopManager;
typedef struct IVirtualDesktopManagerVtbl {
    /* Standard COM identity query. Unused. Present so the later slots line up. */
    HRESULT (*QueryInterface)(IVirtualDesktopManager *self, const GUID *iid, void **out);

    /* Standard COM reference increment. Unused. */
    DWORD (*AddRef)(IVirtualDesktopManager *self);

    /* Standard COM reference decrement. Unused. The process exit releases it. */
    DWORD (*Release)(IVirtualDesktopManager *self);

    /* Writes whether `hwnd` is on the desktop the user is looking at. */
    HRESULT (*IsWindowOnCurrentVirtualDesktop)(IVirtualDesktopManager *self, HWND hwnd, BOOL *out);

    /* Writes the desktop id of `hwnd`. Unused. Present so the last slot lines up. */
    HRESULT (*GetWindowDesktopId)(IVirtualDesktopManager *self, HWND hwnd, GUID *out);

    /* Moves `hwnd` to a desktop. Unused. Windows has no public "activate desktop" here. */
    HRESULT (*MoveWindowToDesktop)(IVirtualDesktopManager *self, HWND hwnd, const GUID *desktop);
} IVirtualDesktopManagerVtbl;

/* The interface pointer is the address of a vtable pointer, as COM requires. */
struct IVirtualDesktopManager {
    /* Functions for this object. */
    IVirtualDesktopManagerVtbl *lpVtbl;
};

/* BeginPaint / EndPaint record. */
typedef struct PAINTSTRUCT {
    /* Device context valid until EndPaint. */
    HDC hdc;

    /* Non-zero when the background needs erasing. We erase ourselves. */
    BOOL fErase;

    /* Rectangle that needs painting, in client pixels. */
    RECT rcPaint;

    /* Reserved for Windows. */
    BOOL fRestore;

    /* Reserved for Windows. */
    BOOL fIncUpdate;

    /* Reserved for Windows. Thirty-two bytes, matching the SDK. */
    BYTE rgbReserved[32];
} PAINTSTRUCT;

/* Window-class registration record. On x64 this struct is 80 bytes. */
typedef struct WNDCLASSEXW {
    /* Size of this struct, in bytes. */
    UINT cbSize;

    /* Class style. Left zero: no redraw-on-size extra, no private DC. */
    UINT style;

    /* Procedure that receives messages for windows of this class. */
    LRESULT (*lpfnWndProc)(HWND, UINT, WPARAM, LPARAM);

    /* Extra bytes after the class. Zero. */
    int cbClsExtra;

    /* Extra bytes after the window. Zero. */
    int cbWndExtra;

    /* Module that owns the class. */
    HINSTANCE hInstance;

    /* Large icon. Null: the class has no custom icon. */
    HICON hIcon;

    /* Cursor shown over the window. Null hides the pointer over the lock. */
    HCURSOR hCursor;

    /* Background brush. Null for the lock. The hint class holds a dark brush. */
    HBRUSH hbrBackground;

    /* Menu name. Null: no menu. */
    LPCWSTR lpszMenuName;

    /* Class name registered with RegisterClassExW. */
    LPCWSTR lpszClassName;

    /* Small icon. Null. */
    HICON hIconSm;
} WNDCLASSEXW;

/* Low-level keyboard hook payload. Twenty-four bytes on x64. */
typedef struct KBDLLHOOKSTRUCT {
    /* Virtual-key code of the physical or injected key. */
    DWORD vkCode;

    /* Hardware scan code. */
    DWORD scanCode;

    /* Flags. LLKHF_INJECTED marks the chords this program sends. */
    DWORD flags;

    /* Event time, in milliseconds. */
    DWORD time;

    /* Extra information associated with the event. */
    UINT_PTR dwExtraInfo;
} KBDLLHOOKSTRUCT;

/* Thread message. Forty-eight bytes on x64. */
typedef struct MSG {
    /* Window the message is aimed at. Null for thread messages such as the hooks' posts. */
    HWND hwnd;

    /* Message id. */
    UINT message;

    /* Message-specific word. */
    WPARAM wParam;

    /* Message-specific long. For WM_TOUCH this is the touch-input handle. */
    LPARAM lParam;

    /* Event time, in milliseconds. */
    DWORD time;

    /* Cursor position when the message was posted, in screen pixels. */
    POINT pt;
} MSG;

/* Compile-time layout checks against the x64 SDK sizes. A mismatch is a build error. */
extern char lock_abi_input[(sizeof(INPUT) == 40) ? 1 : -1];
extern char lock_abi_msg[(sizeof(MSG) == 48) ? 1 : -1];
extern char lock_abi_wndclass[(sizeof(WNDCLASSEXW) == 80) ? 1 : -1];
extern char lock_abi_paint[(sizeof(PAINTSTRUCT) == 72) ? 1 : -1];
extern char lock_abi_placement[(sizeof(WINDOWPLACEMENT) == 44) ? 1 : -1];
extern char lock_abi_kbd[(sizeof(KBDLLHOOKSTRUCT) == 24) ? 1 : -1];

/* user32: window creation, Z-order, placement, hooks, and the message pump. */
extern int GetSystemMetrics(int nIndex);
extern HWND CreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName,
                                      DWORD dwStyle, int x, int y, int nWidth, int nHeight,
                                      HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, void *lpParam);
extern BOOL ShowWindow(HWND hWnd, int nCmdShow);
extern BOOL SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int x, int y, int cx, int cy, UINT uFlags);
extern BOOL SetForegroundWindow(HWND hWnd);
extern HWND GetForegroundWindow(void);
extern HWND GetTopWindow(HWND hWnd);
extern DWORD GetWindowThreadProcessId(HWND hWnd, DWORD *processId);
extern BOOL AttachThreadInput(DWORD idAttach, DWORD idAttachTo, BOOL fAttach);
extern BOOL IsIconic(HWND hWnd);
extern BOOL EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);
extern BOOL IsWindow(HWND hWnd);
extern BOOL IsWindowVisible(HWND hWnd);
extern HWND GetWindow(HWND hWnd, UINT uCmd);
extern LONG GetWindowLongW(HWND hWnd, int nIndex);
extern int GetWindowTextLengthW(HWND hWnd);
extern BOOL IsZoomed(HWND hWnd);
extern BOOL GetWindowRect(HWND hWnd, RECT *lpRect);
extern LRESULT SendMessageTimeoutW(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                            UINT fuFlags, UINT uTimeout, UINT_PTR *lpdwResult);
extern BOOL GetWindowPlacement(HWND hWnd, WINDOWPLACEMENT *lpwndpl);
extern BOOL SetWindowPlacement(HWND hWnd, const WINDOWPLACEMENT *lpwndpl);
extern UINT SendInput(UINT cInputs, INPUT *pInputs, int cbSize);
extern UINT_PTR SetTimer(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, void *lpTimerFunc);
extern BOOL KillTimer(HWND hWnd, UINT_PTR uIDEvent);
extern BOOL UpdateWindow(HWND hWnd);
extern BOOL SetLayeredWindowAttributes(HWND hwnd, COLORREF crKey, BYTE bAlpha, DWORD dwFlags);
extern BOOL RegisterTouchWindow(HWND hwnd, DWORD ulFlags);
extern BOOL CloseTouchInputHandle(HTOUCHINPUT hTouchInput);
extern int ShowCursor(BOOL bShow);
extern HHOOK SetWindowsHookExW(int idHook, LRESULT (*lpfn)(int, WPARAM, LPARAM),
                                        HINSTANCE hmod, DWORD dwThreadId);
extern BOOL UnhookWindowsHookEx(HHOOK hhk);
extern void *SetWinEventHook(DWORD eventMin, DWORD eventMax, void *module,
                                      WINEVENTPROC proc, DWORD processId, DWORD threadId,
                                      DWORD flags);
extern LRESULT CallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
extern BOOL PostMessageW(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
extern void PostQuitMessage(int nExitCode);
extern BOOL GetMessageW(MSG *lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
extern BOOL TranslateMessage(const MSG *lpMsg);
extern LRESULT DispatchMessageW(const MSG *lpMsg);
extern unsigned short RegisterClassExW(const WNDCLASSEXW *lpwcx);
extern LRESULT DefWindowProcW(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
extern HDC BeginPaint(HWND hWnd, PAINTSTRUCT *lpPaint);
extern BOOL EndPaint(HWND hWnd, const PAINTSTRUCT *lpPaint);
extern BOOL GetClientRect(HWND hWnd, RECT *lpRect);
extern int FillRect(HDC hdc, const RECT *lprc, HBRUSH hbr);
extern HBRUSH CreateSolidBrush(COLORREF color);
extern HFONT CreateFontW(int cHeight, int cWidth, int cEscapement, int cOrientation,
                                   int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut,
                                   DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision,
                                   DWORD iQuality, DWORD iPitchAndFamily, LPCWSTR pszFaceName);
extern HGDIOBJ SelectObject(HDC hdc, HGDIOBJ h);
extern BOOL DeleteObject(HGDIOBJ ho);
extern int SetBkMode(HDC hdc, int mode);
extern COLORREF SetTextColor(HDC hdc, COLORREF color);
extern int DrawTextW(HDC hdc, LPCWSTR lpchText, int cchText, RECT *lprc, UINT format);

/* ole32: the virtual-desktop query. Activation of a desktop is not a public method. */
extern HRESULT CoInitializeEx(void *pvReserved, DWORD dwCoInit);
extern HRESULT CoCreateInstance(const GUID *rclsid, void *pUnkOuter, DWORD dwClsContext,
                                         const GUID *riid, void **ppv);

/* kernel32: process lifetime, the module handle, and the two memory blocks. */
extern void *GetModuleHandleW(const WCHAR *lpModuleName);
extern void ExitProcess(DWORD uExitCode);
extern void *VirtualAlloc(void *lpAddress, unsigned long long dwSize, DWORD flAllocationType, DWORD flProtect);
extern DWORD GetCurrentThreadId(void);
extern DWORD GetModuleFileNameW(void *module, WCHAR *path, DWORD cap);
extern HANDLE CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *security,
                                   DWORD disposition, DWORD flags, HANDLE templateFile);
extern BOOL WriteFile(HANDLE file, const void *bytes, DWORD count, DWORD *written, void *overlapped);
extern BOOL FlushFileBuffers(HANDLE file);
extern BOOL CloseHandle(HANDLE handle);
extern BOOL CreateDirectoryW(const WCHAR *path, void *security);
extern HANDLE GetStdHandle(DWORD stdHandle);
extern WCHAR *GetCommandLineW(void);

/*
 * Compiler-called byte fill. /NODEFAULTLIB does not provide one, and a large
 * clear can still turn into a call to this symbol. The program's own clears
 * go through lock_zero.
 */
void *memset(void *dst, int val, size_t size) {
    unsigned char *bytes;
    size_t i;

    bytes = (unsigned char *)dst;

    /* Fill the requested range with the low 8 bits of val. */
    for (i = 0; i < size; i++) {
        bytes[i] = (unsigned char)val;
    }

    return dst;
}

/* Compiler-called byte copy. Same reason as memset. The program's own copies use lock_copy. */
void *memcpy(void *dst, const void *src, size_t size) {
    unsigned char *out;
    const unsigned char *in;
    size_t i;

    out = (unsigned char *)dst;
    in = (const unsigned char *)src;

    /* Copy src onto dst. The compiler only emits this for non-overlapping ranges. */
    for (i = 0; i < size; i++) {
        out[i] = in[i];
    }

    return dst;
}

/* Low-level keyboard hook handle. Null until the hook is installed. */
static HHOOK g_keyboardHook = NULL;

/* Low-level mouse hook handle. Null until the hook is installed. */
static HHOOK g_mouseHook = NULL;

/* Nonzero while a pace step or a plan is on the stack. ShowWindow and
   SetWindowPlacement can send WM_SIZE back into the window procedure.
   The flag makes that nested call return so the step that is already
   running is not started over. */
static int g_repairing = 0;

/* PACE_IDLE, or the phase whose next timer fire sends one instruction.
   A repair that is already pacing ignores new gesture events, so a burst
   of focus changes does not start a second stack of moves. */
static int g_pacePhase = PACE_IDLE;

/* Attempt index for the delay. Zero after the stack matches the snapshot.
   It climbs when an attempt still sees drift, and it stops at the cap. */
static int g_paceAttempt = 0;

/* Next instruction to send. The entries below this index were already sent. */
static int g_paceIndex = 0;

/* How many instructions the current phase has. */
static int g_paceCount = 0;

/* Slot indexes for the placement phase now running. Normal windows and
   maximized windows share this table. It is filled again when the phase
   changes. It outlives the tick bump because the pace timer sends the
   indexes one at a time. */
static int g_placeSlots[LOCK_MAX_TRACKED];

/* Minimum z-order moves for the current attempt. Same lifetime as the
   placement table. insertAfter null means the top of the snapshot.
   apply_one_zmove anchors that window under the lock, not at HWND_TOP. */
static LockZMove g_zMoves[LOCK_MAX_TRACKED];

/* Fullscreen layered window that covers the primary monitor. */
static HWND g_hwnd = NULL;

/* Small pill that reminds the user of the Z+M exit chord. */
static HWND g_hintHwnd = NULL;

/* Permanent state. Points into the permanent VirtualAlloc block. Never freed. */
static LockPermanent *g_state = NULL;

/* Debug trace beside the exe. Null when CreateFile failed. Never the
   invalid-handle sentinel. Idle ticks do not write it. Process rundown
   closes the handle. */
static HANDLE g_logFile = NULL;

/* One output line being assembled. Flushed by log_commit. Not a window list. */
static char g_logLine[1024];

/* How many bytes of g_logLine are waiting. Zero after a commit. */
static int g_logLen = 0;

/* Slots already printed by the current z-order walk. One byte per slot.
   The walk sets a byte when that snapshot window is seen, then the missing
   pass prints the zeros. UI thread only. */
static unsigned char g_logSeen[LOCK_MAX_TRACKED];

/* Watchdog scratch. One tick allocates from it and then resets the cursor. */
static LockBump g_tick;

/* Virtual-desktop manager. Null when the COM class is unavailable. */
static IVirtualDesktopManager *g_vdm = NULL;

/* CLSID_VirtualDesktopManager {aa509086-5ca9-4c25-8f95-589d3c07b48a}. */
static const GUID g_clsidVirtualDesktopManager = {
    0xaa509086u, 0x5ca9u, 0x4c25u,
    {0x8fu, 0x95u, 0x58u, 0x9du, 0x3cu, 0x07u, 0xb4u, 0x8au}
};

/* IID_IVirtualDesktopManager {a5cd92ff-29be-454c-8d04-d82879fb3f1b}. */
static const GUID g_iidVirtualDesktopManager = {
    0xa5cd92ffu, 0x29beu, 0x454cu,
    {0x8du, 0x04u, 0xd8u, 0x28u, 0x79u, 0xfbu, 0x3fu, 0x1bu}
};

/* Text copied into the permanent block at startup. The pill draws that copy. */
static const WCHAR g_exitHintLiteral[] = L"Exit: Hold Z+M together";

/* Touch one stack chunk, then recurse, then touch the chunk again so the
   frame stays live. This build has no __chkstk. The pages stay committed
   for the rest of the process, which is what makes later frames safe.
   stepsLeft is how many chunks are still owed, including this one. */
static void commit_stack_pages(int stepsLeft) {
    volatile unsigned char page[STACK_PROBE_CHUNK];

    /* Touch the first byte so this frame's guard page is committed. */
    page[0] = (unsigned char)stepsLeft;

    /* Walk toward the bottom of the reserve. One chunk per call. */
    if (stepsLeft > 1) {
        commit_stack_pages(stepsLeft - 1);
    }

    /* Touch the last byte after the recursive call so the store cannot be deleted. */
    page[STACK_PROBE_CHUNK - 1] = page[0];
}

/* Count wide characters before the terminating zero. A null pointer counts as zero. */
static int wide_length(const WCHAR *text) {
    int count;

    count = 0;

    /* No string, so the permanent hint is stored empty. */
    if (!text) {
        return 0;
    }

    /* Stop at the first zero. The count does not include that zero. */
    while (text[count] != 0) {
        count += 1;
    }

    return count;
}

/* Map a keyboard-hook message id onto LOCK_KEY_DOWN, LOCK_KEY_UP, or LOCK_KEY_OTHER. */
static int key_transition_from_message(UINT msg) {
    /* A key or system-key press, including auto-repeat. */
    if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) {
        return LOCK_KEY_DOWN;
    }

    /* A key or system-key release. */
    if (msg == WM_KEYUP || msg == WM_SYSKEYUP) {
        return LOCK_KEY_UP;
    }

    return LOCK_KEY_OTHER;
}

/* Copy the show command and the restored rectangle out of a Win32 placement. */
static void placement_from_win32(const WINDOWPLACEMENT *wp, LockPlacement *place) {
    /* Both pointers are required. Callers pass stack records they just filled. */
    if (!wp || !place) {
        return;
    }

    place->showCmd = (int)wp->showCmd;
    place->flags = (int)wp->flags;
    place->minX = wp->ptMinPosition.x;
    place->minY = wp->ptMinPosition.y;
    place->maxX = wp->ptMaxPosition.x;
    place->maxY = wp->ptMaxPosition.y;
    place->left = wp->rcNormalPosition.left;
    place->top = wp->rcNormalPosition.top;
    place->right = wp->rcNormalPosition.right;
    place->bottom = wp->rcNormalPosition.bottom;
}

/* Write the snapshotted placement back. The saved flags and min/max points
   go with the show command and the restored rectangle. Returns 1 when
   SetWindowPlacement accepts the write, and 0 when the window or the
   sample is missing or the call fails. */
static int restore_one_placement(HWND hwnd, const LockPlacement *place) {
    WINDOWPLACEMENT wp;

    /* A missing window or sample has nothing to write. */
    if (!hwnd || !place) {
        return 0;
    }

    lock_zero(&wp, sizeof(wp));
    wp.length = (UINT)sizeof(wp);
    wp.flags = (UINT)place->flags;
    wp.showCmd = (UINT)place->showCmd;
    wp.ptMinPosition.x = place->minX;
    wp.ptMinPosition.y = place->minY;
    wp.ptMaxPosition.x = place->maxX;
    wp.ptMaxPosition.y = place->maxY;
    wp.rcNormalPosition.left = place->left;
    wp.rcNormalPosition.top = place->top;
    wp.rcNormalPosition.right = place->right;
    wp.rcNormalPosition.bottom = place->bottom;

    /* Nonzero from Windows means the placement was accepted. */
    if (SetWindowPlacement(hwnd, &wp)) {
        return 1;
    }
    return 0;
}

/* EnumWindows callback. Records user top-level windows into the permanent table. */
static BOOL snapshot_enum_proc(HWND hwnd, LPARAM lParam) {
    LockWindowFacts facts;
    WINDOWPLACEMENT wp;
    LONG exStyle;
    int decision;
    LockTrackedSlot *slot;

    /* The parameter is unused. EnumWindows requires the signature anyway. */
    (void)lParam;

    /* Startup failed to bind the permanent block. Stop the walk. */
    if (!g_state || !g_state->tracked) {
        return FALSE;
    }

    lock_zero(&facts, sizeof(facts));
    facts.isSelf = (hwnd == g_hwnd) ? 1 : 0;
    facts.isHint = (hwnd == g_hintHwnd) ? 1 : 0;
    facts.visible = IsWindowVisible(hwnd) ? 1 : 0;
    facts.hasOwner = (GetWindow(hwnd, GW_OWNER) != NULL) ? 1 : 0;

    exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    facts.isToolWindow = (exStyle & (LONG)WS_EX_TOOLWINDOW) ? 1 : 0;
    facts.isAppWindow = (exStyle & (LONG)WS_EX_APPWINDOW) ? 1 : 0;
    facts.titleLength = GetWindowTextLengthW(hwnd);

    lock_zero(&wp, sizeof(wp));
    wp.length = (UINT)sizeof(wp);

    /* Classify from a complete fact record, including the placement read. */
    if (GetWindowPlacement(hwnd, &wp)) {
        facts.placementOk = 1;
    }

    decision = lock_snapshot_classify(&facts, g_state->trackedCount, g_state->trackedCap);

    /* The table is full, or the facts could not be judged. */
    if (decision == LOCK_SNAP_STOP) {
        return FALSE;
    }

    /* This window is not part of the user's launch arrangement. */
    if (decision != LOCK_SNAP_TAKE) {
        return TRUE;
    }

    /* Append the slot. The classify call already rejected a full table. */
    slot = &g_state->tracked[g_state->trackedCount];
    slot->hwnd = (void *)hwnd;
    placement_from_win32(&wp, &slot->place);
    g_state->trackedCount += 1;
    return TRUE;
}

/* WM_GETTEXT, used with a timeout so a hung window cannot stall the trace. */
#define WM_GETTEXT 0x000Du
#define SMTO_ABORTIFHUNG 0x0002u

/* CreateFileW access, share, disposition, and attributes for the trace. */
#define LOG_GENERIC_WRITE 0x40000000u
#define LOG_SHARE_READ 0x00000001u
#define LOG_SHARE_WRITE 0x00000002u
#define LOG_CREATE_ALWAYS 2u
#define LOG_FILE_ATTRIBUTE_NORMAL 0x00000080u

/* Append one byte to the current line. A line that is already full stops. */
static void log_putc(char c) {
    /* Leave one byte so a newline can still be stored by log_commit. */
    if (g_logLen + 1 >= (int)sizeof(g_logLine)) {
        return;
    }

    g_logLine[g_logLen] = c;
    g_logLen += 1;
}

/* Append a C string. A null pointer is ignored so a missing word cannot fault. */
static void log_puts(const char *text) {
    /* Nothing to add. */
    if (!text) {
        return;
    }

    /* Copy until the line is full or the string ends. */
    while (*text) {
        log_putc(*text);
        text += 1;
    }
}

/* Append a signed decimal. INT_MIN is converted without negating it as an int. */
static void log_int(int value) {
    char digits[16];
    int count;
    int negative;
    unsigned int magnitude;

    negative = 0;

    /* A negative value is printed with a sign. The magnitude stays unsigned. */
    if (value < 0) {
        negative = 1;
        magnitude = (unsigned int)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned int)value;
    }

    count = 0;

    /* Least significant digit first. Zero still produces one character. */
    if (magnitude == 0u) {
        digits[count] = '0';
        count += 1;
    } else {
        while (magnitude != 0u && count < (int)sizeof(digits)) {
            digits[count] = (char)('0' + (magnitude % 10u));
            count += 1;
            magnitude /= 10u;
        }
    }

    if (negative) {
        log_putc('-');
    }

    /* Reverse the digits into the line. */
    while (count > 0) {
        count -= 1;
        log_putc(digits[count]);
    }
}

/* Append a pointer-sized hex value with a 0x prefix. Always sixteen digits. */
static void log_hex64(unsigned long long value) {
    int shift;

    log_puts("0x");

    /* High nibble first so the text sorts and lines up. */
    for (shift = 60; shift >= 0; shift -= 4) {
        int nibble;

        nibble = (int)((value >> shift) & 0xfull);
        if (nibble < 10) {
            log_putc((char)('0' + nibble));
        } else {
            log_putc((char)('a' + (nibble - 10)));
        }
    }
}

/* Write the current line and clear it. A missing file drops the line. */
static void log_commit(void) {
    DWORD wrote;

    /* Logging is optional. A failed open must not change the repair. */
    if (!g_logFile) {
        g_logLen = 0;
        return;
    }

    log_putc('\r');
    log_putc('\n');
    WriteFile(g_logFile, g_logLine, (DWORD)g_logLen, &wrote, NULL);
    g_logLen = 0;
}

/* Push the trace to disk so a killed process still leaves the last step. */
static void log_flush(void) {
    /* No file, nothing to flush. */
    if (!g_logFile) {
        return;
    }

    FlushFileBuffers(g_logFile);
}

/* Append a show command as a number and a short name. */
static void log_show(int showCmd) {
    log_int(showCmd);
    log_putc(':');

    /* The names match the show commands this repair compares. */
    if (showCmd == 1) {
        log_puts("normal");
    } else if (showCmd == 2) {
        log_puts("min");
    } else if (showCmd == LOCK_SHOW_MAXIMIZED) {
        log_puts("max");
    } else if (showCmd == 6) {
        log_puts("minimize");
    } else if (showCmd == 9) {
        log_puts("restore");
    } else {
        log_puts("other");
    }
}

/* Append the window title in quotes. A hung target is abandoned after 30 ms. */
static void log_title(HWND hwnd) {
    WCHAR text[96];
    UINT_PTR result;
    int count;
    int i;

    log_putc('"');
    lock_zero(text, sizeof(text));
    result = 0;

    /* WM_GETTEXT fills the buffer. The timeout keeps the pace timer moving. */
    SendMessageTimeoutW(hwnd, WM_GETTEXT, 96u, (LPARAM)text, SMTO_ABORTIFHUNG, 30u, &result);

    count = 0;
    while (count < 95 && text[count] != 0) {
        count += 1;
    }

    /* Quotes and controls stay on one line. Other characters are UTF-8. */
    for (i = 0; i < count; i++) {
        unsigned int ch;

        ch = text[i];
        if (ch == (unsigned int)'"' || ch == (unsigned int)'\\') {
            log_putc('\\');
            log_putc((char)ch);
        } else if (ch < 32u || ch == 127u) {
            log_putc(' ');
        } else if (ch < 128u) {
            log_putc((char)ch);
        } else if (ch < 0x800u) {
            log_putc((char)(0xc0u | (ch >> 6)));
            log_putc((char)(0x80u | (ch & 0x3fu)));
        } else {
            log_putc((char)(0xe0u | (ch >> 12)));
            log_putc((char)(0x80u | ((ch >> 6) & 0x3fu)));
            log_putc((char)(0x80u | (ch & 0x3fu)));
        }
    }

    log_putc('"');
}

/* Snapshot slot of a live HWND, or -1 when this window was not tracked. */
static int log_slot_of(HWND hwnd) {
    int slot;

    /* No table yet. */
    if (!g_state || !g_state->tracked) {
        return -1;
    }

    /* The table is at most LOCK_MAX_TRACKED. This walk is not a hot path. */
    for (slot = 0; slot < g_state->trackedCount; slot++) {
        if (g_state->tracked[slot].hwnd == (void *)hwnd) {
            return slot;
        }
    }

    return -1;
}

/* Name of the pace phase, for the trace header. */
static const char *log_phase_name(int phase) {
    /* The numbers are the PACE_ values. An unknown value stays numeric. */
    if (phase == PACE_IDLE) {
        return "idle";
    }
    if (phase == PACE_PLACE) {
        return "place";
    }
    if (phase == PACE_PLACE_SETTLE) {
        return "place-settle";
    }
    if (phase == PACE_Z) {
        return "z";
    }
    if (phase == PACE_Z_SETTLE) {
        return "z-settle";
    }
    if (phase == PACE_MAX) {
        return "max";
    }
    if (phase == PACE_MAX_SETTLE) {
        return "max-settle";
    }
    return "other";
}

/* Write every tracked window in current top-to-bottom order.
   `tag` says when the sample was taken. Each line has the live show
   command, whether Windows reports the window zoomed or iconic, the
   snapshot show command, the on-screen rectangle, and the title.
   Tracked windows missing from the walk are listed after the walk.
   The file is flushed before returning. */
static void log_zorder(const char *tag) {
    HWND hwnd;
    HWND foreground;
    int walk;
    int rank;
    int slot;

    /* A failed open leaves the repair silent. */
    if (!g_logFile || !g_state || !g_state->tracked) {
        return;
    }

    lock_zero(g_logSeen, (unsigned long long)g_state->trackedCount);

    foreground = GetForegroundWindow();
    log_puts("z-order ");
    log_puts(tag);
    log_puts(" attempt=");
    log_int(g_paceAttempt);
    log_puts(" phase=");
    log_puts(log_phase_name(g_pacePhase));
    log_puts(" fg=");
    log_hex64((unsigned long long)(UINT_PTR)foreground);
    log_puts(" fgSlot=");
    log_int(log_slot_of(foreground));
    log_commit();

    hwnd = GetTopWindow(NULL);
    walk = 0;
    rank = 0;

    /* Foreign windows are counted by the walk index. Only tracked ones are lines. */
    while (hwnd && walk < ZORDER_WALK_CAP) {
        WINDOWPLACEMENT wp;
        RECT rect;
        int liveShow;
        int snapShow;

        walk += 1;
        slot = log_slot_of(hwnd);

        /* The lock, the hint, and windows we never snapshotted stay off the list. */
        if (slot < 0) {
            hwnd = GetWindow(hwnd, GW_HWNDNEXT);
            continue;
        }

        if (slot < LOCK_MAX_TRACKED) {
            g_logSeen[slot] = 1;
        }

        liveShow = -1;
        lock_zero(&wp, sizeof(wp));
        wp.length = (UINT)sizeof(wp);
        if (GetWindowPlacement(hwnd, &wp)) {
            liveShow = (int)wp.showCmd;
        }

        lock_zero(&rect, sizeof(rect));
        GetWindowRect(hwnd, &rect);
        snapShow = g_state->tracked[slot].place.showCmd;

        log_puts("  #");
        log_int(rank);
        log_puts(" walk=");
        log_int(walk);
        log_puts(" slot=");
        log_int(slot);
        log_puts(" hwnd=");
        log_hex64((unsigned long long)(UINT_PTR)hwnd);
        log_puts(" live=");
        log_show(liveShow);
        log_puts(" zoom=");
        log_int(IsZoomed(hwnd) ? 1 : 0);
        log_puts(" iconic=");
        log_int(IsIconic(hwnd) ? 1 : 0);
        log_puts(" snap=");
        log_show(snapShow);
        log_puts(" win=");
        log_int(rect.left);
        log_putc(',');
        log_int(rect.top);
        log_putc(',');
        log_int(rect.right);
        log_putc(',');
        log_int(rect.bottom);
        log_puts(" normal=");
        log_int(wp.rcNormalPosition.left);
        log_putc(',');
        log_int(wp.rcNormalPosition.top);
        log_putc(',');
        log_int(wp.rcNormalPosition.right);
        log_putc(',');
        log_int(wp.rcNormalPosition.bottom);
        log_puts(" title=");
        log_title(hwnd);
        log_commit();

        rank += 1;
        hwnd = GetWindow(hwnd, GW_HWNDNEXT);
    }

    /* A destroyed window is not in the walk. Say so instead of dropping it. */
    for (slot = 0; slot < g_state->trackedCount; slot++) {
        if (g_logSeen[slot]) {
            continue;
        }

        log_puts("  missing slot=");
        log_int(slot);
        log_puts(" hwnd=");
        log_hex64((unsigned long long)(UINT_PTR)g_state->tracked[slot].hwnd);
        log_puts(" snap=");
        log_show(g_state->tracked[slot].place.showCmd);
        log_commit();
    }

    log_flush();
}

/* Write the placement list that was just queued. */
static void log_plan_place(const char *which) {
    int i;

    if (!g_logFile) {
        return;
    }

    log_puts("plan ");
    log_puts(which);
    log_puts(" count=");
    log_int(g_paceCount);
    log_puts(" attempt=");
    log_int(g_paceAttempt);
    log_puts(" delayMs=");
    log_int(lock_z_attempt_delay_ms(g_paceAttempt));
    log_commit();

    /* One line per window the timer is about to touch, in send order. */
    for (i = 0; i < g_paceCount && i < LOCK_MAX_TRACKED; i++) {
        int slot;

        slot = g_placeSlots[i];
        log_puts("  item ");
        log_int(i);
        log_puts(" slot=");
        log_int(slot);

        if (g_state && g_state->tracked && slot >= 0 && slot < g_state->trackedCount) {
            log_puts(" hwnd=");
            log_hex64((unsigned long long)(UINT_PTR)g_state->tracked[slot].hwnd);
            log_puts(" snap=");
            log_show(g_state->tracked[slot].place.showCmd);
            log_puts(" title=");
            log_title((HWND)g_state->tracked[slot].hwnd);
        }

        log_commit();
    }

    log_flush();
}

/* Write the z-order moves that were just queued. */
static void log_plan_z(void) {
    int i;

    if (!g_logFile) {
        return;
    }

    log_puts("plan z count=");
    log_int(g_paceCount);
    log_puts(" attempt=");
    log_int(g_paceAttempt);
    log_puts(" delayMs=");
    log_int(lock_z_attempt_delay_ms(g_paceAttempt));
    log_commit();

    /* insertAfter null is the top of the snapshot. The move uses the lock. */
    for (i = 0; i < g_paceCount && i < LOCK_MAX_TRACKED; i++) {
        log_puts("  move ");
        log_int(i);
        log_puts(" hwnd=");
        log_hex64((unsigned long long)(UINT_PTR)g_zMoves[i].hwnd);
        log_puts(" after=");
        if (!g_zMoves[i].insertAfter) {
            /* The plan stores null for the top. The move inserts under the lock. */
            log_puts("lock ");
            log_hex64((unsigned long long)(UINT_PTR)g_hwnd);
        } else {
            log_hex64((unsigned long long)(UINT_PTR)g_zMoves[i].insertAfter);
            log_puts(" slot=");
            log_int(log_slot_of((HWND)g_zMoves[i].insertAfter));
        }
        log_puts(" slot=");
        log_int(log_slot_of((HWND)g_zMoves[i].hwnd));
        log_puts(" title=");
        log_title((HWND)g_zMoves[i].hwnd);
        log_commit();
    }

    log_flush();
}

/* Open baby_screen_lock_log.txt next to this exe, replacing any previous run.
   Failure leaves g_logFile null and the repair does not log. */
static void log_open(void) {
    WCHAR path[560];
    DWORD length;
    DWORD i;
    DWORD dir;
    /* The file name that replaces the exe name. Kept beside the program. */
    static const WCHAR tail[] = L"baby_screen_lock_log.txt";
    int t;

    length = GetModuleFileNameW(NULL, path, 520u);

    /* A missing path or a truncated one is not a place we can write. */
    if (length == 0u || length >= 520u) {
        return;
    }

    dir = 0;

    /* The directory is everything through the last slash. */
    for (i = 0; i < length; i++) {
        if (path[i] == (WCHAR)'\\' || path[i] == (WCHAR)'/') {
            dir = i + 1u;
        }
    }

    t = 0;
    while (tail[t] != 0 && dir + (DWORD)t + 1u < 560u) {
        path[dir + (DWORD)t] = tail[t];
        t += 1;
    }
    path[dir + (DWORD)t] = 0;

    g_logFile = CreateFileW(path, LOG_GENERIC_WRITE, LOG_SHARE_READ | LOG_SHARE_WRITE,
                            NULL, LOG_CREATE_ALWAYS, LOG_FILE_ATTRIBUTE_NORMAL, NULL);

    /* The invalid sentinel is not a file we can write. */
    if (g_logFile == (HANDLE)(LONG_PTR)-1) {
        g_logFile = NULL;
        return;
    }

    log_puts("baby screen lock trace");
    log_commit();
    log_flush();
}

/* Capture the launch arrangement into the permanent table. Called once. */
static void snapshot_windows(void) {
    /* The table lives for the process. A second call would append, so the count starts at zero. */
    if (!g_state) {
        return;
    }

    g_state->trackedCount = 0;
    EnumWindows(snapshot_enum_proc, 0);

    /* The launch order is the arrangement later steps are compared against. */
    log_puts("snapshot count=");
    log_int(g_state->trackedCount);
    log_commit();
    log_zorder("launch");
}

/* Read each tracked window into `observed`. Dead windows are marked not alive. */
static void fill_observations(LockObserved *observed, int count) {
    int i;

    /* No scratch, or the snapshot is empty. */
    if (!observed || count <= 0 || !g_state) {
        return;
    }

    /* One observation per snapshot slot, in the same order. */
    for (i = 0; i < count; i++) {
        HWND hwnd;
        WINDOWPLACEMENT wp;

        hwnd = (HWND)g_state->tracked[i].hwnd;
        lock_zero(&observed[i], sizeof(observed[i]));

        /* The window has been destroyed since launch. Leave it not alive. */
        if (!IsWindow(hwnd)) {
            continue;
        }

        wp.length = (UINT)sizeof(wp);

        /* A placement read that fails is treated as "not observed". */
        if (!GetWindowPlacement(hwnd, &wp)) {
            continue;
        }

        observed[i].alive = 1;
        placement_from_win32(&wp, &observed[i].place);
    }
}

/* Make `hwnd` the foreground window.
   SetForegroundWindow refuses the call when another process already holds
   the foreground, which is the state a touchpad app-switch leaves behind.
   Attaching this thread's input queue to that thread lets the call succeed.
   The attach is skipped when there is no foreground thread or it is already
   ours. SetForegroundWindow still runs when the attach itself fails. The
   other thread is detached before this function returns. */
static void force_foreground(HWND hwnd) {
    HWND foreground;
    DWORD foregroundThread;
    DWORD ourThread;
    int attached;

    /* No window to raise. */
    if (!hwnd) {
        return;
    }

    attached = 0;
    ourThread = GetCurrentThreadId();
    foregroundThread = 0;
    foreground = GetForegroundWindow();

    /* A null foreground has no thread to join. */
    if (foreground) {
        foregroundThread = GetWindowThreadProcessId(foreground, NULL);
    }

    /* Attaching to ourselves, or to thread 0, would not join the foreground queue. */
    if (foregroundThread != 0u && foregroundThread != ourThread) {
        if (AttachThreadInput(ourThread, foregroundThread, TRUE)) {
            attached = 1;
        }
    }

    /* The queues are joined, so this process is allowed to take the foreground. */
    SetForegroundWindow(hwnd);

    /* Leave the other thread's input queue as we found it. */
    if (attached) {
        AttachThreadInput(ourThread, foregroundThread, FALSE);
    }
}

/* Inject one Ctrl+Win+Arrow chord. goRight selects the right arrow. */
static void send_desktop_switch(int goRight) {
    LockKeyStroke strokes[LOCK_STROKE_COUNT];
    INPUT inputs[LOCK_STROKE_COUNT];
    int count;
    int i;

    count = lock_desktop_switch_strokes(goRight, strokes, LOCK_STROKE_COUNT);

    /* A short write would send a partial chord and get stuck holding Win. */
    if (count != LOCK_STROKE_COUNT) {
        return;
    }

    /* Translate the chord strokes into SendInput keyboard events. */
    for (i = 0; i < count; i++) {
        lock_zero(&inputs[i], sizeof(inputs[i]));
        inputs[i].type = INPUT_KEYBOARD;
        inputs[i].u.ki.wVk = (WORD)strokes[i].vk;

        /* Releases carry KEYEVENTF_KEYUP. Presses leave the flag clear. */
        if (strokes[i].keyUp) {
            inputs[i].u.ki.dwFlags = KEYEVENTF_KEYUP;
        }
    }

    /* One call, so the six events stay a single chord. The keyboard hook lets them through. */
    SendInput((UINT)count, inputs, (int)sizeof(INPUT));
}

/* If the lock has left the active virtual desktop, take one step toward it. */
static void ensure_on_desktop(void) {
    BOOL onCurrent;
    HRESULT hr;
    int observation;
    int action;

    /* No manager, or the lock window is not up yet. */
    if (!g_vdm || !g_hwnd || !g_state) {
        return;
    }

    onCurrent = TRUE;
    hr = g_vdm->lpVtbl->IsWindowOnCurrentVirtualDesktop(g_vdm, g_hwnd, &onCurrent);

    /* A failed query must not be read as "switch desktops". */
    if (hr != S_OK) {
        observation = LOCK_VD_QUERY_FAILED;
    /* The lock is on the desktop the user is looking at. */
    } else if (onCurrent) {
        observation = LOCK_VD_ON_CURRENT;
    /* A gesture moved the active desktop away from the lock. */
    } else {
        observation = LOCK_VD_ON_OTHER;
    }

    action = lock_vd_on_check(&g_state->vd, observation);

    /* One step left. The next check, on a later tick, sees whether that was enough. */
    if (action == LOCK_VD_ACT_LEFT) {
        send_desktop_switch(0);
        return;
    }

    /* One step right, after the leftward cap has already been spent. */
    if (action == LOCK_VD_ACT_RIGHT) {
        send_desktop_switch(1);
    }
}

/* Put the lock back to fullscreen topmost, and raise the hint with it. */
static void reassert_lock(void) {
    LockReassert plan;
    int iconic;

    iconic = 0;

    /* IsIconic is only meaningful once the lock window exists. */
    if (g_hwnd) {
        iconic = IsIconic(g_hwnd) ? 1 : 0;
    }

    lock_reassert_actions(g_hwnd != NULL, iconic, g_hintHwnd != NULL, &plan);

    /* ShowWindow(SW_RESTORE) before the move, so a minimized lock accepts the new size. */
    if (plan.unminimize) {
        ShowWindow(g_hwnd, SW_RESTORE);
    }

    /* Fullscreen and topmost without activating via SetWindowPos.
       Foreground goes through the input-queue attach, or a swipe's target keeps it. */
    if (plan.reposition && g_state) {
        SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, g_state->screenW, g_state->screenH,
                     SWP_SHOWWINDOW | SWP_NOACTIVATE);
        force_foreground(g_hwnd);
    }

    /* The hint stays above the lock without taking activation. */
    if (plan.raiseHint) {
        SetWindowPos(g_hintHwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    /* An idle reassert runs four times a second and would bury the trace.
       During a pace it can change foreground between window instructions. */
    if (g_pacePhase != PACE_IDLE) {
        log_zorder("reassert");
    }
}

/* Copy tracked window handles from the live top-to-bottom Z-order into `order`.
   The walk starts at GetTopWindow(NULL) and follows GW_HWNDNEXT. Handles that
   are not in the launch snapshot are skipped, so the lock and the hint do not
   appear in the result. The walk stops at `orderCap` recorded handles, at
   ZORDER_WALK_CAP visited windows, or at the end of the chain. The return
   value is how many handles were recorded. A failed walk returns 0 so the
   caller does not treat it as a reorder. */
static int collect_tracked_zorder(void **order, int orderCap) {
    HWND hwnd;
    int walked;
    int recorded;

    /* No room to write, or the snapshot was never taken. */
    if (!order || orderCap <= 0 || !g_state || !g_state->tracked) {
        return 0;
    }

    recorded = 0;
    walked = 0;
    hwnd = GetTopWindow(NULL);

    /* A looping next-pointer stops at the cap instead of hanging the watchdog. */
    while (hwnd && walked < ZORDER_WALK_CAP && recorded < orderCap) {
        int s;

        walked += 1;
        s = 0;

        /* The table holds at most LOCK_MAX_TRACKED entries. This is not a hot path. */
        while (s < g_state->trackedCount && g_state->tracked[s].hwnd != (void *)hwnd) {
            s += 1;
        }

        /* This top-level window is one we captured at launch. */
        if (s < g_state->trackedCount) {
            order[recorded] = (void *)hwnd;
            recorded += 1;
        }

        hwnd = GetWindow(hwnd, GW_HWNDNEXT);
    }

    return recorded;
}

/* Stop the one-window timer and forget the queued instructions.
   The attempt index is left alone: a failed plan retries at the same pace,
   and a successful cycle clears the index itself. */
static void pace_stop(void) {
    /* The timer is what delivers the next instruction. Drop it first. */
    if (g_hwnd) {
        KillTimer(g_hwnd, IDT_PACE);
    }

    g_pacePhase = PACE_IDLE;
    g_paceIndex = 0;
    g_paceCount = 0;
}

/* Arm the one-window timer at the gap for the current attempt.
   A failed SetTimer leaves the pace idle so the watchdog can try again. */
static void pace_arm(void) {
    unsigned int ms;

    ms = (unsigned int)lock_z_attempt_delay_ms(g_paceAttempt);

    /* No window, or the timer did not start. Do not pretend a pace is running. */
    if (!g_hwnd || !SetTimer(g_hwnd, IDT_PACE, ms, NULL)) {
        g_pacePhase = PACE_IDLE;
        g_paceIndex = 0;
        g_paceCount = 0;
    }
}

/* Climb one attempt, and stop once the gap is already the maximum. */
static void raise_attempt(void) {
    /* Further failures keep the longest gap instead of growing without bound. */
    if (g_paceAttempt < LOCK_Z_ATTEMPT_CAP) {
        g_paceAttempt += 1;
    }
}

/* Queue placement writes for windows that are not maximized in the snapshot.
   The timer sends the first one after the current gap. The list is bottom
   of the snapshot first, so the highest of these windows is shown last. */
static void queue_place(int count) {
    g_pacePhase = PACE_PLACE;
    g_paceIndex = 0;
    g_paceCount = count;

    /* Record the list before the timer is armed, so a failed arm is still visible. */
    log_plan_place("place");
    pace_arm();
}

/* Queue the maximized snapshot windows. This phase runs after normal
   placements and before z-order. Showing one brings it forward. The
   z-order pass that follows puts the snapshot order back and leaves the
   maximized state set. */
static void queue_max(int count) {
    g_pacePhase = PACE_MAX;
    g_paceIndex = 0;
    g_paceCount = count;

    /* Same as the normal placement list. Z-order runs after this phase. */
    log_plan_place("max");
    pace_arm();
}

/* Queue z-order moves. Take the foreground first so the window a swipe
   focused does not stay active. The timer sends the moves one at a time
   after that. The top snapshot window is anchored under the lock. */
static void queue_z(int count) {
    /* The gesture's window stops being the one we cannot climb over. */
    force_foreground(g_hwnd);

    g_pacePhase = PACE_Z;
    g_paceIndex = 0;
    g_paceCount = count;

    /* The foreground change above can itself reorder windows. The plan is the intent. */
    log_plan_z();
    pace_arm();
}

/* Write one drifted placement. Destroyed windows are skipped. The slot
   stays in the snapshot so later indexes do not shuffle. */
static void apply_one_placement(int listIndex) {
    int slot;
    HWND hwnd;

    /* The queue or the snapshot disappeared between the plan and this tick. */
    if (!g_state || !g_state->tracked) {
        return;
    }
    if (listIndex < 0 || listIndex >= g_paceCount || listIndex >= LOCK_MAX_TRACKED) {
        return;
    }

    slot = g_placeSlots[listIndex];

    /* A stale index must not walk off the snapshot table. */
    if (slot < 0 || slot >= g_state->trackedCount) {
        return;
    }

    hwnd = (HWND)g_state->tracked[slot].hwnd;

    /* The window died while we were waiting out the gap. */
    if (!IsWindow(hwnd)) {
        log_puts("step ");
        log_puts(g_pacePhase == PACE_MAX ? "max" : "place");
        log_puts(" skipped dead slot=");
        log_int(slot);
        log_commit();
        log_zorder(g_pacePhase == PACE_MAX ? "after-max" : "after-place");
        return;
    }

    /* The trace records the call result and the stack after Windows has returned. */
    log_puts("step ");
    log_puts(g_pacePhase == PACE_MAX ? "max" : "place");
    log_puts(" i=");
    log_int(listIndex);
    log_puts("/");
    log_int(g_paceCount);
    log_puts(" slot=");
    log_int(slot);
    log_puts(" ok=");
    log_int(restore_one_placement(hwnd, &g_state->tracked[slot].place));
    log_puts(" snap=");
    log_show(g_state->tracked[slot].place.showCmd);
    log_commit();
    log_zorder(g_pacePhase == PACE_MAX ? "after-max" : "after-place");
}

/* 1 when `hwnd` is the highest window that is not topmost.
   The lock and the hint are topmost, so the top snapshot window belongs
   directly under that band. The walk stops at ZORDER_WALK_CAP so a cycle
   cannot hang the pace tick. A null or destroyed hwnd is not that window. */
static int is_top_ordinary(HWND hwnd) {
    HWND walk;
    int guard;

    /* Nothing to find. */
    if (!hwnd || !IsWindow(hwnd)) {
        return 0;
    }

    walk = GetTopWindow(NULL);
    guard = 0;

    /* Skip the topmost band. The next window is the top of the ordinary band. */
    while (walk && guard < ZORDER_WALK_CAP) {
        if ((GetWindowLongW(walk, GWL_EXSTYLE) & (LONG)WS_EX_TOPMOST) == 0) {
            return walk == hwnd;
        }

        walk = GetWindow(walk, GW_HWNDNEXT);
        guard += 1;
    }

    return 0;
}

/* Put the lock, then the hint, back at the top of the topmost band.
   Size and position stay as they are, and neither window is activated.
   A z-order repair calls this so a user window cannot end up covering
   the shield. */
static void raise_shield(void) {
    /* The shield is the lower of the two topmost windows. Raise it first. */
    if (g_hwnd && IsWindow(g_hwnd)) {
        SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    /* The hint stays above the lock, still without taking activation. */
    if (g_hintHwnd && IsWindow(g_hintHwnd)) {
        SetWindowPos(g_hintHwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
}

/* Move one window to just after its predecessor. A null or dead predecessor
   means the top of the snapshot, which is anchored under the lock window.
   SWP_NOOWNERZORDER is not set, so an owned dialog stays above its owner.
   The call does not activate the window, so the lock keeps the foreground. */
static void apply_one_zmove(int listIndex) {
    HWND hwnd;
    HWND after;
    LockZMove *move;
    int anchored;
    int topmostFix;
    int ok;

    /* The queue was cleared, or this index was never filled. */
    if (listIndex < 0 || listIndex >= g_paceCount || listIndex >= LOCK_MAX_TRACKED) {
        return;
    }

    move = &g_zMoves[listIndex];
    hwnd = (HWND)move->hwnd;
    anchored = 0;
    topmostFix = 0;

    /* The window died during the gap. The next attempt plans without it. */
    if (!IsWindow(hwnd)) {
        log_puts("step z skipped dead hwnd=");
        log_hex64((unsigned long long)(UINT_PTR)hwnd);
        log_commit();
        log_zorder("after-z");
        return;
    }

    /* Null is the top of the snapshot. A predecessor that died cannot
       anchor the insert. Both use the lock. HWND_TOP is not used. */
    if (!move->insertAfter || !IsWindow((HWND)move->insertAfter)) {
        after = g_hwnd;
        anchored = 1;
    } else {
        after = (HWND)move->insertAfter;
    }

    /* No lock yet. Leave the window where it is. The next plan retries. */
    if (!after || !IsWindow(after)) {
        log_puts("step z skipped no-anchor hwnd=");
        log_hex64((unsigned long long)(UINT_PTR)hwnd);
        log_commit();
        log_zorder("after-z");
        return;
    }

    /* Insert under the real window. NOACTIVATE keeps the lock in front. */
    ok = SetWindowPos(hwnd, after, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) ? 1 : 0;

    /* A direct insert under the topmost lock can be ignored, or it can
       promote the window. Promote, then drop it: that lands it under every
       topmost window and above every other ordinary window. */
    if (anchored && !is_top_ordinary(hwnd)) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        topmostFix = 1;
    }

    /* The shield pair goes back above whatever this move just did. */
    if (anchored) {
        raise_shield();
    }

    /* The trace records whether the insert was accepted, then the live stack. */
    log_puts("step z i=");
    log_int(listIndex);
    log_puts("/");
    log_int(g_paceCount);
    log_puts(" hwnd=");
    log_hex64((unsigned long long)(UINT_PTR)hwnd);
    log_puts(" after=");
    log_hex64((unsigned long long)(UINT_PTR)after);
    log_puts(" ok=");
    log_int(ok);
    if (anchored) {
        log_puts(" topmostFix=");
        log_int(topmostFix);
    }
    log_commit();
    log_zorder("after-z");
}

/* Copy drifted slot indexes into g_placeSlots.
   `maximized` is LOCK_PLACE_NORMAL or LOCK_PLACE_MAXIMIZED. The tick bump
   is reset before the return, so the only result that survives is the
   fixed table. Returns the count, 0 when that set did not drift, or -1
   when the plan could not be built. */
static int plan_placement_slots(int maximized) {
    LockObserved *observed;
    int count;
    int n;

    /* Nothing was captured, so there is no placement to put back. */
    if (!g_state || !g_state->tracked || g_state->trackedCount <= 0) {
        return 0;
    }

    /* Drop the previous plan's scratch. The block stays reserved. */
    lock_bump_reset(&g_tick);
    count = g_state->trackedCount;
    observed = (LockObserved *)lock_bump_alloc(
        &g_tick,
        (unsigned long long)sizeof(LockObserved) * (unsigned long long)count,
        8ull);

    /* The tick block is far larger than this list. A null means it was not reset. */
    if (!observed) {
        return -1;
    }

    fill_observations(observed, count);

    /* Nothing drifted. Skip the slot list. */
    if (!lock_windows_need_restore(g_state->tracked, count, observed)) {
        lock_bump_reset(&g_tick);
        return 0;
    }

    n = lock_placement_move_slots(g_state->tracked, count, observed,
                                  g_placeSlots, LOCK_MAX_TRACKED, maximized);

    /* The indexes now live in g_placeSlots. The observation list does not. */
    lock_bump_reset(&g_tick);
    return n;
}

/* Copy the minimum z-order moves into g_zMoves. Same bump rule as the
   placement plan. Returns the count, 0 when the relative order already
   matches, or -1 when the walk or the scratch could not be built. */
static int plan_z_moves(void) {
    void **order;
    int count;
    int orderCount;
    int n;

    /* Nothing was captured, so there is no order to rebuild. */
    if (!g_state || !g_state->tracked || g_state->trackedCount <= 0) {
        return 0;
    }

    lock_bump_reset(&g_tick);
    count = g_state->trackedCount;
    order = (void **)lock_bump_alloc(
        &g_tick,
        (unsigned long long)sizeof(void *) * (unsigned long long)count,
        8ull);

    /* A failed walk must not look like a reorder. */
    if (!order) {
        return -1;
    }

    orderCount = collect_tracked_zorder(order, count);

    /* The tracked windows are already in snapshot order. */
    if (!lock_zorder_differs(g_state->tracked, count, order, orderCount)) {
        lock_bump_reset(&g_tick);
        return 0;
    }

    n = lock_z_minimum_moves(g_state->tracked, count, order, orderCount,
                             &g_tick, g_zMoves, LOCK_MAX_TRACKED);

    /* The moves now live in g_zMoves. The walk does not. */
    lock_bump_reset(&g_tick);
    return n;
}

/* Queue maximized placements when that set still differs.
   Returns 1 if a phase was armed, 0 if those windows already match,
   and -1 if the plan could not be built. Does not climb the attempt:
   maximizing is a step of the attempt already running, before z-order. */
static int queue_maximized_phase(void) {
    int maxes;

    maxes = plan_placement_slots(LOCK_PLACE_MAXIMIZED);

    /* Leave the attempt where it is. The watchdog retries the whole order. */
    if (maxes < 0) {
        return -1;
    }

    /* Shown bottom-up. The z-order pass after this phase puts back the
       windows that belong above them, and leaves these maximized. */
    if (maxes > 0) {
        queue_max(maxes);
        return 1;
    }

    return 0;
}

/* Look again after the instructions have had the current gap to land.
   A clean stack resets the attempt so the next gesture starts at the
   short gap. A stack that is still wrong starts another attempt at a
   longer gap, and that attempt moves only the windows still out of place.
   Placements are queued before z-order, so a show is not the last
   instruction of the retry. */
static void finish_pace_cycle(void) {
    int places;
    int zMoves;
    int maxes;

    places = plan_placement_slots(LOCK_PLACE_NORMAL);

    /* The plan could not be built. Leave the attempt where it is and retry later. */
    if (places < 0) {
        log_puts("finish plan normal failed");
        log_commit();
        log_zorder("finish");
        pace_stop();
        return;
    }

    /* Normal placements still differ. The new list is only those windows. */
    if (places > 0) {
        log_puts("finish retry place");
        log_commit();
        log_zorder("retry");
        raise_attempt();
        queue_place(places);
        return;
    }

    maxes = plan_placement_slots(LOCK_PLACE_MAXIMIZED);

    /* Could not read the maximized set. Retry later at this same gap. */
    if (maxes < 0) {
        log_puts("finish plan max failed");
        log_commit();
        log_zorder("finish");
        pace_stop();
        return;
    }

    /* Still not maximized. The longer gap applies to this write too.
       The max phase settles into z-order, so this show is not last. */
    if (maxes > 0) {
        log_puts("finish retry max");
        log_commit();
        log_zorder("retry");
        raise_attempt();
        queue_max(maxes);
        return;
    }

    zMoves = plan_z_moves();

    /* Same as a failed placement plan: do not pretend the stack is clean. */
    if (zMoves < 0) {
        log_puts("finish plan z failed");
        log_commit();
        log_zorder("finish");
        pace_stop();
        return;
    }

    /* Order still differs. Move only the windows outside the stable run. */
    if (zMoves > 0) {
        log_puts("finish retry z");
        log_commit();
        log_zorder("retry");
        raise_attempt();
        queue_z(zMoves);
        return;
    }

    /* Placements and z-order match. Sample first, then drop the pace. */
    log_puts("finish clean");
    log_commit();
    log_zorder("clean");
    g_paceAttempt = 0;
    pace_stop();
    reassert_lock();
}

/* One pace tick. Sends a single window instruction, or, on a settle tick,
   reads the stack and continues. Normal placements settle into maximized
   placements, those settle into z-order, and z-order settles into a recheck. */
static void on_pace_timer(void) {
    /* A nested size message must not start a second step on top of this one. */
    if (g_repairing || !g_state || !g_hwnd) {
        return;
    }

    g_repairing = 1;

    /* Placement instructions, one window per tick.
       Normal windows settle into the maximized phase. Maximized windows
       settle into z-order. */
    if (g_pacePhase == PACE_PLACE || g_pacePhase == PACE_MAX) {
        int settle;

        settle = (g_pacePhase == PACE_PLACE) ? PACE_PLACE_SETTLE : PACE_MAX_SETTLE;

        if (g_paceIndex < g_paceCount) {
            apply_one_placement(g_paceIndex);
            g_paceIndex += 1;
        }

        /* The next tick is the gap those writes need before we read them back. */
        if (g_paceIndex >= g_paceCount) {
            g_pacePhase = settle;
        }

        g_repairing = 0;
        return;
    }

    /* The normal placements have had one gap. Maximize next, then z-order.
       A show jumps that window forward, so z-order has to follow the shows. */
    if (g_pacePhase == PACE_PLACE_SETTLE) {
        int zMoves;
        int maxes;

        /* The gap after the last normal placement. Later lines are the decision. */
        log_zorder("place-settle");
        maxes = queue_maximized_phase();

        /* Could not plan. The watchdog retries without climbing the attempt. */
        if (maxes < 0) {
            pace_stop();
            g_repairing = 0;
            return;
        }

        /* Maximized windows still differ. Their settle tick queues z-order. */
        if (maxes > 0) {
            g_repairing = 0;
            return;
        }

        /* Nothing left to show. Put the snapshot order back. */
        zMoves = plan_z_moves();

        if (zMoves < 0) {
            pace_stop();
        } else if (zMoves > 0) {
            queue_z(zMoves);
        } else {
            finish_pace_cycle();
        }

        g_repairing = 0;
        return;
    }

    /* Z-order instructions, one window per tick. */
    if (g_pacePhase == PACE_Z) {
        if (g_paceIndex < g_paceCount) {
            apply_one_zmove(g_paceIndex);
            g_paceIndex += 1;
        }

        /* The next tick reads the stack after the last move has had a gap. */
        if (g_paceIndex >= g_paceCount) {
            g_pacePhase = PACE_Z_SETTLE;
        }

        g_repairing = 0;
        return;
    }

    /* Z-order has had one gap. Recheck placements and order. */
    if (g_pacePhase == PACE_Z_SETTLE) {
        /* The gap after the last z-order move. The recheck decides the retry. */
        log_zorder("z-settle");
        finish_pace_cycle();
        g_repairing = 0;
        return;
    }

    /* The maximized writes have had one gap. Z-order next, since each show
       brought that window forward. */
    if (g_pacePhase == PACE_MAX_SETTLE) {
        int zMoves;

        /* The gap after the last maximized write, before any z-order move. */
        log_zorder("max-settle");
        zMoves = plan_z_moves();

        /* Could not read the order. The watchdog will try again. */
        if (zMoves < 0) {
            pace_stop();
        } else if (zMoves > 0) {
            queue_z(zMoves);
        } else {
            finish_pace_cycle();
        }

        g_repairing = 0;
        return;
    }

    /* A tick with no phase should not keep firing. */
    pace_stop();
    g_repairing = 0;
}

/* Start a paced repair when none is running. Reassert the lock, then queue
   normal placements, then maximized placements, then z-order. Z-order is
   last because each show brings its window forward.
   Does nothing when a pace is already in progress: that pace will notice
   whatever this gesture changed on its next settle. */
static void start_paced_repair(void) {
    int places;
    int zMoves;
    int maxes;

    /* Nested from ShowWindow, or a pace is already sending instructions. */
    if (g_repairing || g_pacePhase != PACE_IDLE || !g_state || !g_hwnd) {
        return;
    }

    g_repairing = 1;

    /* The shield goes back to fullscreen before any user window is touched. */
    reassert_lock();

    places = plan_placement_slots(LOCK_PLACE_NORMAL);

    /* Try again on a later watchdog tick. Do not blast every window instead. */
    if (places < 0) {
        g_repairing = 0;
        return;
    }

    /* Windows that should not be maximized, bottom of the snapshot first. */
    if (places > 0) {
        log_puts("repair place");
        log_commit();
        log_zorder("gesture");
        queue_place(places);
        g_repairing = 0;
        return;
    }

    maxes = plan_placement_slots(LOCK_PLACE_MAXIMIZED);

    if (maxes < 0) {
        g_repairing = 0;
        return;
    }

    /* A maximized window is queued. Its settle tick runs z-order after. */
    if (maxes > 0) {
        log_puts("repair max");
        log_commit();
        log_zorder("gesture");
        queue_max(maxes);
        g_repairing = 0;
        return;
    }

    zMoves = plan_z_moves();

    if (zMoves < 0) {
        g_repairing = 0;
        return;
    }

    /* Only the windows that are outside the already-correct run. */
    if (zMoves > 0) {
        log_puts("repair z");
        log_commit();
        log_zorder("gesture");
        queue_z(zMoves);
        g_repairing = 0;
        return;
    }

    /* Nothing is drifted. A later gesture starts at the short gap again. */
    g_paceAttempt = 0;
    g_repairing = 0;
}

/* Timer visit. Start a paced repair when one is not already running, then
   take at most one virtual-desktop step. The desktop counter advances only
   here. The pace timer does not call this function, so a long z-order
   attempt cannot walk desktops faster than the switch animation. */
static void run_watchdog(void) {
    /* No permanent state yet. There is nothing to repair and no counter to advance. */
    if (!g_state) {
        return;
    }

    /* A pace already owns the user-window instructions. Keep the shield up. */
    if (g_pacePhase == PACE_IDLE) {
        start_paced_repair();
    } else {
        reassert_lock();
    }

    /* Pace the desktop query to every other tick so a switch animation can finish. */
    g_state->vdTick += 1;

    /* Even ticks query the desktop. Odd ticks let a switch animation finish. */
    if (lock_vd_check_this_tick(g_state->vdTick)) {
        ensure_on_desktop();
    }
}

/* Eat physical keys. Pass injected keys. Post WM_CLOSE when Z and M are both held. */
static LRESULT low_level_keyboard_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    KBDLLHOOKSTRUCT *kb;
    LockKeyDecision decision;
    int isAction;
    int isInjected;
    int transition;
    unsigned int vk;

    isAction = (nCode == HC_ACTION) ? 1 : 0;
    isInjected = 0;
    transition = LOCK_KEY_OTHER;
    vk = 0;
    kb = (KBDLLHOOKSTRUCT *)lParam;

    /* The payload is only meaningful for an action the hook is allowed to read. */
    if (isAction && kb) {
        isInjected = (kb->flags & LLKHF_INJECTED) ? 1 : 0;
        transition = key_transition_from_message((UINT)wParam);
        vk = kb->vkCode;
    } else {
        /* No payload to read, so the event is not treated as an action. */
        isAction = 0;
    }

    /* No permanent state yet: do not eat keys, because the latch would be lost. */
    if (!g_state) {
        return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
    }

    decision = lock_key_on_event(&g_state->keys, isAction, isInjected, transition, vk);

    /* The chord is complete. WM_CLOSE ends the lock on this thread. */
    if (decision.requestExit && g_hwnd) {
        PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
    }

    /* Physical keys stop here, including the Z and M that completed the chord. */
    if (decision.swallow) {
        return 1;
    }

    return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

/* Eat low-level mouse actions so clicks and motion do not reach other windows. */
static LRESULT low_level_mouse_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    /* HC_ACTION is swallowed. Any other code continues down the hook chain. */
    if (lock_mouse_should_call_next(nCode == HC_ACTION)) {
        return CallNextHookEx(g_mouseHook, nCode, wParam, lParam);
    }

    return 1;
}

/* Lock window procedure. The window is a nearly invisible input shield. */
static LRESULT lock_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    /* The window handle and lParam are unused. The messages we care about carry wParam. */
    (void)hwnd;
    (void)lParam;

    /* Choose the messages that keep the shield up. Everything else is default. */
    switch (msg) {
    case WM_DESTROY:
        /* Leave the message loop. The low-level hooks are dropped after
           GetMessage returns, and then the process exits. */
        PostQuitMessage(0);
        return 0;

    case WM_SIZE:
        /* A gesture minimized the lock. Raise the shield now. Queue user-window
           repairs only when a pace is not already sending them. */
        if (wParam == SIZE_MINIMIZED) {
            reassert_lock();
            if (g_pacePhase == PACE_IDLE) {
                start_paced_repair();
            }
        }
        return 0;

    case WM_LOCK_REPAIR:
        /* Focus, move, switch, minimize, or a desktop change.
           An in-progress pace keeps its gap. A new one would fight it. */
        if (g_pacePhase == PACE_IDLE) {
            start_paced_repair();
        }
        return 0;

    case WM_TIMER:
        /* One window instruction, or the 250 ms shield and desktop step. */
        if (wParam == IDT_PACE) {
            on_pace_timer();
        } else if (wParam == IDT_REASSERT) {
            run_watchdog();
        }
        return 0;

    case WM_ERASEBKGND:
        /* The layered window has no background paint. Say the erase already happened. */
        return 1;

    default:
        break;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* Hint window procedure. Draws the exit chord on a small dark pill. */
static LRESULT hint_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    /* Paint uses the window. The other two parameters are not needed for these messages. */
    (void)wParam;
    (void)lParam;

    /* Paint and erase are handled here. Other messages use the default procedure. */
    switch (msg) {
    case WM_PAINT: {
        /* Draw the dark pill and the exit chord into the hint window. */
        PAINTSTRUCT ps;
        HDC hdc;
        RECT rc;
        HBRUSH pillBrush;
        HFONT font;
        HGDIOBJ oldFont;

        /* BeginPaint validates the region even when we draw nothing. */
        hdc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rc);

        /* Fill the pill. This brush is a per-paint GDI object, so it is deleted
           before EndPaint. GDI handles are a small process-wide table. */
        pillBrush = CreateSolidBrush(RGB(30, 30, 30));
        FillRect(hdc, &rc, pillBrush);
        DeleteObject((HGDIOBJ)pillBrush);

        /* Bold Segoe UI, then the permanent hint string centered in the pill. */
        font = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS,
                           (LPCWSTR)L"Segoe UI");
        oldFont = SelectObject(hdc, (HGDIOBJ)font);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));

        /* The hint was copied into the permanent block at startup. */
        if (g_state && g_state->exitHint) {
            DrawTextW(hdc, (LPCWSTR)g_state->exitHint, -1, &rc, DT_CENTER | DT_NOCLIP);
        }

        /* Put the previous font back, then delete the one this paint created. */
        SelectObject(hdc, oldFont);
        DeleteObject((HGDIOBJ)font);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        /* WM_PAINT fills the whole client area. Skip the extra erase. */
        return 1;

    default:
        break;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* Register one window class. Returns 0 when registration fails. */
static int register_one_class(HINSTANCE instance, const WCHAR *name,
                              LRESULT (*proc)(HWND, UINT, WPARAM, LPARAM),
                              HBRUSH background) {
    WNDCLASSEXW wc;

    lock_zero(&wc, sizeof(wc));
    wc.cbSize = (UINT)sizeof(wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = instance;
    wc.lpszClassName = name;
    wc.hCursor = NULL;
    wc.hbrBackground = background;

    /* A zero atom means the class was not registered. */
    if (!RegisterClassExW(&wc)) {
        return 0;
    }

    return 1;
}

/* Reserve both blocks, bind the permanent layout, and init the tick bump.
   Returns 0 when either VirtualAlloc fails or the layout does not fit.
   On failure the blocks that did get allocated are left for process teardown. */
static int create_memory(void) {
    void *permanent;
    void *tick;
    int hintChars;

    /* Current process, so VirtualAlloc rather than VirtualAllocEx. */
    permanent = VirtualAlloc(NULL, PERMANENT_BLOCK_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    tick = VirtualAlloc(NULL, TICK_BLOCK_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    /* One missing block means the lock cannot keep its snapshot or its tick scratch. */
    if (!permanent || !tick) {
        return 0;
    }

    hintChars = wide_length(g_exitHintLiteral);

    /* Static header at the front, bump table and hint after it. The tail is not reset. */
    if (!lock_permanent_bind(permanent, PERMANENT_BLOCK_BYTES, LOCK_MAX_TRACKED,
                             (const unsigned short *)g_exitHintLiteral, hintChars, &g_state)) {
        return 0;
    }

    /* The hint and the table must have moved the permanent cursor. */
    if (!g_state || lock_bump_used(&g_state->tail) == 0ull) {
        return 0;
    }

    /* The tick cursor starts at zero. Each plan resets it after copying its result. */
    lock_bump_init(&g_tick, tick, TICK_BLOCK_BYTES);
    return 1;
}

/* WinEvent hook procedure. The interesting arguments are the event id.
   Anything else is ignored. A repair is posted to the lock window so the
   restack runs on the UI thread's message pump, not on the hook callback.
   Events this process caused are already filtered by WINEVENT_SKIPOWNPROCESS.
   Scroll and menu events fail lock_event_needs_repair and are dropped here. */
static void win_event_proc(void *hook, DWORD event, HWND hwnd,
                                   LONG idObject, LONG idChild,
                                   DWORD eventThread, DWORD eventTime) {
    /* The hook, the target window, and the timing are not used to decide. */
    (void)hook;
    (void)hwnd;
    (void)idObject;
    (void)idChild;
    (void)eventThread;
    (void)eventTime;

    /* The lock window is the only place that owns the repair. */
    if (!g_hwnd) {
        return;
    }

    /* Scroll, capture, and menu traffic shares this hook range and must not restack. */
    if (!lock_event_needs_repair(event)) {
        return;
    }

    PostMessageW(g_hwnd, WM_LOCK_REPAIR, 0, 0);
}

/*
 * Fuzzing self-test.
 *
 * WinMainCRTStartup runs this instead of the lock when the command line
 * contains --self-test. A failure writes out\self_test.txt and exits with
 * the source line of the failing check as the process code. Coverage flags
 * are asserted at the end of each fuzz so a generator that stops producing
 * a case cannot pass quietly.
 *
 * The generator is a fixed-seed PCG. The same failure happens on the next run.
 */

#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 0x00000001u
#define CREATE_ALWAYS 2u
#define FILE_ATTRIBUTE_NORMAL 0x00000080u
#define STD_OUTPUT_HANDLE ((DWORD)-11)

/* Log file in out\self_test.txt. Invalid until run_self_test opens it. */
static HANDLE g_log = INVALID_HANDLE_VALUE;

/* Console handle. Invalid when the process has no stdout. */
static HANDLE g_stdout = INVALID_HANDLE_VALUE;

/* PCG state. run_self_test sets both so the stream is visible in one place. */
static unsigned long long g_rngState = 0;
static unsigned long long g_rngInc = 0;

/* Write one C string to a handle. Returns 0 when the write is short or fails. */
static int write_text(HANDLE file, const char *text) {
    DWORD length;
    DWORD written;

    length = 0;

    /* Measure. The log strings are short literals and decimal numbers. */
    while (text[length] != 0) {
        length += 1;
    }

    /* An empty string is a successful no-op. */
    if (length == 0) {
        return 1;
    }

    written = 0;

    /* A short write would leave a log that looks like a pass. Treat it as failure. */
    if (!WriteFile(file, text, length, &written, NULL) || written != length) {
        return 0;
    }

    return 1;
}

/* Append a line to the log file and to stdout. A failed log write aborts. */
static void test_log(const char *text) {
    /* Stdout is best-effort. The file is the record the exit code points at. */
    if (g_stdout != INVALID_HANDLE_VALUE && g_stdout != NULL) {
        write_text(g_stdout, text);
    }

    /* The self-test cannot continue once it cannot record a failure. */
    if (g_log == INVALID_HANDLE_VALUE || !write_text(g_log, text)) {
        /* Close a half-written log before the abort so the bytes hit disk. */
        if (g_log != INVALID_HANDLE_VALUE) {
            CloseHandle(g_log);
        }
        ExitProcess(0xFFFFFFFEu);
    }
}

/* Write an unsigned value in decimal. Used for the failing source line. */
static void test_log_uint(unsigned long long value) {
    char digits[24];
    char out[24];
    int count;
    int i;

    count = 0;

    /* Zero is a digit. The loop below would otherwise emit an empty string. */
    if (value == 0ull) {
        digits[count] = '0';
        count += 1;
    }

    /* Collect digits least-significant first. */
    while (value > 0ull) {
        digits[count] = (char)('0' + (value % 10ull));
        count += 1;
        value /= 10ull;
    }

    /* Reverse them into the printed order. */
    for (i = 0; i < count; i++) {
        out[i] = digits[count - 1 - i];
    }
    out[count] = 0;
    test_log(out);
}

/* Record the failing line and stop. The process code is that line number. */
static void test_fail_at_line(int line) {
    test_log("\r\n*** FAILED at source line ");
    test_log_uint((unsigned long long)line);
    test_log(" ***\r\n");

    /* Close the log so the failure line is flushed before the process ends. */
    if (g_log != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log);
        g_log = INVALID_HANDLE_VALUE;
    }
    ExitProcess((DWORD)line);
}

/* Exit with the source line when cond is true. The do/while keeps the macro a statement. */
#define crash_if(cond) do { if (cond) test_fail_at_line(__LINE__); } while (0)

/* Next PCG-XSH-RR value. The stream is fully determined by g_rngState and g_rngInc. */
static unsigned int rng(void) {
    unsigned long long old;
    unsigned int xorshifted;
    unsigned int rot;

    old = g_rngState;

    /* Advance the LCG. The increment is the stream selector and must be odd. */
    g_rngState = old * 6364136223846793005ull + g_rngInc;
    xorshifted = (unsigned int)(((old >> 18) ^ old) >> 27);
    rot = (unsigned int)(old >> 59);
    return (xorshifted >> rot) | (xorshifted << ((0u - rot) & 31u));
}

/* Inclusive integer in [first, last]. first must be less than or equal to last. */
static int rand_range(int first, int last) {
    unsigned int span;

    crash_if(first > last);

    /* A one-point range does not need a random draw. */
    if (first == last) {
        return first;
    }

    span = (unsigned int)(last - first) + 1u;
    return (int)(rng() % span) + first;
}

/* Fair coin from the low bit of the generator. */
static int coin_flip(void) {
    /* 0 or 1, used to pick injected vs physical and similar forks. */
    if ((rng() & 1u) == 0u) {
        return 0;
    }
    return 1;
}

/* Alignment helper: powers of two, rejection of bad aligns, and wrap. */
static void test_align_up(void) {
    int sawExact;
    int sawRound;
    int sawReject;
    int sawWrap;
    int i;

    sawExact = 0;
    sawRound = 0;
    sawReject = 0;
    sawWrap = 0;

    crash_if(lock_align_up(0ull, 8ull) != 0ull);
    crash_if(lock_align_up(8ull, 8ull) != 8ull);
    sawExact = 1;

    crash_if(lock_align_up(1ull, 8ull) != 8ull);
    crash_if(lock_align_up(9ull, 16ull) != 16ull);
    sawRound = 1;

    crash_if(lock_align_up(4ull, 0ull) != ~0ull);
    crash_if(lock_align_up(4ull, 3ull) != ~0ull);
    crash_if(lock_align_up(4ull, 6ull) != ~0ull);
    sawReject = 1;

    crash_if(lock_align_up(~0ull, 8ull) != ~0ull);
    crash_if(lock_align_up(~0ull - 6ull, 8ull) != ~0ull);
    sawWrap = 1;

    /* Already-aligned values near the top of the range still round cleanly. */
    crash_if(lock_align_up(~0ull - 7ull, 8ull) != (~0ull - 7ull));

    /* Random powers of two: the result is aligned and not below the input. */
    for (i = 0; i < 200; i++) {
        unsigned long long value;
        unsigned long long align;
        unsigned long long got;

        value = ((unsigned long long)rng() << 32) ^ (unsigned long long)rng();
        align = 1ull << rand_range(0, 12);
        got = lock_align_up(value, align);

        /* Wrap is reported as ~0ull. Every other result is a multiple of align. */
        if (got == ~0ull) {
            /* This input could not be rounded without wrapping. */
            sawWrap = 1;
        } else {
            /* A successful round is aligned and is never below the input. */
            crash_if((got & (align - 1ull)) != 0ull);
            crash_if(got < value);
        }
    }

    crash_if(!sawExact);
    crash_if(!sawRound);
    crash_if(!sawReject);
    crash_if(!sawWrap);
    test_log("align up ................. OK\r\n");
}

/* lock_zero and lock_copy, including the empty-length null-pointer case. */
static void test_memory_bytes(void) {
    unsigned char dst[16];
    unsigned char src[16];
    int i;

    /* A zero length does not touch a null pointer. */
    lock_zero(NULL, 0ull);
    lock_copy(NULL, NULL, 0ull);

    /* Paint, clear, and check every byte. */
    for (i = 0; i < 16; i++) {
        dst[i] = 0xA5;
        src[i] = (unsigned char)(i + 1);
    }
    lock_zero(dst, 16ull);
    for (i = 0; i < 16; i++) {
        crash_if(dst[i] != 0);
    }

    /* Copy a prefix and leave the tail of the destination alone. */
    for (i = 0; i < 16; i++) {
        dst[i] = 0x3C;
    }
    lock_copy(dst, src, 8ull);
    for (i = 0; i < 8; i++) {
        crash_if(dst[i] != src[i]);
    }
    for (i = 8; i < 16; i++) {
        crash_if(dst[i] != 0x3C);
    }

    test_log("zero and copy ............ OK\r\n");
}

/* Bump cursor: alignment, exact fit, overflow that does not move the cursor, and reset. */
static void test_bump(void) {
    unsigned char raw[256];
    unsigned char *block;
    LockBump bump;
    LockBump empty;
    unsigned char *first;
    unsigned char *again;
    unsigned char *p;
    unsigned long long usedBefore;
    int sawFit;
    int sawOverflow;
    int sawReset;
    int sawPad;
    int sawBadAlign;
    int sawZeroRejected;
    int i;
    int nrec;
    struct {
        unsigned char *ptr;
        unsigned long long size;
        unsigned char tag;
    } rec[64];

    sawFit = 0;
    sawOverflow = 0;
    sawReset = 0;
    sawPad = 0;
    sawBadAlign = 0;
    sawZeroRejected = 0;

    /* A null record is ignored. A null block becomes an empty arena. */
    lock_bump_init(NULL, raw, 16ull);
    lock_bump_init(&empty, NULL, 32ull);
    crash_if(lock_bump_used(&empty) != 0ull);
    crash_if(lock_bump_used(NULL) != 0ull);
    crash_if(lock_bump_alloc(&empty, 1ull, 1ull) != NULL);
    lock_bump_reset(NULL);
    lock_bump_reset(&empty);
    crash_if(empty.used != 0ull);

    /* Exact fit of the whole buffer, then one more byte must fail and leave the cursor. */
    lock_bump_init(&bump, raw, 32ull);
    p = (unsigned char *)lock_bump_alloc(&bump, 32ull, 1ull);
    crash_if(p != raw);
    crash_if(lock_bump_used(&bump) != 32ull);
    usedBefore = lock_bump_used(&bump);
    crash_if(lock_bump_alloc(&bump, 1ull, 1ull) != NULL);
    crash_if(lock_bump_used(&bump) != usedBefore);
    sawFit = 1;
    sawOverflow = 1;

    /* Zero bytes and a non-power-of-two alignment do not move the cursor. */
    lock_bump_init(&bump, raw, 64ull);
    crash_if(lock_bump_alloc(&bump, 0ull, 8ull) != NULL);
    crash_if(lock_bump_used(&bump) != 0ull);
    sawZeroRejected = 1;
    crash_if(lock_bump_alloc(&bump, 4ull, 3ull) != NULL);
    crash_if(lock_bump_alloc(&bump, 4ull, 0ull) != NULL);
    crash_if(lock_bump_used(&bump) != 0ull);
    sawBadAlign = 1;
    crash_if(lock_bump_alloc(NULL, 4ull, 4ull) != NULL);

    /* used == 1 forces the next 8-aligned object to skip the padding bytes. */
    bump.used = 1ull;
    p = (unsigned char *)lock_bump_alloc(&bump, 1ull, 8ull);
    crash_if(p != raw + 8);
    crash_if(lock_bump_used(&bump) != 9ull);
    sawPad = 1;

    /* Reset brings the cursor back. The next aligned alloc starts at the base. */
    lock_bump_reset(&bump);
    crash_if(lock_bump_used(&bump) != 0ull);
    again = (unsigned char *)lock_bump_alloc(&bump, 8ull, 8ull);
    crash_if(again != raw);
    sawReset = 1;

    /* Fuzz a real block: paint each successful object and check the paint survives. */
    block = (unsigned char *)VirtualAlloc(NULL, 65536ull, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    crash_if(!block);
    lock_bump_init(&bump, block, 65536ull);
    nrec = 0;

    for (i = 0; i < 400; i++) {
        unsigned long long size;
        unsigned long long align;
        unsigned long long before;
        unsigned char tag;
        int a;

        size = (unsigned long long)rand_range(1, 200);
        a = rand_range(0, 4);
        align = 1ull << a;
        before = lock_bump_used(&bump);
        tag = (unsigned char)rand_range(1, 255);
        p = (unsigned char *)lock_bump_alloc(&bump, size, align);

        /* Failure must leave the cursor where it was. */
        if (!p) {
            crash_if(lock_bump_used(&bump) != before);
            sawOverflow = 1;
        } else {
            /* The object lies inside the block on the requested alignment. */
            unsigned long long off;
            unsigned long long k;

            off = (unsigned long long)(p - block);
            crash_if((off & (align - 1ull)) != 0ull);
            crash_if(off + size > 65536ull);
            crash_if(lock_bump_used(&bump) < before);

            /* Paint the object. A later check proves no later alloc overlapped it. */
            for (k = 0; k < size; k++) {
                p[k] = tag;
            }

            /* Remember a sample of objects. The table is a ring once it is full. */
            if (nrec < 64) {
                rec[nrec].ptr = p;
                rec[nrec].size = size;
                rec[nrec].tag = tag;
                nrec += 1;
            }
        }
    }

    /* Every remembered object still holds the byte it was painted with. */
    for (i = 0; i < nrec; i++) {
        unsigned long long k;

        for (k = 0; k < rec[i].size; k++) {
            crash_if(rec[i].ptr[k] != rec[i].tag);
        }
    }

    crash_if(nrec < 1);
    first = rec[0].ptr;
    lock_bump_reset(&bump);
    crash_if(lock_bump_used(&bump) != 0ull);
    again = (unsigned char *)lock_bump_alloc(&bump, 8ull, 8ull);
    crash_if(again != block);
    crash_if(first < block || first >= block + 65536);
    sawReset = 1;

    crash_if(!sawFit);
    crash_if(!sawOverflow);
    crash_if(!sawReset);
    crash_if(!sawPad);
    crash_if(!sawBadAlign);
    crash_if(!sawZeroRejected);
    test_log("bump allocator ........... 400 cases OK\r\n");
}

/* Exit chord: scripted Z+M sequence, injected pass-through, then random events. */
static void test_keys(void) {
    LockKeyLatch latch;
    LockKeyDecision decision;
    int sawExit;
    int sawSwallow;
    int sawPass;
    int sawInjected;
    int sawRelease;
    int sawIgnored;
    int i;
    unsigned int keys[6];

    sawExit = 0;
    sawSwallow = 0;
    sawPass = 0;
    sawInjected = 0;
    sawRelease = 0;
    sawIgnored = 0;

    lock_key_latch_clear(&latch);
    crash_if(latch.zHeld != 0 || latch.mHeld != 0);
    lock_key_latch_clear(NULL);

    /* Z down is eaten and held. M is still up, so this is not an exit. */
    decision = lock_key_on_event(&latch, 1, 0, LOCK_KEY_DOWN, LOCK_VK_Z);
    crash_if(!decision.swallow);
    crash_if(decision.callNext);
    crash_if(decision.requestExit);
    crash_if(latch.zHeld != 1 || latch.mHeld != 0);
    sawSwallow = 1;

    /* Auto-repeat of Z stays held and still does not exit. */
    decision = lock_key_on_event(&latch, 1, 0, LOCK_KEY_DOWN, LOCK_VK_Z);
    crash_if(!decision.swallow);
    crash_if(decision.requestExit);
    crash_if(latch.zHeld != 1);

    /* M down completes the chord and is eaten too. */
    decision = lock_key_on_event(&latch, 1, 0, LOCK_KEY_DOWN, LOCK_VK_M);
    crash_if(!decision.swallow);
    crash_if(!decision.requestExit);
    crash_if(latch.zHeld != 1 || latch.mHeld != 1);
    sawExit = 1;

    /* A different physical key does not drop the chord. */
    decision = lock_key_on_event(&latch, 1, 0, LOCK_KEY_DOWN, 0x41u);
    crash_if(!decision.requestExit);
    crash_if(latch.zHeld != 1 || latch.mHeld != 1);
    sawIgnored = 1;

    /* Releasing Z ends the exit request. M stays down. */
    decision = lock_key_on_event(&latch, 1, 0, LOCK_KEY_UP, LOCK_VK_Z);
    crash_if(decision.requestExit);
    crash_if(!decision.swallow);
    crash_if(latch.zHeld != 0 || latch.mHeld != 1);
    sawRelease = 1;

    /* Releasing M clears the latch. */
    decision = lock_key_on_event(&latch, 1, 0, LOCK_KEY_UP, LOCK_VK_M);
    crash_if(decision.requestExit);
    crash_if(latch.zHeld != 0 || latch.mHeld != 0);

    /* Releasing a key that is already up stays up. */
    decision = lock_key_on_event(&latch, 1, 0, LOCK_KEY_UP, LOCK_VK_Z);
    crash_if(latch.zHeld != 0);

    /* An injected Z must not arm the latch, and it must be passed through. */
    decision = lock_key_on_event(&latch, 1, 1, LOCK_KEY_DOWN, LOCK_VK_Z);
    crash_if(!decision.callNext);
    crash_if(decision.swallow);
    crash_if(decision.requestExit);
    crash_if(latch.zHeld != 0);
    sawInjected = 1;
    sawPass = 1;

    /* A code other than HC_ACTION is passed through and does not change the latch. */
    decision = lock_key_on_event(&latch, 0, 0, LOCK_KEY_DOWN, LOCK_VK_M);
    crash_if(!decision.callNext);
    crash_if(decision.swallow);
    crash_if(latch.mHeld != 0);

    /* No latch: a physical key is still eaten, and exit cannot be requested. */
    decision = lock_key_on_event(NULL, 1, 0, LOCK_KEY_DOWN, LOCK_VK_Z);
    crash_if(!decision.swallow);
    crash_if(decision.requestExit);
    crash_if(decision.callNext);

    keys[0] = LOCK_VK_Z;
    keys[1] = LOCK_VK_M;
    keys[2] = 0x41u;
    keys[3] = 0x0Du;
    keys[4] = 0x20u;
    keys[5] = 0x1Bu;

    lock_key_latch_clear(&latch);

    /* Random physical, injected, and non-action events. Invariants are checked on each one. */
    for (i = 0; i < 2000; i++) {
        int isAction;
        int isInjected;
        int transition;
        unsigned int vk;
        int zBefore;
        int mBefore;

        isAction = coin_flip();
        isInjected = coin_flip();
        transition = rand_range(0, 2);
        vk = keys[rand_range(0, 5)];
        zBefore = latch.zHeld;
        mBefore = latch.mHeld;
        decision = lock_key_on_event(&latch, isAction, isInjected, transition, vk);

        /* Exactly one of pass-through or swallow is set. */
        crash_if(decision.callNext == decision.swallow);

        /* Exit is only requested for a swallowed event while both keys are down. */
        if (decision.requestExit) {
            crash_if(!decision.swallow);
            crash_if(!latch.zHeld || !latch.mHeld);
            sawExit = 1;
        }

        /* Injected events and non-actions do not move the latch. */
        if (!isAction || isInjected) {
            crash_if(latch.zHeld != zBefore || latch.mHeld != mBefore);
            crash_if(!decision.callNext);
            sawPass = 1;
            /* An injected action is the desktop-switch path. */
            if (isInjected && isAction) {
                sawInjected = 1;
            }
        } else {
            /* A physical action is eaten, and exit matches the latch after the event. */
            crash_if(!decision.swallow);
            crash_if(decision.requestExit != (latch.zHeld && latch.mHeld));
            sawSwallow = 1;
            /* Keys other than Z and M must not move the latch. */
            if (vk != LOCK_VK_Z && vk != LOCK_VK_M) {
                crash_if(latch.zHeld != zBefore || latch.mHeld != mBefore);
                sawIgnored = 1;
            }
            /* A release of Z or M is the path that clears a held key. */
            if (transition == LOCK_KEY_UP && (vk == LOCK_VK_Z || vk == LOCK_VK_M)) {
                sawRelease = 1;
            }
        }
    }

    crash_if(!sawExit);
    crash_if(!sawSwallow);
    crash_if(!sawPass);
    crash_if(!sawInjected);
    crash_if(!sawRelease);
    crash_if(!sawIgnored);
    test_log("key chord ................ 2000 cases OK\r\n");
}

/* Mouse hook, touch message, hint rect, reassert plan, and desktop-check pacing. */
static void test_small_decisions(void) {
    LockReassert plan;
    LockHintRect hint;
    LockHintRect hintTall;
    LockKeyStroke strokes[LOCK_STROKE_COUNT];
    unsigned char dirty[sizeof(strokes)];
    int i;

    /* Mouse actions are eaten. Any other hook code is passed on. */
    crash_if(lock_mouse_should_call_next(1) != 0);
    crash_if(lock_mouse_should_call_next(0) != 1);

    /* Only WM_TOUCH is consumed by the pump. */
    crash_if(lock_message_is_touch(LOCK_WM_TOUCH) != 1);
    crash_if(lock_message_is_touch(LOCK_WM_TOUCH + 1u) != 0);
    crash_if(lock_message_is_touch(0u) != 0);

    /* 1920-wide screen: the pill is centered on the top edge. */
    lock_hint_rect(1920, 1080, &hint);
    crash_if(hint.x != (1920 - LOCK_HINT_W) / 2);
    crash_if(hint.y != LOCK_HINT_Y);
    crash_if(hint.w != LOCK_HINT_W || hint.h != LOCK_HINT_H);

    /* Height does not move the pill. A narrow screen may place x below zero. */
    lock_hint_rect(1920, 1, &hintTall);
    crash_if(hintTall.x != hint.x || hintTall.y != hint.y);
    lock_hint_rect(100, 800, &hint);
    crash_if(hint.x != (100 - LOCK_HINT_W) / 2);
    lock_hint_rect(100, 800, NULL);

    /* No lock window: nothing to repair. */
    lock_reassert_actions(0, 1, 1, &plan);
    crash_if(plan.unminimize || plan.reposition || plan.raiseHint);

    /* Iconic lock with a hint: restore, reposition, and raise the hint. */
    lock_reassert_actions(1, 1, 1, &plan);
    crash_if(!plan.unminimize || !plan.reposition || !plan.raiseHint);

    /* Visible lock, no hint: reposition only. */
    lock_reassert_actions(1, 0, 0, &plan);
    crash_if(plan.unminimize || plan.raiseHint);
    crash_if(!plan.reposition);
    lock_reassert_actions(1, 1, 1, NULL);

    /* Even ticks query the desktop. Tick 1 is the first watchdog increment. */
    crash_if(lock_vd_check_this_tick(1) != 0);
    crash_if(lock_vd_check_this_tick(2) != 1);
    crash_if(lock_vd_check_this_tick(3) != 0);
    crash_if(lock_vd_check_this_tick(4) != 1);
    crash_if(lock_vd_check_this_tick(0) != 1);

    /* Left chord: win, control, left, then the three releases in reverse. */
    crash_if(lock_desktop_switch_strokes(0, strokes, LOCK_STROKE_COUNT) != LOCK_STROKE_COUNT);
    crash_if(strokes[0].vk != LOCK_VK_LWIN || strokes[0].keyUp != 0);
    crash_if(strokes[1].vk != LOCK_VK_CONTROL || strokes[1].keyUp != 0);
    crash_if(strokes[2].vk != LOCK_VK_LEFT || strokes[2].keyUp != 0);
    crash_if(strokes[3].vk != LOCK_VK_LEFT || strokes[3].keyUp != 1);
    crash_if(strokes[4].vk != LOCK_VK_CONTROL || strokes[4].keyUp != 1);
    crash_if(strokes[5].vk != LOCK_VK_LWIN || strokes[5].keyUp != 1);

    /* Any non-zero goRight selects the right arrow. The other keys stay put. */
    crash_if(lock_desktop_switch_strokes(2, strokes, LOCK_STROKE_COUNT) != LOCK_STROKE_COUNT);
    crash_if(strokes[2].vk != LOCK_VK_RIGHT || strokes[3].vk != LOCK_VK_RIGHT);
    crash_if(strokes[0].vk != LOCK_VK_LWIN || strokes[5].vk != LOCK_VK_LWIN);

    /* A short buffer is rejected and left untouched. */
    for (i = 0; i < (int)sizeof(dirty); i++) {
        dirty[i] = 0xAB;
    }
    crash_if(lock_desktop_switch_strokes(1, (LockKeyStroke *)dirty, LOCK_STROKE_COUNT - 1) != 0);
    crash_if(lock_desktop_switch_strokes(1, NULL, LOCK_STROKE_COUNT) != 0);
    for (i = 0; i < (int)sizeof(dirty); i++) {
        crash_if(dirty[i] != 0xAB);
    }

    test_log("small decisions ........... OK\r\n");
}

/* Virtual-desktop walk: the scripted left cap, the silent phase change, the right walk, and give-up. */
static void test_vd_sweep(void) {
    LockVdSweep sweep;
    LockVdSweep saved;
    int action;
    int i;
    int sawLeft;
    int sawSilent;
    int sawRight;
    int sawGiveUp;
    int sawReset;
    int sawQuery;

    sawLeft = 0;
    sawSilent = 0;
    sawRight = 0;
    sawGiveUp = 0;
    sawReset = 0;
    sawQuery = 0;

    lock_vd_sweep_clear(NULL);
    lock_vd_sweep_clear(&sweep);
    crash_if(sweep.phase != LOCK_VD_PHASE_HOME);
    crash_if(sweep.leftSteps != 0 || sweep.totalSteps != 0);
    crash_if(lock_vd_on_check(NULL, LOCK_VD_ON_OTHER) != LOCK_VD_ACT_NONE);

    /* Eight left steps, then one silent call that only flips the phase. */
    for (i = 1; i <= LOCK_VD_LEFT_CAP; i++) {
        action = lock_vd_on_check(&sweep, LOCK_VD_ON_OTHER);
        crash_if(action != LOCK_VD_ACT_LEFT);
        crash_if(sweep.phase != LOCK_VD_PHASE_LEFT);
        crash_if(sweep.leftSteps != i);
        crash_if(sweep.totalSteps != i);
        sawLeft = 1;
    }

    action = lock_vd_on_check(&sweep, LOCK_VD_ON_OTHER);
    crash_if(action != LOCK_VD_ACT_NONE);
    crash_if(sweep.phase != LOCK_VD_PHASE_RIGHT);
    crash_if(sweep.leftSteps != LOCK_VD_LEFT_CAP);
    crash_if(sweep.totalSteps != LOCK_VD_LEFT_CAP);
    sawSilent = 1;

    /* Right steps run until the total cap, then further checks stay silent. */
    while (sweep.totalSteps < LOCK_VD_TOTAL_CAP) {
        int before;

        before = sweep.totalSteps;
        action = lock_vd_on_check(&sweep, LOCK_VD_ON_OTHER);
        crash_if(action != LOCK_VD_ACT_RIGHT);
        crash_if(sweep.totalSteps != before + 1);
        crash_if(sweep.leftSteps != LOCK_VD_LEFT_CAP);
        crash_if(sweep.phase != LOCK_VD_PHASE_RIGHT);
        sawRight = 1;
    }

    action = lock_vd_on_check(&sweep, LOCK_VD_ON_OTHER);
    crash_if(action != LOCK_VD_ACT_NONE);
    crash_if(sweep.totalSteps != LOCK_VD_TOTAL_CAP);
    sawGiveUp = 1;

    /* Give-up sticks until the lock is observed on the current desktop. */
    action = lock_vd_on_check(&sweep, LOCK_VD_ON_OTHER);
    crash_if(action != LOCK_VD_ACT_NONE);
    crash_if(sweep.phase != LOCK_VD_PHASE_RIGHT);

    action = lock_vd_on_check(&sweep, LOCK_VD_ON_CURRENT);
    crash_if(action != LOCK_VD_ACT_NONE);
    crash_if(sweep.phase != LOCK_VD_PHASE_HOME);
    crash_if(sweep.leftSteps != 0 || sweep.totalSteps != 0);
    sawReset = 1;

    /* A failed query in the middle of a left walk changes nothing. */
    lock_vd_on_check(&sweep, LOCK_VD_ON_OTHER);
    saved = sweep;
    action = lock_vd_on_check(&sweep, LOCK_VD_QUERY_FAILED);
    crash_if(action != LOCK_VD_ACT_NONE);
    crash_if(sweep.phase != saved.phase);
    crash_if(sweep.leftSteps != saved.leftSteps);
    crash_if(sweep.totalSteps != saved.totalSteps);
    sawQuery = 1;

    /* Returning home mid-walk clears the counters before another departure. */
    lock_vd_on_check(&sweep, LOCK_VD_ON_CURRENT);
    crash_if(sweep.phase != LOCK_VD_PHASE_HOME);
    action = lock_vd_on_check(&sweep, LOCK_VD_ON_OTHER);
    crash_if(action != LOCK_VD_ACT_LEFT);
    crash_if(sweep.leftSteps != 1);

    /* Random observations never push the counters past the caps. */
    lock_vd_sweep_clear(&sweep);
    for (i = 0; i < 500; i++) {
        int observation;

        observation = rand_range(0, 3);
        action = lock_vd_on_check(&sweep, observation);
        crash_if(sweep.phase != LOCK_VD_PHASE_HOME &&
                 sweep.phase != LOCK_VD_PHASE_LEFT &&
                 sweep.phase != LOCK_VD_PHASE_RIGHT);
        crash_if(sweep.leftSteps < 0 || sweep.leftSteps > LOCK_VD_LEFT_CAP);
        crash_if(sweep.totalSteps < 0 || sweep.totalSteps > LOCK_VD_TOTAL_CAP);
        crash_if(sweep.leftSteps > sweep.totalSteps);
        crash_if(action != LOCK_VD_ACT_NONE &&
                 action != LOCK_VD_ACT_LEFT &&
                 action != LOCK_VD_ACT_RIGHT);
        if (observation == LOCK_VD_QUERY_FAILED) {
            sawQuery = 1;
        }
        if (observation == LOCK_VD_ON_CURRENT) {
            crash_if(sweep.phase != LOCK_VD_PHASE_HOME);
            sawReset = 1;
        }
    }

    crash_if(!sawLeft);
    crash_if(!sawSilent);
    crash_if(!sawRight);
    crash_if(!sawGiveUp);
    crash_if(!sawReset);
    crash_if(!sawQuery);
    test_log("virtual desktop ........... scripted + 500 OK\r\n");
}

/* Build a perfect window fact record, then let each test knock out one field. */
static void perfect_facts(LockWindowFacts *facts) {
    facts->isSelf = 0;
    facts->isHint = 0;
    facts->visible = 1;
    facts->hasOwner = 0;
    facts->isToolWindow = 0;
    facts->isAppWindow = 0;
    facts->titleLength = 8;
    facts->placementOk = 1;
}

/* Snapshot classifier: one scripted case per skip reason, then random invariants. */
static void test_snapshot(void) {
    LockWindowFacts facts;
    int sawStop;
    int sawSelf;
    int sawHint;
    int sawHidden;
    int sawOwned;
    int sawTool;
    int sawEmpty;
    int sawPlacement;
    int sawTake;
    int sawToolApp;
    int i;

    sawStop = 0;
    sawSelf = 0;
    sawHint = 0;
    sawHidden = 0;
    sawOwned = 0;
    sawTool = 0;
    sawEmpty = 0;
    sawPlacement = 0;
    sawTake = 0;
    sawToolApp = 0;

    perfect_facts(&facts);
    crash_if(lock_snapshot_classify(&facts, 0, LOCK_MAX_TRACKED) != LOCK_SNAP_TAKE);
    sawTake = 1;

    /* A full table stops even if the window would otherwise be recorded. */
    crash_if(lock_snapshot_classify(&facts, LOCK_MAX_TRACKED, LOCK_MAX_TRACKED) != LOCK_SNAP_STOP);
    crash_if(lock_snapshot_classify(&facts, LOCK_MAX_TRACKED + 1, LOCK_MAX_TRACKED) != LOCK_SNAP_STOP);
    crash_if(lock_snapshot_classify(NULL, 0, LOCK_MAX_TRACKED) != LOCK_SNAP_STOP);
    sawStop = 1;

    /* The last free slot is still taken. */
    crash_if(lock_snapshot_classify(&facts, LOCK_MAX_TRACKED - 1, LOCK_MAX_TRACKED) != LOCK_SNAP_TAKE);

    facts.isSelf = 1;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_SKIP);
    sawSelf = 1;

    perfect_facts(&facts);
    facts.isHint = 1;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_SKIP);
    sawHint = 1;

    perfect_facts(&facts);
    facts.visible = 0;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_SKIP);
    sawHidden = 1;

    perfect_facts(&facts);
    facts.hasOwner = 1;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_SKIP);
    sawOwned = 1;

    perfect_facts(&facts);
    facts.isToolWindow = 1;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_SKIP);
    sawTool = 1;

    /* A tool window that is also an app window is a real Alt+Tab surface. */
    facts.isAppWindow = 1;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_TAKE);
    sawToolApp = 1;

    perfect_facts(&facts);
    facts.titleLength = 0;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_SKIP);
    facts.titleLength = -1;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_SKIP);
    sawEmpty = 1;

    perfect_facts(&facts);
    facts.placementOk = 0;
    crash_if(lock_snapshot_classify(&facts, 0, 4) != LOCK_SNAP_SKIP);
    sawPlacement = 1;

    /* Random facts. TAKE has to satisfy every record condition. A full count always stops. */
    for (i = 0; i < 1000; i++) {
        int count;
        int cap;
        int result;

        perfect_facts(&facts);
        facts.isSelf = coin_flip();
        facts.isHint = coin_flip();
        facts.visible = coin_flip();
        facts.hasOwner = coin_flip();
        facts.isToolWindow = coin_flip();
        facts.isAppWindow = coin_flip();
        facts.titleLength = rand_range(-2, 12);
        facts.placementOk = coin_flip();
        cap = rand_range(1, 8);
        count = rand_range(0, cap);
        result = lock_snapshot_classify(&facts, count, cap);

        crash_if(result != LOCK_SNAP_STOP && result != LOCK_SNAP_SKIP && result != LOCK_SNAP_TAKE);

        /* The table-full check wins over every fact. */
        if (count >= cap) {
            crash_if(result != LOCK_SNAP_STOP);
            sawStop = 1;
        }

        /* A recorded window has to be a visible, unowned, titled window with a placement. */
        if (result == LOCK_SNAP_TAKE) {
            crash_if(facts.isSelf || facts.isHint);
            crash_if(!facts.visible);
            crash_if(facts.hasOwner);
            crash_if(facts.isToolWindow && !facts.isAppWindow);
            crash_if(facts.titleLength <= 0);
            crash_if(!facts.placementOk);
            crash_if(count >= cap);
            sawTake = 1;
        }
    }

    crash_if(!sawStop);
    crash_if(!sawSelf);
    crash_if(!sawHint);
    crash_if(!sawHidden);
    crash_if(!sawOwned);
    crash_if(!sawTool);
    crash_if(!sawEmpty);
    crash_if(!sawPlacement);
    crash_if(!sawTake);
    crash_if(!sawToolApp);
    test_log("snapshot classify ......... 1000 cases OK\r\n");
}

/* Placement compare and the "any alive window drifted" check. */
static void test_restore_decision(void) {
    LockPlacement a;
    LockPlacement b;
    LockTrackedSlot slots[4];
    LockObserved observed[4];
    int i;
    int sawEqual;
    int sawShow;
    int sawRect;
    int sawDead;
    int sawClean;
    int sawNull;

    sawEqual = 0;
    sawShow = 0;
    sawRect = 0;
    sawDead = 0;
    sawClean = 0;
    sawNull = 0;

    lock_zero(&a, sizeof(a));
    a.showCmd = 1;
    a.left = 10;
    a.top = 20;
    a.right = 110;
    a.bottom = 220;
    b = a;
    crash_if(lock_placement_differs(&a, &b) != 0);
    sawEqual = 1;

    b.showCmd = 2;
    crash_if(lock_placement_differs(&a, &b) != 1);
    sawShow = 1;
    b = a;
    b.left = 11;
    crash_if(lock_placement_differs(&a, &b) != 1);
    b = a;
    b.top = 21;
    crash_if(lock_placement_differs(&a, &b) != 1);
    b = a;
    b.right = 111;
    crash_if(lock_placement_differs(&a, &b) != 1);
    b = a;
    b.bottom = 221;
    crash_if(lock_placement_differs(&a, &b) != 1);
    sawRect = 1;

    crash_if(lock_placement_differs(NULL, &a) != 1);
    crash_if(lock_placement_differs(&a, NULL) != 1);
    crash_if(lock_placement_differs(NULL, NULL) != 1);
    sawNull = 1;

    /* Four identical alive windows do not need a restore. */
    for (i = 0; i < 4; i++) {
        slots[i].hwnd = (void *)(long long)(i + 1);
        slots[i].place = a;
        observed[i].alive = 1;
        observed[i].place = a;
    }
    crash_if(lock_windows_need_restore(slots, 4, observed) != 0);
    crash_if(lock_windows_need_restore(slots, 0, observed) != 0);
    crash_if(lock_windows_need_restore(NULL, 4, observed) != 0);
    crash_if(lock_windows_need_restore(slots, 4, NULL) != 0);
    sawClean = 1;

    /* A dead window with a wild rectangle is ignored. */
    observed[1].alive = 0;
    observed[1].place.left = 9999;
    crash_if(lock_windows_need_restore(slots, 4, observed) != 0);
    sawDead = 1;

    /* One live rectangle change is enough to restore the whole snapshot. */
    observed[2].place.bottom = 5;
    crash_if(lock_windows_need_restore(slots, 4, observed) == 0);

    observed[2].place = a;
    observed[3].place.showCmd = 3;
    crash_if(lock_windows_need_restore(slots, 4, observed) == 0);

    /* Random tables. A positive result requires some alive slot to differ. */
    for (i = 0; i < 300; i++) {
        int n;
        int s;
        int expect;
        int got;

        n = rand_range(1, 4);
        expect = 0;
        for (s = 0; s < n; s++) {
            slots[s].hwnd = (void *)(long long)(s + 1);
            slots[s].place.showCmd = rand_range(0, 3);
            slots[s].place.left = rand_range(-20, 40);
            slots[s].place.top = rand_range(-20, 40);
            slots[s].place.right = slots[s].place.left + rand_range(1, 80);
            slots[s].place.bottom = slots[s].place.top + rand_range(1, 80);
            observed[s].alive = coin_flip();
            observed[s].place = slots[s].place;
            /* Sometimes shove the restored left edge so the slot and the observation differ. */
            if (coin_flip()) {
                observed[s].place.left += rand_range(1, 5);
            }
            /* Only a live difference should make the batch report a restore. */
            if (observed[s].alive && lock_placement_differs(&slots[s].place, &observed[s].place)) {
                expect = 1;
            }
        }
        got = lock_windows_need_restore(slots, n, observed);
        crash_if(got != expect);
        /* Remember that both the dirty and the clean outcomes occurred. */
        if (expect) {
            sawRect = 1;
        } else {
            sawClean = 1;
        }
    }

    crash_if(!sawEqual);
    crash_if(!sawShow);
    crash_if(!sawRect);
    crash_if(!sawDead);
    crash_if(!sawClean);
    crash_if(!sawNull);
    test_log("restore decision .......... 300 cases OK\r\n");
}

/* Z-order compare and the WinEvent filter. A program-switch swipe leaves
   rectangles alone, so this is the check that decides to restack. */
static void test_zorder_and_events(void) {
    LockTrackedSlot slots[8];
    void *current[16];
    int i;
    int sawSame;
    int sawSwap;
    int sawMissing;
    int sawForeign;
    int sawReverse;

    sawSame = 0;
    sawSwap = 0;
    sawMissing = 0;
    sawForeign = 0;
    sawReverse = 0;

    /* Three windows, snapshot order, is not a reorder. */
    for (i = 0; i < 3; i++) {
        lock_zero(&slots[i], sizeof(slots[i]));
        slots[i].hwnd = (void *)(long long)(i + 1);
        current[i] = slots[i].hwnd;
    }
    crash_if(lock_zorder_differs(slots, 3, current, 3) != 0);
    sawSame = 1;

    /* Reversed stack. Index 0 is no longer on top. */
    current[0] = slots[2].hwnd;
    current[1] = slots[1].hwnd;
    current[2] = slots[0].hwnd;
    crash_if(lock_zorder_differs(slots, 3, current, 3) != 1);
    sawReverse = 1;

    /* The middle window is gone. The other two are still in snapshot order. */
    current[0] = slots[0].hwnd;
    current[1] = slots[2].hwnd;
    crash_if(lock_zorder_differs(slots, 3, current, 2) != 0);
    sawMissing = 1;

    /* The top of the snapshot is gone and the rest kept their order. */
    current[0] = slots[1].hwnd;
    current[1] = slots[2].hwnd;
    crash_if(lock_zorder_differs(slots, 3, current, 2) != 0);

    /* Slot 2 then slot 0. The lower snapshot index came back to the front. */
    current[0] = slots[2].hwnd;
    current[1] = slots[0].hwnd;
    crash_if(lock_zorder_differs(slots, 3, current, 2) != 1);
    sawSwap = 1;

    /* Untracked windows between an otherwise untouched snapshot order. */
    current[0] = (void *)(long long)100;
    current[1] = slots[0].hwnd;
    current[2] = (void *)(long long)101;
    current[3] = slots[1].hwnd;
    current[4] = slots[2].hwnd;
    crash_if(lock_zorder_differs(slots, 3, current, 5) != 0);
    sawForeign = 1;

    /* A foreign window does not hide a tracked pair that swapped. */
    current[0] = slots[0].hwnd;
    current[1] = (void *)(long long)100;
    current[2] = slots[2].hwnd;
    current[3] = slots[1].hwnd;
    crash_if(lock_zorder_differs(slots, 3, current, 4) != 1);

    /* A null gap in the walk is skipped, same as a window we do not track. */
    current[0] = slots[0].hwnd;
    current[1] = NULL;
    current[2] = slots[1].hwnd;
    current[3] = slots[2].hwnd;
    crash_if(lock_zorder_differs(slots, 3, current, 4) != 0);

    /* The same tracked window twice is not a valid top-to-bottom walk. */
    current[0] = slots[0].hwnd;
    current[1] = slots[1].hwnd;
    current[2] = slots[0].hwnd;
    crash_if(lock_zorder_differs(slots, 3, current, 3) != 1);

    /* A failed walk, an empty snapshot, or a null table must not force a restore. */
    crash_if(lock_zorder_differs(slots, 3, current, 0) != 0);
    crash_if(lock_zorder_differs(slots, 3, current, -1) != 0);
    crash_if(lock_zorder_differs(slots, 0, current, 3) != 0);
    crash_if(lock_zorder_differs(slots, -1, current, 3) != 0);
    crash_if(lock_zorder_differs(NULL, 3, current, 3) != 0);
    crash_if(lock_zorder_differs(slots, 3, NULL, 3) != 0);

    /* Same order, a real swap, a dropped window, a foreign window, and a reverse. */
    for (i = 0; i < 400; i++) {
        int n;
        int c;
        int kind;
        int count;
        void *tmp;

        n = rand_range(2, 8);
        for (c = 0; c < n; c++) {
            lock_zero(&slots[c], sizeof(slots[c]));
            slots[c].hwnd = (void *)(long long)(c + 1);
        }

        kind = i % 5;

        /* The live walk matches the snapshot from top to bottom. */
        if (kind == 0) {
            for (c = 0; c < n; c++) {
                current[c] = slots[c].hwnd;
            }
            crash_if(lock_zorder_differs(slots, n, current, n) != 0);
            sawSame = 1;
        /* The top and bottom tracked windows traded places. */
        } else if (kind == 1) {
            for (c = 0; c < n; c++) {
                current[c] = slots[c].hwnd;
            }
            tmp = current[0];
            current[0] = current[n - 1];
            current[n - 1] = tmp;
            crash_if(lock_zorder_differs(slots, n, current, n) != 1);
            sawSwap = 1;
        /* One snapshot window is absent. The rest stay in order. */
        } else if (kind == 2) {
            count = 0;
            for (c = 0; c < n; c++) {
                if (c == n / 2) {
                    continue;
                }
                current[count] = slots[c].hwnd;
                count += 1;
            }
            crash_if(lock_zorder_differs(slots, n, current, count) != 0);
            sawMissing = 1;
        /* Windows we never snapshotted are interleaved and do not count. */
        } else if (kind == 3) {
            count = 0;
            for (c = 0; c < n; c++) {
                current[count] = (void *)(long long)(1000 + c);
                count += 1;
                current[count] = slots[c].hwnd;
                count += 1;
            }
            crash_if(lock_zorder_differs(slots, n, current, count) != 0);
            sawForeign = 1;
        /* Bottom to top is the app-switch failure the watchdog has to see. */
        } else {
            for (c = 0; c < n; c++) {
                current[c] = slots[n - 1 - c].hwnd;
            }
            crash_if(lock_zorder_differs(slots, n, current, n) != 1);
            sawReverse = 1;
        }
    }

    crash_if(!sawSame);
    crash_if(!sawSwap);
    crash_if(!sawMissing);
    crash_if(!sawForeign);
    crash_if(!sawReverse);

    /* The eight gesture events repair. Neighbors, including scroll, do not. */
    crash_if(lock_event_needs_repair(LOCK_EVENT_FOREGROUND) != 1);
    crash_if(lock_event_needs_repair(LOCK_EVENT_MOVESIZESTART) != 1);
    crash_if(lock_event_needs_repair(LOCK_EVENT_MOVESIZEEND) != 1);
    crash_if(lock_event_needs_repair(LOCK_EVENT_SWITCHSTART) != 1);
    crash_if(lock_event_needs_repair(LOCK_EVENT_SWITCHEND) != 1);
    crash_if(lock_event_needs_repair(LOCK_EVENT_MINIMIZESTART) != 1);
    crash_if(lock_event_needs_repair(LOCK_EVENT_MINIMIZEEND) != 1);
    crash_if(lock_event_needs_repair(LOCK_EVENT_DESKTOPSWITCH) != 1);
    crash_if(lock_event_needs_repair(0u) != 0);
    crash_if(lock_event_needs_repair(1u) != 0);
    crash_if(lock_event_needs_repair(0x0004u) != 0);
    crash_if(lock_event_needs_repair(0x0012u) != 0);
    crash_if(lock_event_needs_repair(0x0018u) != 0);
    crash_if(lock_event_needs_repair(0x0021u) != 0);

    test_log("z-order and events ....... 400 cases OK\r\n");
}

/* Length of a longest increasing subsequence. The pace planner must move
   exactly n minus this many windows, because those are the ones already in order. */
static int lis_length(const int *values, int n) {
    int len[8];
    int i;
    int j;
    int best;

    /* The fuzz stays inside this fixed table. */
    if (n <= 0 || n > 8) {
        return 0;
    }

    best = 1;

    /* Same tie rule as the planner: a longer chain replaces a shorter one. */
    for (i = 0; i < n; i++) {
        len[i] = 1;
        for (j = 0; j < i; j++) {
            if (values[j] < values[i] && len[j] + 1 > len[i]) {
                len[i] = len[j] + 1;
            }
        }
        if (len[i] > best) {
            best = len[i];
        }
    }

    return best;
}

/* Apply one SetWindowPos insert-after to a top-to-bottom list.
   A null `after` inserts at the top. The window is removed first. */
static void sim_z_insert(void **order, int *count, void *hwnd, void *after) {
    int at;
    int i;
    int ins;

    at = -1;

    /* Find the window the move names. A missing window is not inserted. */
    for (i = 0; i < *count; i++) {
        if (order[i] == hwnd) {
            at = i;
        }
    }
    if (at < 0) {
        return;
    }

    /* Pull it out so the insert position is among the windows that stay. */
    for (i = at; i < *count - 1; i++) {
        order[i] = order[i + 1];
    }
    *count -= 1;

    /* Null means the top. Otherwise the slot just below `after`. */
    if (!after) {
        ins = 0;
    } else {
        ins = *count;
        for (i = 0; i < *count; i++) {
            if (order[i] == after) {
                ins = i + 1;
                break;
            }
        }
    }

    for (i = *count; i > ins; i--) {
        order[i] = order[i - 1];
    }
    order[ins] = hwnd;
    *count += 1;
}

/* Delays, the minimum placement list, and the minimum z-order moves.
   Applying the moves to a copy of the walk must restore snapshot order,
   and the move count must be the number of windows outside a longest
   already-correct run. */
static void test_pace_plan(void) {
    unsigned char raw[8192];
    unsigned char tiny[16];
    LockBump bump;
    LockBump small;
    LockTrackedSlot slots[8];
    LockObserved observed[4];
    LockPlacement place;
    LockZMove moves[8];
    void *current[8];
    void *sim[8];
    int perm[8];
    int outSlots[4];
    int i;
    int sawSame;
    int sawOne;
    int sawReverse;
    int sawPartial;

    sawSame = 0;
    sawOne = 0;
    sawReverse = 0;
    sawPartial = 0;

    lock_bump_init(&bump, raw, sizeof(raw));
    lock_bump_init(&small, tiny, sizeof(tiny));

    /* Attempt 0 is the short gap. Each miss doubles it, then it stays capped.
       The limits are copied into locals so the check is not a constant condition. */
    {
        int baseMs;
        int maxMs;

        baseMs = LOCK_Z_DELAY_BASE_MS;
        maxMs = LOCK_Z_DELAY_MAX_MS;
        crash_if(baseMs != 40);
        crash_if(maxMs != 640);
    }
    crash_if(lock_z_attempt_delay_ms(0) != 40);
    crash_if(lock_z_attempt_delay_ms(1) != 80);
    crash_if(lock_z_attempt_delay_ms(2) != 160);
    crash_if(lock_z_attempt_delay_ms(3) != 320);
    crash_if(lock_z_attempt_delay_ms(4) != 640);
    crash_if(lock_z_attempt_delay_ms(5) != 640);
    crash_if(lock_z_attempt_delay_ms(-1) != 40);
    crash_if(lock_z_attempt_delay_ms(LOCK_Z_ATTEMPT_CAP) != LOCK_Z_DELAY_MAX_MS);
    crash_if(lock_z_attempt_delay_ms(LOCK_Z_ATTEMPT_CAP + 8) != LOCK_Z_DELAY_MAX_MS);

    lock_zero(&place, sizeof(place));
    place.showCmd = 1;
    place.left = 10;
    place.top = 20;
    place.right = 110;
    place.bottom = 220;

    /* Four matching windows need no placement write. */
    for (i = 0; i < 4; i++) {
        lock_zero(&slots[i], sizeof(slots[i]));
        slots[i].hwnd = (void *)(long long)(i + 1);
        slots[i].place = place;
        observed[i].alive = 1;
        observed[i].place = place;
    }
    crash_if(lock_placement_move_slots(slots, 4, observed, outSlots, 4, LOCK_PLACE_NORMAL) != 0);
    crash_if(lock_placement_move_slots(slots, 4, observed, outSlots, 4, LOCK_PLACE_MAXIMIZED) != 0);
    sawSame = 1;

    /* One rectangle and one dead window. Only the live change is listed. */
    observed[1].alive = 0;
    observed[1].place.left = 999;
    observed[2].place.right = 50;
    crash_if(lock_placement_move_slots(slots, 4, observed, outSlots, 4, LOCK_PLACE_NORMAL) != 1);
    crash_if(outSlots[0] != 2);
    sawOne = 1;

    /* A second live change is included. Bottom of the snapshot comes first. */
    observed[0].place.showCmd = 3;
    crash_if(lock_placement_move_slots(slots, 4, observed, outSlots, 4, LOCK_PLACE_NORMAL) != 2);
    crash_if(outSlots[0] != 2 || outSlots[1] != 0);
    crash_if(lock_placement_move_slots(slots, 4, observed, outSlots, 4, LOCK_PLACE_MAXIMIZED) != 0);
    sawPartial = 1;

    /* The snapshot says slot 0 is maximized, so it waits for the later phase.
       Slot 3 is maximized too. The later phase shows the lower one first. */
    slots[0].place.showCmd = LOCK_SHOW_MAXIMIZED;
    slots[3].place.showCmd = LOCK_SHOW_MAXIMIZED;
    observed[0].place.showCmd = 1;
    observed[3].place.left = 4;
    crash_if(lock_placement_move_slots(slots, 4, observed, outSlots, 4, LOCK_PLACE_NORMAL) != 1);
    crash_if(outSlots[0] != 2);
    crash_if(lock_placement_move_slots(slots, 4, observed, outSlots, 4, LOCK_PLACE_MAXIMIZED) != 2);
    crash_if(outSlots[0] != 3 || outSlots[1] != 0);
    crash_if(!lock_placement_is_maximized(&slots[0].place));
    crash_if(lock_placement_is_maximized(&slots[2].place));
    crash_if(lock_placement_is_maximized(NULL));

    /* A short buffer is rejected instead of returning a truncated list. */
    crash_if(lock_placement_move_slots(slots, 4, observed, outSlots, 1, LOCK_PLACE_MAXIMIZED) != -1);
    crash_if(lock_placement_move_slots(slots, 4, observed, NULL, 4, LOCK_PLACE_NORMAL) != -1);
    crash_if(lock_placement_move_slots(NULL, 4, observed, outSlots, 4, LOCK_PLACE_NORMAL) != 0);
    crash_if(lock_placement_move_slots(slots, 0, observed, outSlots, 4, LOCK_PLACE_NORMAL) != 0);
    crash_if(lock_placement_move_slots(slots, 4, NULL, outSlots, 4, LOCK_PLACE_NORMAL) != 0);

    /* Snapshot order needs no z-order move. */
    for (i = 0; i < 3; i++) {
        current[i] = slots[i].hwnd;
    }
    lock_bump_reset(&bump);
    crash_if(lock_z_minimum_moves(slots, 3, current, 3, &bump, moves, 8) != 0);

    /* 0,2,1. Window 1 is the only one outside the longest increasing run. */
    current[0] = slots[0].hwnd;
    current[1] = slots[2].hwnd;
    current[2] = slots[1].hwnd;
    lock_bump_reset(&bump);
    crash_if(lock_z_minimum_moves(slots, 3, current, 3, &bump, moves, 8) != 1);
    crash_if(moves[0].hwnd != slots[1].hwnd);
    crash_if(moves[0].insertAfter != slots[0].hwnd);

    /* Reversed. The bottom snapshot window stays. The others move, top first. */
    current[0] = slots[2].hwnd;
    current[1] = slots[1].hwnd;
    current[2] = slots[0].hwnd;
    lock_bump_reset(&bump);
    crash_if(lock_z_minimum_moves(slots, 3, current, 3, &bump, moves, 8) != 2);
    crash_if(moves[0].hwnd != slots[0].hwnd);
    crash_if(moves[0].insertAfter != NULL);
    crash_if(moves[1].hwnd != slots[1].hwnd);
    crash_if(moves[1].insertAfter != slots[0].hwnd);
    sawReverse = 1;

    /* A missing middle window does not count as a reorder. */
    current[0] = slots[0].hwnd;
    current[1] = slots[2].hwnd;
    lock_bump_reset(&bump);
    crash_if(lock_z_minimum_moves(slots, 3, current, 2, &bump, moves, 8) != 0);

    /* Foreign windows and a null gap around an in-order pair. */
    current[0] = (void *)(long long)100;
    current[1] = slots[0].hwnd;
    current[2] = NULL;
    current[3] = slots[1].hwnd;
    lock_bump_reset(&bump);
    crash_if(lock_z_minimum_moves(slots, 2, current, 4, &bump, moves, 8) != 0);

    /* Empty, missing, and too-small outputs do not pretend to have a plan. */
    lock_bump_reset(&bump);
    crash_if(lock_z_minimum_moves(slots, 3, current, 0, &bump, moves, 8) != 0);
    crash_if(lock_z_minimum_moves(NULL, 3, current, 3, &bump, moves, 8) != 0);
    crash_if(lock_z_minimum_moves(slots, 3, NULL, 3, &bump, moves, 8) != 0);
    current[0] = slots[2].hwnd;
    current[1] = slots[1].hwnd;
    current[2] = slots[0].hwnd;
    lock_bump_reset(&bump);
    crash_if(lock_z_minimum_moves(slots, 3, current, 3, &bump, moves, 0) != -1);
    crash_if(lock_z_minimum_moves(slots, 3, current, 3, &bump, NULL, 8) != -1);
    lock_bump_reset(&small);
    crash_if(lock_z_minimum_moves(slots, 3, current, 3, &small, moves, 8) != -1);
    crash_if(lock_z_minimum_moves(slots, 3, current, 3, NULL, moves, 8) != -1);

    /* Permutations. The moves sort the walk and touch only the windows that have to move. */
    for (i = 0; i < 200; i++) {
        int n;
        int c;
        int j;
        int movesN;
        int simN;
        int expect;

        n = rand_range(1, 6);
        for (c = 0; c < n; c++) {
            lock_zero(&slots[c], sizeof(slots[c]));
            slots[c].hwnd = (void *)(long long)(c + 1);
            perm[c] = c;
        }

        /* Shuffle the live order. Identity is one of the outcomes. */
        for (c = n - 1; c > 0; c--) {
            int swap;
            int tmp;

            swap = rand_range(0, c);
            tmp = perm[c];
            perm[c] = perm[swap];
            perm[swap] = tmp;
        }

        for (c = 0; c < n; c++) {
            current[c] = slots[perm[c]].hwnd;
            sim[c] = current[c];
        }

        lock_bump_reset(&bump);
        movesN = lock_z_minimum_moves(slots, n, current, n, &bump, moves, 8);
        expect = n - lis_length(perm, n);
        crash_if(movesN != expect);

        simN = n;
        for (c = 0; c < movesN; c++) {
            sim_z_insert(sim, &simN, moves[c].hwnd, moves[c].insertAfter);
        }
        crash_if(simN != n);
        for (c = 0; c < n; c++) {
            crash_if(sim[c] != slots[c].hwnd);
        }

        /* Remember which shapes the shuffle actually produced. */
        if (movesN == 0) {
            sawSame = 1;
        } else if (movesN == 1) {
            sawOne = 1;
        } else if (movesN == n - 1) {
            sawReverse = 1;
        } else {
            sawPartial = 1;
        }

        /* A scripted partial is checked below. This keeps j used when n is 1. */
        j = 0;
        (void)j;
    }

    /* 1,0,3,2 is neither sorted, nor one swap, nor fully reversed. */
    for (i = 0; i < 4; i++) {
        lock_zero(&slots[i], sizeof(slots[i]));
        slots[i].hwnd = (void *)(long long)(i + 1);
    }
    perm[0] = 1;
    perm[1] = 0;
    perm[2] = 3;
    perm[3] = 2;
    for (i = 0; i < 4; i++) {
        current[i] = slots[perm[i]].hwnd;
        sim[i] = current[i];
    }
    lock_bump_reset(&bump);
    {
        int movesN;
        int simN;

        movesN = lock_z_minimum_moves(slots, 4, current, 4, &bump, moves, 8);
        crash_if(movesN != 4 - lis_length(perm, 4));
        crash_if(movesN <= 1 || movesN >= 3);
        simN = 4;
        for (i = 0; i < movesN; i++) {
            sim_z_insert(sim, &simN, moves[i].hwnd, moves[i].insertAfter);
        }
        for (i = 0; i < 4; i++) {
            crash_if(sim[i] != slots[i].hwnd);
        }
    }
    sawPartial = 1;

    crash_if(!sawSame);
    crash_if(!sawOne);
    crash_if(!sawReverse);
    crash_if(!sawPartial);
    test_log("pace plan ................ 200 cases OK\r\n");
}

/* Permanent layout: failure cases, then a real block whose hint is an owned copy. */
static void test_permanent_bind(void) {
    unsigned char tinyStack[32];
    unsigned short hint[8];
    unsigned short *saved;
    LockPermanent *state;
    void *small;
    void *big;
    unsigned char *block;
    unsigned long long used;
    void *extra;
    int i;

    hint[0] = 'H';
    hint[1] = 'i';
    hint[2] = 0;

    /* Missing output, missing block, empty cap, and a hint length with no text. */
    crash_if(lock_permanent_bind(tinyStack, sizeof(tinyStack), 1, hint, 2, NULL) != 0);
    state = (LockPermanent *)1;
    crash_if(lock_permanent_bind(NULL, 1000ull, 1, hint, 2, &state) != 0);
    crash_if(state != NULL);
    crash_if(lock_permanent_bind(tinyStack, 0ull, 1, hint, 2, &state) != 0);
    crash_if(lock_permanent_bind(tinyStack, sizeof(tinyStack), 0, hint, 2, &state) != 0);
    crash_if(lock_permanent_bind(tinyStack, sizeof(tinyStack), -1, hint, 2, &state) != 0);
    crash_if(lock_permanent_bind(tinyStack, sizeof(tinyStack), 1, NULL, 2, &state) != 0);
    crash_if(lock_permanent_bind(tinyStack, sizeof(tinyStack), 1, hint, -1, &state) != 0);

    /* One page cannot hold 512 tracked slots. The bind fails and clears the output. */
    small = VirtualAlloc(NULL, 4096ull, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    crash_if(!small);
    state = (LockPermanent *)1;
    crash_if(lock_permanent_bind(small, 4096ull, LOCK_MAX_TRACKED, hint, 2, &state) != 0);
    crash_if(state != NULL);

    /* A 1 MiB block holds a small table and a copied hint. */
    big = VirtualAlloc(NULL, 1024ull * 1024ull, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    crash_if(!big);
    crash_if(lock_permanent_bind(big, 1024ull * 1024ull, 4, hint, 2, &state) != 1);
    crash_if(!state);
    crash_if(state->trackedCount != 0);
    crash_if(state->trackedCap != 4);
    crash_if(state->screenW != 0 || state->screenH != 0 || state->vdTick != 0);
    crash_if(state->vd.phase != LOCK_VD_PHASE_HOME);
    crash_if(state->keys.zHeld != 0 || state->keys.mHeld != 0);
    crash_if(state->exitHintChars != 2);
    crash_if(!state->exitHint);
    crash_if(state->exitHint[0] != 'H' || state->exitHint[1] != 'i' || state->exitHint[2] != 0);

    /* Slots are inside the block, 8-aligned, and cleared. */
    block = (unsigned char *)big;
    crash_if((unsigned char *)state->tracked < block + (int)sizeof(LockPermanent));
    crash_if(((unsigned long long)state->tracked & 7ull) != 0ull);
    for (i = 0; i < 4; i++) {
        crash_if(state->tracked[i].hwnd != NULL);
        crash_if(state->tracked[i].place.showCmd != 0);
    }

    /* The hint is a copy. Changing the source must not change the block. */
    saved = state->exitHint;
    hint[0] = 'N';
    crash_if(saved[0] != 'H');
    crash_if((unsigned char *)saved < block || (unsigned char *)saved >= block + (1024ull * 1024ull));

    /* The permanent cursor has moved and is not reset by the bind. */
    used = lock_bump_used(&state->tail);
    crash_if(used == 0ull);
    crash_if(lock_bump_used(&state->tail) != used);

    /* Further permanent allocation appends. This test does not reset that bump. */
    extra = lock_bump_alloc(&state->tail, 32ull, 8ull);
    crash_if(!extra);
    crash_if(lock_bump_used(&state->tail) <= used);
    crash_if((unsigned char *)extra < block || (unsigned char *)extra >= block + (1024ull * 1024ull));

    /* An empty hint is allowed. The table is still allocated and the pointer stays null. */
    crash_if(lock_permanent_bind(big, 1024ull * 1024ull, 2, NULL, 0, &state) != 1);
    crash_if(!state);
    crash_if(state->exitHint != NULL);
    crash_if(state->exitHintChars != 0);
    crash_if(state->trackedCap != 2);
    crash_if(lock_bump_used(&state->tail) == 0ull);

    test_log("permanent bind ........... OK\r\n");
}

/* 1 when the command line contains --self-test. The executable path is
   searched too, which is the same rule the icon generator uses. A hit runs
   the fuzz instead of the lock. */
static int wants_self_test(void) {
    const WCHAR *cmd;
    const WCHAR *needle;
    const WCHAR *p;

    needle = (const WCHAR *)L"--self-test";
    cmd = GetCommandLineW();

    /* No command line means there is no request. */
    if (!cmd) {
        return 0;
    }

    /* Substring match. The needle is not a prefix of another flag this program uses. */
    for (p = cmd; *p != 0; p++) {
        int i;

        i = 0;
        while (needle[i] != 0 && p[i] == needle[i]) {
            i += 1;
        }
        if (needle[i] == 0) {
            return 1;
        }
    }

    return 0;
}

/* Open out\self_test.txt, run every decision test, and exit 0 only if all of them passed.
   WinMainCRTStartup calls this after the stack probe when --self-test is present.
   This function does not return. */
static void run_self_test(void) {
    /* Fixed PCG stream. A failing run repeats the same sequence. */
    g_rngState = 0x853c49e6748fea9bull;
    g_rngInc = 0xda3e39cb94b95bdbull;

    g_stdout = GetStdHandle(STD_OUTPUT_HANDLE);

    /* The log lives with the other build products. CreateDirectoryW is fine if out already exists. */
    CreateDirectoryW((const unsigned short *)L"out", NULL);
    g_log = CreateFileW((const unsigned short *)L"out\\self_test.txt", GENERIC_WRITE, FILE_SHARE_READ,
                        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    /* Without a log, a passing-looking console line would be the only record. Stop instead. */
    if (g_log == INVALID_HANDLE_VALUE) {
        ExitProcess(0xFFFFFFFEu);
    }

    test_log("baby_screen_lock self-test\r\n");
    test_log("==========================\r\n\r\n");

    test_align_up();
    test_memory_bytes();
    test_bump();
    test_keys();
    test_small_decisions();
    test_vd_sweep();
    test_snapshot();
    test_restore_decision();
    test_zorder_and_events();
    test_pace_plan();
    test_permanent_bind();

    test_log("\r\nALL TESTS PASSED\r\n");

    /* Close the log, then end. Returning would fall through into the lock. */
    if (g_log != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log);
    }
    ExitProcess(0);
}

/* Process entry. The linker uses this symbol. There is no CRT startup.
   --self-test runs the fuzz and exits before any window is created. */
void WinMainCRTStartup(void) {
    HINSTANCE instance;
    LockHintRect hint;
    MSG msg;
    BOOL got;

    /* Commit stack pages before any other frame. There is no __chkstk. */
    commit_stack_pages(STACK_PROBE_STEPS);

    /* Fuzz the decisions and leave. The lock, the hooks, and the cursor stay untouched. */
    if (wants_self_test()) {
        run_self_test();
        /* run_self_test exits. This backstop refuses to fall through into the lock. */
        ExitProcess(0);
    }

    /* Permanent table and tick scratch. Failure leaves nothing on screen. */
    if (!create_memory()) {
        ExitProcess(1);
    }

    /* COM is only here for the desktop-manager query. Failure leaves g_vdm null. */
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    CoCreateInstance(&g_clsidVirtualDesktopManager, NULL, CLSCTX_ALL,
                     &g_iidVirtualDesktopManager, (void **)&g_vdm);

    instance = (HINSTANCE)GetModuleHandleW(NULL);

    /* The lock class has no background brush. The layered alpha is the only fill. */
    if (!register_one_class(instance, (LPCWSTR)L"BabyScreenLock", lock_wnd_proc, NULL)) {
        ExitProcess(1);
    }

    /* The hint class keeps its dark brush for the process lifetime. */
    if (!register_one_class(instance, (LPCWSTR)L"BabyScreenLockHint", hint_wnd_proc,
                            CreateSolidBrush(RGB(30, 30, 30)))) {
        ExitProcess(1);
    }

    g_state->screenW = GetSystemMetrics(SM_CXSCREEN);
    g_state->screenH = GetSystemMetrics(SM_CYSCREEN);

    /* Trace first, so the launch snapshot is the first z-order in the file. */
    log_open();

    /* Snapshot before our windows exist, so they are not part of the arrangement. */
    snapshot_windows();

    /* Near-invisible fullscreen shield. Alpha 1 still hits the input path. */
    g_hwnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        (LPCWSTR)L"BabyScreenLock",
        (LPCWSTR)L"Baby Screen Lock",
        WS_POPUP,
        0, 0, g_state->screenW, g_state->screenH,
        NULL, NULL, instance, NULL);

    /* Without the shield there is nothing to show. Hooks are not installed yet. */
    if (!g_hwnd) {
        ExitProcess(1);
    }

    SetLayeredWindowAttributes(g_hwnd, 0, 1, LWA_ALPHA);
    RegisterTouchWindow(g_hwnd, 0);
    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    /* The pill is centered on the top edge. screenH is passed and unused by the helper. */
    lock_hint_rect(g_state->screenW, g_state->screenH, &hint);
    g_hintHwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        (LPCWSTR)L"BabyScreenLockHint",
        (LPCWSTR)L"Hint",
        WS_POPUP,
        hint.x, hint.y, hint.w, hint.h,
        NULL, NULL, instance, NULL);

    /* The hint is a reminder. The lock still works if the pill cannot be created. */
    if (g_hintHwnd) {
        ShowWindow(g_hintHwnd, SW_SHOW);
        UpdateWindow(g_hintHwnd);
    }

    /* Hide the system cursor for the rest of the lock. The show count is
       thread-local, so it disappears with this thread. */
    ShowCursor(FALSE);

    /* 250 ms repair loop. WM_SIZE and the WinEvent hook also repair immediately. */
    SetTimer(g_hwnd, IDT_REASSERT, WATCHDOG_MS, NULL);

    g_keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, low_level_keyboard_proc, instance, 0);
    g_mouseHook = SetWindowsHookExW(WH_MOUSE_LL, low_level_mouse_proc, instance, 0);

    /* Foreground through desktop-switch. The callback posts WM_LOCK_REPAIR.
       Out of context, so the procedure can live in this exe. Skip our own
       process so SetForegroundWindow does not queue another repair.
       The timer still repairs if this hook cannot be installed.
       The returned handle is not kept. Process rundown removes the hook. */
    (void)SetWinEventHook(
        LOCK_EVENT_FOREGROUND,
        LOCK_EVENT_DESKTOPSWITCH,
        NULL,
        win_event_proc,
        0,
        0,
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

    /* Pump until WM_DESTROY posts a quit. A negative GetMessage result is an error and also leaves. */
    for (;;) {
        got = GetMessageW(&msg, NULL, 0, 0);

        /* Quit message, or a pump failure. Either way the lock is coming down. */
        if (got <= 0) {
            break;
        }

        /* Touch input is consumed here so it is not delivered as a mouse click. */
        if (lock_message_is_touch(msg.message)) {
            CloseTouchInputHandle((HTOUCHINPUT)msg.lParam);
            continue;
        }

        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    /* Drop the low-level hooks, then exit. They are called on this thread.
       ExitProcess does not pump, so a key or click that arrives while one
       is still installed stalls the whole desktop until the system times
       the hook out and removes it. These two calls return input at once.
       The OS teardown is faster for everything else, and walking it here
       only delays ExitProcess. The window-event hook, both timers, the
       thread-local cursor show count, the trace handle, the windows, the
       COM object, the class brush, and both arenas are left in place.
       Process rundown reclaims them in one kernel pass. */
    if (g_keyboardHook) {
        UnhookWindowsHookEx(g_keyboardHook);
    }
    if (g_mouseHook) {
        UnhookWindowsHookEx(g_mouseHook);
    }
    ExitProcess(0);
}
