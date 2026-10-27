# Baby Screen Lock

A transparent fullscreen overlay that blocks all keyboard, mouse, and touch
input. Designed so a toddler can mash keys and tap the screen during video
calls without interfering.

## How it works

When launched, the app creates an invisible fullscreen window on top of
everything and installs system-wide input hooks that swallow all keyboard
and mouse events. Touch input is also consumed. The system cursor is hidden.

Your video call (or whatever else) continues running underneath unaffected.

A small hint along the top edge of the screen shows the exit chord while the
lock is active.

## Touchpad gestures

Precision Touchpad gestures (three/four-finger swipe to minimize, Task View,
or show desktop) are processed by the touchpad driver above the level of the
low-level input hooks, so they cannot be swallowed directly. Instead, the app
runs a watchdog (every 250 ms, and immediately on any minimize) that undoes
their effects:

- Own window: if minimized or pushed down, it is restored to fullscreen,
  forced topmost, and brought back to the foreground.
- Other windows: at launch the app snapshots every user top-level window
  (position, minimized/maximized/normal state, and Z-order). If a gesture
  such as show-desktop (minimize all) or Task View moves, minimizes, or
  reorders them, the app restores them to their launch arrangement. It
  messages only the windows that are still wrong, one at a time. Normal
  placements are restored first, then maximized ones. Z-order is restored
  after those shows: the top window is placed directly under the lock, and
  every other moved window is placed under the snapshot window that belongs
  above it. Each run writes
  baby_screen_lock_log.txt next to the program: the launch z-order, and
  the z-order and show state after every restore step. When an attempt
  does not stick, the
  next attempt waits longer between windows and skips any window that has
  already caught up.
- Virtual desktop: a four-finger swipe can switch the active virtual
  desktop. Windows exposes no public API to activate a desktop, so the app
  uses the documented IVirtualDesktopManager only to detect that its window
  is no longer on the current desktop, then injects the standard
  Ctrl+Win+Left / Ctrl+Win+Right shortcut one step at a time, re-checking
  after each step, until the original desktop is active again.

  This virtual-desktop switch-back is best-effort. It depends on the
  desktop manager recognizing the lock window. If it does not behave on a
  given Windows build, the other protections still apply.

## Keyboard shortcuts

| Keys | Action |
| --- | --- |
| Z+M (hold both) | Exit the screen lock and restore normal input |

The app also injects Ctrl+Win+Left / Ctrl+Win+Right internally to switch
virtual desktops back. Those injected keystrokes are allowed through the
input block. Physical key and mouse input stays blocked.

## Building

`config.bat` holds the path to the Visual Studio x64 tools. Set `VCVARS64`
in the environment to override it for one run. `build.bat` calls that
script, then compiles the programs with no C runtime and writes every
output into `out\`. It also builds `out\create_icon.exe`, which draws a
monitor with a padlock and writes `out\app_icon.ico`. That icon is linked
into the lock executable, so a shortcut to the app shows it.

```
build.bat
build.bat test
```

`build.bat test` runs the fuzzing self-test
(`out\baby_screen_lock.exe --self-test`) and writes `out\self_test.txt`.
The test process exits with the source line of the first failed check.
`build.bat run` builds and starts the lock.

The GUI executable is `out\baby_screen_lock.exe`. Pass `--self-test` to
run the fuzz instead of locking the screen. The programs are each a
single C file. They do not include system headers and do not link the C
runtime. `baby_screen_lock.c` holds the decisions, the bump allocator,
the lock, and the self-test. `create_icon.c` is the icon generator.
`out\create_icon.exe --self-test` checks its pixels and writes
`out\create_icon_self_test.txt`.

## Usage

1. Start your video call (Zoom, Teams, etc.)
2. Run `out\baby_screen_lock.exe`
3. Hand the laptop or keyboard to your toddler
4. Press and hold Z+M together when you want control back

## License

The code is covered by [LICENSE](LICENSE) (BSD Zero Clause License, 0BSD).
Use is unrestricted. There is no warranty, no guarantee, and no liability.
