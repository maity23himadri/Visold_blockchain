#!/data/data/com.termux/files/usr/bin/bash
# Convenience manager for Visold's existing interactive TUI in a tmux session.
# This is a session manager, not a separate blockchain daemon.
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="${VISOLD_TMUX_SESSION:-visold}"
PYTHON_BIN="${VISOLD_PYTHON:-python}"

usage() {
  cat <<'USAGE'
Visold Termux session helper

Usage: scripts/visold-termux.sh {start|attach|status|stop|help}

  start   Start the Visold TUI in a detached tmux session
  attach  Reopen that terminal session (detach with Ctrl+B, then D)
  status  Show whether the tmux session exists
  stop    Send Ctrl+C to Visold for a graceful interactive shutdown

Requires: Termux, Python/dependencies, and tmux.
Optional: termux-wake-lock / termux-wake-unlock for screen-off operation.
USAGE
}

need_tmux() {
  if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux is missing. In Termux, run: pkg install tmux" >&2
    exit 127
  fi
}

has_session() {
  tmux has-session -t "$SESSION" 2>/dev/null
}

case "${1:-help}" in
  start)
    need_tmux
    if has_session; then
      echo "Visold session '$SESSION' is already running. Use: $0 attach"
      exit 0
    fi
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
      echo "Python command '$PYTHON_BIN' was not found." >&2
      exit 127
    fi
    # %q safely quotes paths containing spaces for the command executed by tmux.
    printf -v ROOT_Q '%q' "$ROOT"
    printf -v PYTHON_Q '%q' "$PYTHON_BIN"
    tmux new-session -d -s "$SESSION" "cd $ROOT_Q && exec $PYTHON_Q $ROOT_Q/visold_vsd_.py"
    if command -v termux-wake-lock >/dev/null 2>&1; then
      termux-wake-lock || echo "Warning: could not acquire Android wake lock." >&2
    else
      echo "Note: termux-wake-lock unavailable; Android may suspend the node in the background."
    fi
    echo "Started Visold in tmux session '$SESSION'."
    echo "View it with: $0 attach"
    ;;
  attach)
    need_tmux
    if ! has_session; then
      echo "No Visold session '$SESSION'. Start it with: $0 start" >&2
      exit 1
    fi
    exec tmux attach-session -t "$SESSION"
    ;;
  status)
    need_tmux
    if has_session; then
      echo "Visold tmux session '$SESSION' exists."
      tmux display-message -p -t "$SESSION" 'window=#{window_name} pane=#{pane_current_command}' 2>/dev/null || true
    else
      echo "Visold tmux session '$SESSION' is not running."
      exit 1
    fi
    ;;
  stop)
    need_tmux
    if ! has_session; then
      echo "Visold session '$SESSION' is not running."
      command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock || true
      exit 0
    fi
    # Let the TUI receive Ctrl+C and run its normal shutdown path. Do not force-kill
    # the pane if it does not exit; that could bypass node/storage cleanup.
    tmux send-keys -t "$SESSION" C-c
    echo "Sent Ctrl+C to Visold. Check status/logs before closing Termux."
    sleep 2
    if ! has_session; then
      command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock || true
      echo "Visold session stopped."
    else
      echo "Session is still present. Attach and inspect it; it was not force-killed."
      echo "When fully stopped, release the wake lock with: termux-wake-unlock"
    fi
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
