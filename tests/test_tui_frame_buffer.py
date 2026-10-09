"""Regression tests for the buffered TUI frame writer."""
import io
import sys

from visold.cli.interactive import CLI


class CountingStream(io.StringIO):
    def __init__(self):
        super().__init__()
        self.write_count = 0

    def write(self, text):
        self.write_count += 1
        return super().write(text)


def test_menu_can_render_into_a_frame_buffer(monkeypatch):
    cli = CLI()
    cli._layout = {"W": 80, "menu_cols": 2}
    cli._term_width = lambda: 80
    lines = []

    count = cli._print_menu(emit=lines.append)

    assert count == len(lines)
    assert any("MAIN MENU" in line for line in lines)
    assert any("Start Auto Mining" in line for line in lines)
    assert any("Help & Keyboard Tips" in line for line in lines)
    assert any("Detach UI (keep node running)" in line for line in lines)
    # Supplying an emitter must not write directly to process stdout.
    assert lines


def test_full_tty_render_uses_one_stdout_write(monkeypatch):
    cli = CLI()
    cli._ansi_ok = lambda: True
    cli._compute_layout = lambda: {"W": 80, "menu_cols": 2, "pa_n": 8, "notif_n": 5}
    cli._term_width = lambda: 80
    cli._render_header = lambda emit: emit("VISOLD HEADER")
    cli._render_tab_bar = lambda emit: emit("TAB BAR")
    cli._render_tab_dashboard = lambda emit, get_row: emit("DASHBOARD")

    stream = CountingStream()
    monkeypatch.setattr(sys, "stdout", stream)

    cli._full_render()

    rendered = stream.getvalue()
    assert stream.write_count == 1
    assert rendered.startswith("\033[?25h\033[0m\033[H\033[2J")
    assert "VISOLD HEADER" in rendered
    assert "TAB BAR" in rendered
    assert "DASHBOARD" in rendered
    assert "Start Auto Mining" in rendered
    assert rendered.endswith("\n")


def test_top_level_help_is_clean_and_does_not_dump_architecture():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, str(root / "visold_vsd_.py"), "--help"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0
    assert "Usage:" in proc.stdout
    assert "VISOLD SELF-HEALING BLOCKCHAIN SYSTEM — DATA FLOW" not in proc.stdout
    assert proc.stderr == ""


def test_version_is_one_clean_line():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, str(root / "visold_vsd_.py"), "--version"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0].startswith("Visold (VSD) v")
    assert "VISOLD SELF-HEALING BLOCKCHAIN SYSTEM — DATA FLOW" not in proc.stdout


def test_background_detach_explains_requirement_outside_tmux(monkeypatch, capsys):
    cli = CLI()
    monkeypatch.delenv("TMUX", raising=False)

    cli._detach_tui()

    output = capsys.readouterr().out
    assert "requires a tmux session" in output
    assert "visold-termux.sh start" in output
