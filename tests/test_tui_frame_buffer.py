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
    assert any("Network & Ports" in line for line in lines)
    assert any("[28]" in line for line in lines)
    assert any("NETWORK-WIDE NODE DIRECTORY" in line for line in lines)
    assert any("Network-wide Node Directory" in line for line in lines)
    assert any("29" in line and "Network-wide Node Directory" in line for line in lines)
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


def test_option_29_dispatches_to_network_directory(monkeypatch):
    cli = CLI()
    cli._running = False  # Prevent the normal post-action Enter pause in a unit test.
    called = []
    monkeypatch.setattr(cli, "_network_directory", lambda: called.append(True))

    cli._dispatch("29")

    assert called == [True]


def test_option_29_remains_visible_in_narrow_mobile_layout():
    cli = CLI()
    cli._layout = {"W": 40, "menu_cols": 1}
    cli._term_width = lambda: 40
    lines = []

    cli._print_menu(emit=lines.append)

    joined = "\n".join(lines)
    assert "NETWORK-WIDE NODE DIRECTORY" in joined
    assert "Network-wide Node Directory" in joined
    assert any("Network-wide Node Directory" in line for line in lines)


def test_mining_tab_reuses_chain_snapshot_from_mining_status():
    """The foreground mining page must not repeat difficulty/height reads."""
    cli = CLI()
    cli._layout = {"W": 80}
    rendered = []
    row = [0]

    def emit(line=""):
        rendered.append(line)

    def get_row():
        value = row[0]
        row[0] += 1
        return value

    class Mining:
        @staticmethod
        def status():
            return {
                "running": True,
                "paused": False,
                "hashrate": "123 H/s",
                "blocks_found": 2,
                "backend": "CPU",
                "difficulty": 3.25,
                "chain_height": 42,
            }

    class Mempool:
        @staticmethod
        def size():
            return 7

    class Blockchain:
        mempool = Mempool()

        @staticmethod
        def get_difficulty():
            raise AssertionError("difficulty was redundantly queried")

        @staticmethod
        def height():
            raise AssertionError("height was redundantly queried")

    class Node:
        mining = Mining()
        blockchain = Blockchain()

    cli.node = Node()
    cli._render_tab_mining(emit, get_row)

    joined = "\n".join(rendered)
    assert "3.250000" in joined
    assert "42" in joined
    assert "7 TXs" in joined
