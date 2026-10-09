"""Background networking paths must not write directly to an interactive TTY."""
import ast
from pathlib import Path


def _function_print_calls(path: Path, function_name: str):
    tree = ast.parse(path.read_text())
    target = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
            target = node
            break
    assert target is not None, f"function {function_name} not found in {path}"
    return [
        node for node in ast.walk(target)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "print"
    ]


def test_background_network_paths_do_not_print_over_tui():
    root = Path(__file__).resolve().parents[1]
    assert _function_print_calls(root / "visold/network/dns_seeder.py", "_query_one") == []
    assert _function_print_calls(root / "visold/network/p2p.py", "_on_chain_sync_result") == []
    assert _function_print_calls(root / "visold/network/message_logger.py", "_emit") == []
