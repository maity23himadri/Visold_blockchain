#!/usr/bin/env python3
"""Run an isolated local Visold TCP mesh: seven stable nodes, then an eighth.

This harness keeps the source configuration defaults for peer limits, subnet
admission, PEX cadence, reconnect cadence, and per-IP behavior. It disables
external DNS seeds only to isolate the experiment to localhost and injects the
local endpoints through the supported VISOLD_PEERS variable.

Example:
  python3 tools/run_tcp_eof_7to8_repro.py --output /tmp/visold-eof-run
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


NODE_RUNNER = r'''import json, logging, os, signal, threading, time
from visold.node.visold_node import VisoldNode
from visold.kernel.config import Config

class SelectedEventFilter(logging.Filter):
    needles = (
        "[PeerLoopExit]", "[PeerSocketClose]", "[PeerSendFailure]",
        "[PeerRawSocketAction]", "[PeerSession]", "[ChainSync] Watchdog", "Peer connected:",
        "Peer disconnected:", "[PeerAdmission]",
    )
    def filter(self, record):
        try:
            text = record.getMessage()
        except Exception:
            return False
        return record.levelno >= logging.WARNING or any(
            needle in text for needle in self.needles)

root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.FileHandler(os.environ["VISOLD_TRACE_FILE"], encoding="utf-8")
handler.setLevel(logging.DEBUG)
handler.addFilter(SelectedEventFilter())
handler.setFormatter(logging.Formatter(
    "%(asctime)s.%(msecs)03d %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"))
root.addHandler(handler)

port = int(os.environ["VISOLD_PORT"])
state_path = os.environ["VISOLD_STATE_FILE"]
node = VisoldNode(port=port)
node.start()
stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_args: stop.set())
signal.signal(signal.SIGINT, lambda *_args: stop.set())
print(json.dumps({"event":"READY", "port":port,
                  "node_id":node.node_id, "ts_ns":time.time_ns(),
                  "policy_values":{
                      "min_peers":Config.MIN_PEERS,
                      "max_peers":Config.MAX_PEERS,
                      "reconnect_interval":Config.RECONNECT_INTERVAL,
                      "pex_interval":Config.PEX_INTERVAL,
                      "peer_decay_secs":Config.PEER_DECAY_SECS,
                      "per_ip_conn_rate_limit":node.network._CONN_RATE_LIMIT,
                      "per_ip_conn_rate_window":node.network._CONN_RATE_WINDOW,
                  }}, sort_keys=True), flush=True)

def snapshot():
    with node.network._lock:
        peers = list(node.network.peers.values())
        rows = []
        for peer in peers:
            if not getattr(peer, "connected", False):
                continue
            rows.append({
                "peer_id": str(getattr(peer, "peer_id", "")),
                "ip": str(getattr(peer, "ip", "")),
                "port": int(getattr(peer, "port", 0) or 0),
                "session_id": str(getattr(peer, "session_id", "")),
                "direction": ("outbound" if getattr(peer, "local_outbound", None)
                              else "inbound" if getattr(peer, "local_outbound", None) is not None
                              else "unknown"),
                "last_seen": float(getattr(peer, "last_seen", 0.0) or 0.0),
                "last_rx_type": getattr(peer, "_last_rx_message_type", None),
                "last_rx_ts_ns": getattr(peer, "_last_rx_message_ts_ns", None),
            })
    return {"ts_ns":time.time_ns(), "node_id":node.node_id,
            "port":port, "active_peer_count":len(rows), "peers":rows,
            "policy_values":{
                "min_peers":Config.MIN_PEERS,
                "max_peers":Config.MAX_PEERS,
                "reconnect_interval":Config.RECONNECT_INTERVAL,
                "pex_interval":Config.PEX_INTERVAL,
                "peer_decay_secs":Config.PEER_DECAY_SECS,
                "per_ip_conn_rate_limit":node.network._CONN_RATE_LIMIT,
                "per_ip_conn_rate_window":node.network._CONN_RATE_WINDOW,
            }}

try:
    while not stop.wait(1.0):
        state = snapshot()
        tmp = state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, sort_keys=True)
        os.replace(tmp, state_path)
        print(json.dumps({"event":"STATE", **state}, sort_keys=True), flush=True)
finally:
    print(json.dumps({"event":"ORDERLY_SHUTDOWN_BEGIN", "port":port,
                      "ts_ns":time.time_ns()}), flush=True)
    try:
        node.stop()
    finally:
        handler.flush()
        handler.close()
        root.removeHandler(handler)
    print(json.dumps({"event":"ORDERLY_SHUTDOWN_END", "port":port,
                      "ts_ns":time.time_ns()}), flush=True)
'''


def _read_state(path: Path):
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _stable(states, expected, previous):
    if len(states) != expected:
        return False, None
    signature = []
    for state in states:
        if not state or state.get("active_peer_count") != expected - 1:
            return False, None
        links = sorted((int(p["port"]), str(p.get("session_id", "")))
                       for p in state.get("peers", []))
        if len(links) != expected - 1 or any(not sid for _, sid in links):
            return False, None
        signature.append((int(state["port"]), tuple(links)))
    signature = tuple(sorted(signature))
    return signature == previous, signature


def _log_event_counts(path: Path):
    counts = {name: 0 for name in (
        "PeerLoopExit", "PeerSocketClose", "PeerRawSocketAction",
        "PeerSendFailure", "PeerSession",
        "ChainSyncWatchdog", "Peer connected", "Peer disconnected")}
    if not path.exists():
        return counts
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for needle, key in (
                ("[PeerLoopExit]", "PeerLoopExit"),
                ("[PeerSocketClose]", "PeerSocketClose"),
                ("[PeerRawSocketAction]", "PeerRawSocketAction"),
                ("[PeerSendFailure]", "PeerSendFailure"),
                ("[PeerSession]", "PeerSession"),
                ("[ChainSync] Watchdog", "ChainSyncWatchdog"),
                ("Peer connected:", "Peer connected"),
                ("Peer disconnected:", "Peer disconnected"),
            ):
                if needle in line:
                    counts[key] += 1
    return counts


def _topology_snapshot(states):
    links = {}
    for state in states:
        if not state:
            continue
        local_port = int(state["port"])
        for peer in state.get("peers", []):
            remote_port = int(peer["port"])
            key = f"{min(local_port, remote_port)}-{max(local_port, remote_port)}"
            links.setdefault(key, []).append({
                "node_port":local_port,
                "peer_id":str(peer.get("peer_id", "")),
                "session_id":str(peer.get("session_id", "")),
            })
    return {key:sorted(rows, key=lambda row:row["node_port"])
            for key, rows in sorted(links.items())}


def _topology_is_symmetric(topology, expected_links=28):
    if len(topology) != expected_links:
        return False
    for rows in topology.values():
        if len(rows) != 2 or len({row["node_port"] for row in rows}) != 2:
            return False
        if not rows[0]["session_id"] or rows[0]["session_id"] != rows[1]["session_id"]:
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=18338)
    parser.add_argument("--duration", type=int, default=300,
                        help="seconds to observe after full eight-node mesh stabilizes")
    parser.add_argument("--seven-stable-seconds", type=int, default=10)
    parser.add_argument("--eight-stable-seconds", type=int, default=10)
    parser.add_argument("--join-timeout", type=int, default=180)
    parser.add_argument("--strace", action="store_true",
                        help="trace per-node close/shutdown syscalls with socket endpoint annotations")
    parser.add_argument("--capture-fin-rst", action="store_true",
                        help="capture only FIN/RST packets on the local P2P ports using tcpdump")
    parser.add_argument("--capture-full-p2p", action="store_true",
                        help="capture all TCP packets on the local P2P ports")
    parser.add_argument("--tls-keylog", action="store_true",
                        help="write per-node TLS traffic secrets (sensitive; for local forensic decryption only)")
    parser.add_argument("--strict-tls-eof", action="store_true",
                        help="report abrupt TLS/TCP EOF as SSLEOFError instead of silently suppressing it (diagnostic only)")
    args = parser.parse_args()

    if args.duration <= 0 or args.base_port < 1024:
        parser.error("duration must be positive and base-port must be >=1024")
    ports = [args.base_port + 10 * i for i in range(8)]
    if max(ports) + 2 > 65535:
        parser.error("base-port range exceeds 65535")
    for port in ports:
        for candidate in (port, port + 1, port + 2):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                try:
                    probe.bind(("127.0.0.1", candidate))
                except OSError as exc:
                    parser.error(f"port {candidate} is already in use: {exc}")

    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    strace_exe = shutil.which("strace") if args.strace else None
    if args.strace and not strace_exe:
        parser.error("--strace requested but strace is not installed")
    tcpdump_proc = None
    tcpdump_handle = None
    if args.capture_fin_rst and args.capture_full_p2p:
        parser.error("choose only one of --capture-fin-rst or --capture-full-p2p")
    if args.capture_fin_rst or args.capture_full_p2p:
        tcpdump_exe = shutil.which("tcpdump")
        sudo_exe = shutil.which("sudo")
        if not tcpdump_exe or not sudo_exe:
            parser.error("packet capture requires tcpdump and sudo")
        port_filter = " or ".join(f"port {p}" for p in ports)
        bpf_filter = f"tcp and ({port_filter})"
        pcap_name = "p2p_full.pcap"
        if args.capture_fin_rst:
            bpf_filter += " and (tcp[13] & 5 != 0)"
            pcap_name = "fin_rst.pcap"
        tcpdump_handle = (out / "tcpdump.stderr.log").open("w", encoding="utf-8")
        tcpdump_proc = subprocess.Popen(
            [sudo_exe, "-n", tcpdump_exe, "-i", "lo", "-s", "0", "-U",
             "-nn", "-w", str(out / pcap_name), bpf_filter],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=tcpdump_handle, text=True)
        time.sleep(0.5)
        if tcpdump_proc.poll() is not None:
            tcpdump_handle.close()
            parser.error("tcpdump exited before node startup; inspect tcpdump.stderr.log")
    processes = {}
    handles = {}
    nodes = []
    for index, port in enumerate(ports):
        data_dir = out / f"node{index + 1}"
        home = out / f"home{index + 1}"
        data_dir.mkdir(parents=True, exist_ok=True)
        home.mkdir(parents=True, exist_ok=True)
        (data_dir / "config.json").write_text(
            json.dumps({"log_format":"json"}), encoding="utf-8")
        nodes.append({"index":index + 1, "port":port, "data_dir":data_dir,
                      "home":home, "state":out / f"node{index + 1}.state.json",
                      "trace":out / f"node{index + 1}.events.log",
                      "stdout":out / f"node{index + 1}.stdout.log",
                      "syscalls":out / f"node{index + 1}.syscalls.log",
                      "tlskeys":out / f"node{index + 1}.tlskeys.log"})

    project_root = Path(__file__).resolve().parents[1]

    def launch(node):
        other_endpoints = [f"127.0.0.1:{p['port']}" for p in nodes
                           if p["index"] != node["index"] and p["index"] <= node["index"]]
        # For nodes 1–7, start with their already-running/soon-to-run six
        # endpoints. Node 8 explicitly tries all seven existing endpoints.
        if node["index"] <= 7:
            other_endpoints = [f"127.0.0.1:{p['port']}" for p in nodes
                               if p["index"] <= 7 and p["index"] != node["index"]]
        else:
            other_endpoints = [f"127.0.0.1:{p['port']}" for p in nodes[:7]]
        env = dict(os.environ)
        env.update({
            "HOME":str(node["home"]),
            "VISOLD_DATA_DIR":str(node["data_dir"]),
            "VISOLD_PORT":str(node["port"]),
            "VISOLD_PORT_MODE":"manual",
            "VISOLD_LOG_FORMAT":"json",
            "VISOLD_PEERS":",".join(other_endpoints),
            "VISOLD_TRACE_FILE":str(node["trace"]),
            "VISOLD_STATE_FILE":str(node["state"]),
            # Keep the test inside its own localhost topology; external DNS
            # bootstrap would violate the exact six-/seven-peer experiment.
            "VISOLD_DNS_SEEDS":"",
            "PYTHONPATH":str(project_root),
            "PYTHONUNBUFFERED":"1",
        })
        if args.tls_keylog:
            env["VISOLD_TLS_KEYLOG_FILE"] = str(node["tlskeys"])
        if args.strict_tls_eof:
            env["VISOLD_TLS_STRICT_EOF_DIAGNOSTIC"] = "1"
        handle = node["stdout"].open("w", encoding="utf-8")
        child_cmd = [sys.executable, "-u", "-c", NODE_RUNNER]
        if args.strace:
            child_cmd = [strace_exe, "-f", "-ttt", "-T", "-yy",
                         "-e", "trace=close,shutdown",
                         "-o", str(node["syscalls"]), *child_cmd]
        proc = subprocess.Popen(child_cmd,
                                cwd=project_root, env=env, stdin=subprocess.DEVNULL,
                                stdout=handle, stderr=subprocess.STDOUT, text=True)
        processes[node["index"]] = proc
        handles[node["index"]] = handle
        return proc

    def wait_for_mesh(count, stable_seconds, timeout):
        deadline = time.monotonic() + timeout
        last_signature = None
        stable_since = None
        while time.monotonic() < deadline:
            if any(processes.get(i) is not None and processes[i].poll() is not None
                   for i in processes):
                raise RuntimeError("A node exited before mesh stabilization; inspect stdout logs")
            states = [_read_state(nodes[i - 1]["state"]) for i in range(1, count + 1)]
            all_full = len(states) == count and all(
                state and state.get("active_peer_count") == count - 1 for state in states)
            stable, signature = _stable(states, count, last_signature) if all_full else (False, None)
            now = time.monotonic()
            if all_full and stable:
                if stable_since is None:
                    stable_since = now
                if now - stable_since >= stable_seconds:
                    return states
            else:
                last_signature = signature
                stable_since = now if all_full else None
            time.sleep(1)
        raise TimeoutError(f"{count}-node mesh did not remain full for {stable_seconds}s")

    result = {
        "test":"7 stable TCP nodes (6 peers each), then node 8 joins",
        "started_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "base_port":args.base_port,
        "duration_seconds":args.duration,
        "policy_values":{},
        "diagnostics":{"strace":args.strace,
                        "fin_rst_capture":args.capture_fin_rst,
                        "full_p2p_capture":args.capture_full_p2p,
                        "tls_keylog":args.tls_keylog,
                        "strict_tls_eof":args.strict_tls_eof},
        "phases":[],
        "node_states":[],
        "event_counts":{},
        "peer_count_changes":[],
        "session_churn":[],
        "completed":False,
    }
    try:
        # Start seven ordinary nodes together; all P2P policy defaults remain
        # untouched. Each only has the other six localhost endpoints available.
        for node in nodes[:7]:
            launch(node)
        print("Waiting for seven nodes to maintain six peers each...", flush=True)
        phase7 = wait_for_mesh(7, args.seven_stable_seconds, args.join_timeout)
        result["phases"].append({"name":"seven-node-full-mesh-stable",
                                 "stable_seconds":args.seven_stable_seconds,
                                 "states":phase7})
        print("Seven-node six-peer mesh stable; launching node 8.", flush=True)

        launch(nodes[7])
        print("Waiting for all eight nodes to maintain seven peers each...", flush=True)
        phase8 = wait_for_mesh(8, args.eight_stable_seconds, args.join_timeout)
        result["phases"].append({"name":"eight-node-full-mesh-stable",
                                 "stable_seconds":args.eight_stable_seconds,
                                 "states":phase8})
        policy_values = [state.get("policy_values", {}) for state in phase8]
        result["policy_values"] = policy_values[0] if policy_values else {}
        result["policy_values_consistent"] = all(
            value == result["policy_values"] for value in policy_values)

        run_start_ns = time.time_ns()
        print(f"Eight-node mesh stable; beginning {args.duration}s observation.", flush=True)
        deadline = time.monotonic() + args.duration
        last_report = time.monotonic()
        peer_count_changes = []
        last_counts = None
        previous_topology = None
        session_churn = []
        samples_path = out / "topology_samples.jsonl"
        counts_stayed_full = True
        topology_stayed_symmetric = True
        with samples_path.open("w", encoding="utf-8") as samples_file:
            while time.monotonic() < deadline:
                current = [_read_state(node["state"]) for node in nodes]
                counts = [state.get("active_peer_count") if state else None
                          for state in current]
                if counts != last_counts:
                    peer_count_changes.append({"ts_ns":time.time_ns(), "counts":counts})
                    last_counts = counts
                if counts != [7] * 8:
                    counts_stayed_full = False
                topology = _topology_snapshot(current)
                topology_stayed_symmetric = (
                    topology_stayed_symmetric and _topology_is_symmetric(topology))
                sample_ts_ns = time.time_ns()
                if previous_topology is not None:
                    for link in sorted(set(previous_topology) | set(topology)):
                        before = previous_topology.get(link)
                        after = topology.get(link)
                        if before != after:
                            session_churn.append({"ts_ns":sample_ts_ns,
                                                  "link":link,
                                                  "before":before,
                                                  "after":after})
                previous_topology = topology
                samples_file.write(json.dumps({
                    "ts_ns":sample_ts_ns,
                    "counts":counts,
                    "symmetric_full_mesh":_topology_is_symmetric(topology),
                    "links":topology,
                }, sort_keys=True) + "\n")
                samples_file.flush()
                if time.monotonic() - last_report >= 15:
                    elapsed = int(args.duration - (deadline-time.monotonic()))
                    print(f"elapsed={elapsed}s peer_counts={counts} links={len(topology)}",
                          flush=True)
                    last_report = time.monotonic()
                if any(processes[i].poll() is not None for i in processes):
                    raise RuntimeError("A node process exited during the observation window")
                time.sleep(1)
        result["run_start_ns"] = run_start_ns
        result["peer_count_changes"] = peer_count_changes
        result["session_churn"] = session_churn
        result["peer_counts_stayed_full"] = counts_stayed_full
        result["session_ids_stayed_constant"] = not session_churn
        result["all_sampled_meshes_symmetric"] = topology_stayed_symmetric
        result["criteria_passed"] = (
            result["policy_values_consistent"] and counts_stayed_full
            and topology_stayed_symmetric and not session_churn)
        result["topology_samples_file"] = str(samples_path)
        result["final_states"] = [_read_state(node["state"]) for node in nodes]
        result["completed"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["final_states"] = [_read_state(node["state"]) for node in nodes]
        raise
    finally:
        for index in sorted(processes, reverse=True):
            proc = processes[index]
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        for index in sorted(processes, reverse=True):
            proc = processes[index]
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        for handle in handles.values():
            handle.close()
        if tcpdump_proc is not None:
            if tcpdump_proc.poll() is None:
                tcpdump_proc.send_signal(signal.SIGINT)
                try:
                    tcpdump_proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    tcpdump_proc.kill()
                    tcpdump_proc.wait(timeout=5)
            if tcpdump_handle is not None:
                tcpdump_handle.close()
        for node in nodes:
            result["event_counts"][str(node["index"])] = _log_event_counts(node["trace"])
        result["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (out / "run_summary.json").write_text(json.dumps(result, indent=2, sort_keys=True),
                                               encoding="utf-8")
        print(f"Run artifacts: {out}", flush=True)
        print(f"Summary: {out / 'run_summary.json'}", flush=True)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, TimeoutError) as error:
        print(f"TEST ABORTED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)
