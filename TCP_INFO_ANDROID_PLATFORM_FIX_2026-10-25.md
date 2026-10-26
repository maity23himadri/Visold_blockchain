# TCP_INFO Android platform-detection fix — 2026-10-25

## Root cause

`_tcp_transport_snapshot()` returned `unsupported_platform` whenever
`sys.platform` did not start with `linux`. On Termux, Python 3.14 reports
`sys.platform == "android"`, although the kernel is Linux and `socket.TCP_INFO`
was available. A direct Termux probe successfully read 104 bytes of TCP_INFO
and observed state code 1 (`ESTABLISHED`).

## Change

- Removed the `sys.platform` gate from the diagnostic-only TCP_INFO probe.
- The helper now checks whether `socket.TCP_INFO` exists and tries `getsockopt`.
- Unsupported options or socket behavior still degrade to a diagnostic status;
  peer connection/disconnection behavior is not changed.
- Added a regression test simulating `sys.platform == "android"` while the fake
  socket supplies TCP_INFO.

This change affects passive diagnostic reporting only. It does not change
consensus, peer admission, TLS policy, or socket cleanup flow.
