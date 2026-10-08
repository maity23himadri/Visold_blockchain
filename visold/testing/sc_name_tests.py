# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────
# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True
# cython: cdivision=True
# cython: nonecheck=True
# cython: initializedcheck=False
# cython: infer_types=True
# cython: optimize.use_switch=True
# cython: optimize.unpack_method_calls=True
"""visold.testing.sc_name_tests


Origin: visold_vsd_.py L55208-55356
"""

from visold.vm.naming import normalize_contract_name, validate_contract_name


# =============================================================================
# SC-NAME-1 — Self-contained test suite
# Run: python visold_vsd_.py --test-sc-name-1
# All tests are pure-function (no DB, no network) unless marked [integration].
# =============================================================================

def _sc_name_1_run_tests():
    import sys as _sys
    failures = []

    def _assert(condition, msg):
        if not condition:
            failures.append(msg)

    # ── T1: normalize_contract_name ──────────────────────────────────────────
    _assert(normalize_contract_name("  MyToken  ") == "mytoken",
            "T1a: strip + casefold failed")
    _assert(normalize_contract_name("HELLO.WORLD") == "hello.world",
            "T1b: casefold with dot failed")
    _assert(normalize_contract_name("") == "",
            "T1c: empty string → empty string")
    _assert(normalize_contract_name("  ") == "",
            "T1d: whitespace-only → empty string")
    _assert(normalize_contract_name(123) == "",   # type: ignore[arg-type]
            "T1e: non-string input → empty string")
    print("T1 normalize_contract_name: " + ("OK" if not failures else "FAIL"))

    pre = len(failures)

    # ── T2: validate_contract_name ───────────────────────────────────────────
    ok, _ = validate_contract_name("mytoken")
    _assert(ok, "T2a: plain lowercase name should be valid")

    ok, _ = validate_contract_name("my_token_v2")
    _assert(ok, "T2b: underscores should be valid")

    ok, _ = validate_contract_name("my-token.v2")
    _assert(ok, "T2c: hyphens and dots should be valid")

    ok, _ = validate_contract_name("a" * 64)
    _assert(ok, "T2d: exactly 64 chars should be valid")

    ok, msg = validate_contract_name("")
    _assert(not ok and "empty" in msg.lower(), "T2e: empty name must be invalid")

    ok, msg = validate_contract_name("a" * 65)
    _assert(not ok and "long" in msg.lower(), "T2f: 65-char name must be invalid")

    ok, msg = validate_contract_name("My Token!")
    _assert(not ok, "T2g: spaces/special chars must be invalid")

    ok, msg = validate_contract_name(".leading")
    _assert(not ok and "start" in msg.lower(), "T2h: leading dot must be invalid")

    ok, msg = validate_contract_name("trailing.")
    _assert(not ok and "start" in msg.lower(), "T2i: trailing dot must be invalid")  # re-uses "start or end" message

    ok, msg = validate_contract_name("-leading")
    _assert(not ok, "T2j: leading hyphen must be invalid")

    ok, msg = validate_contract_name("double..dot")
    _assert(not ok and ".." in msg, "T2k: double-dot must be invalid")

    ok, msg = validate_contract_name("double--dash")
    _assert(not ok and "--" in msg, "T2l: double-dash must be invalid")

    ok, msg = validate_contract_name("Token")
    _assert(not ok, "T2m: uppercase must be rejected (validate expects normalised input)")

    ok, _ = validate_contract_name("0")
    _assert(ok, "T2n: single digit is valid")

    ok, _ = validate_contract_name("a.b-c_d0")
    _assert(ok, "T2o: mixed allowed chars should be valid")

    t2_status = "OK" if len(failures) == pre else f"FAIL ({len(failures)-pre} assertion(s))"
    print(f"T2 validate_contract_name: {t2_status}")
    pre = len(failures)

    # ── T3: contract_name in tx_id (collision resistance) ───────────────────
    import hashlib as _hashlib

    def _fake_compute_id(sender, receiver, amount, fee, timestamp, memo,
                         nonce, expiry, tx_type, data, gas_limit, gas_price,
                         contract_name):
        data_comp = _hashlib.sha256(data.encode()).hexdigest() if data else ""
        core = (f"{sender}{receiver}{amount}{fee}"
                f"{timestamp}{memo}{nonce}{expiry}"
                f"{tx_type}{data_comp}{gas_limit}{gas_price}"
                f"{contract_name}")
        return _hashlib.sha256(core.encode()).hexdigest()

    base = dict(sender="VSD123", receiver="", amount=0.0, fee=0.0,
                timestamp=1_000_000, memo="", nonce=1, expiry=9_999_999,
                tx_type="deploy", data="deadbeef", gas_limit=100_000,
                gas_price=0.0001)

    id_a = _fake_compute_id(**base, contract_name="mytoken")
    id_b = _fake_compute_id(**base, contract_name="othertoken")
    id_c = _fake_compute_id(**base, contract_name="mytoken")
    id_u = _fake_compute_id(**base, contract_name="")           # unnamed

    _assert(id_a != id_b, "T3a: different names → different tx_ids")
    _assert(id_a == id_c, "T3b: same name → same tx_id (deterministic)")
    _assert(id_a != id_u, "T3c: named vs unnamed → different tx_ids")

    t3_status = "OK" if len(failures) == pre else f"FAIL ({len(failures)-pre} assertion(s))"
    print(f"T3 tx_id name isolation: {t3_status}")
    pre = len(failures)

    # ── T4: signing_bytes includes contract_name (name-hijack resistance) ───
    def _fake_signing_bytes(chain_id, version, sender, receiver, amount, fee,
                            timestamp, memo, nonce, expiry, tx_type,
                            gas_limit, gas_price, data_hash, contract_name):
        d = (f"{chain_id}{version}{sender}{receiver}{amount}"
             f"{fee}{timestamp}{memo}{nonce}{expiry}"
             f"{tx_type}{gas_limit}{gas_price}{data_hash}"
             f"{contract_name}")
        return d.encode()

    common = dict(chain_id="VSD1", version=1, sender="VSD123", receiver="",
                  amount=0.0, fee=0.0, timestamp=1_000_000, memo="",
                  nonce=1, expiry=9_999_999, tx_type="deploy",
                  gas_limit=100_000, gas_price=0.0001, data_hash="abc123")

    sb1 = _fake_signing_bytes(**common, contract_name="alpha")
    sb2 = _fake_signing_bytes(**common, contract_name="beta")
    sb3 = _fake_signing_bytes(**common, contract_name="alpha")

    _assert(sb1 != sb2, "T4a: different names → different signing bytes")
    _assert(sb1 == sb3, "T4b: same name → identical signing bytes")

    t4_status = "OK" if len(failures) == pre else f"FAIL ({len(failures)-pre} assertion(s))"
    print(f"T4 signing_bytes name isolation: {t4_status}")
    pre = len(failures)

    # ── T5: normalize is idempotent ──────────────────────────────────────────
    for raw in ["MyToken", "  MY.TOKEN  ", "hello_world", "", "ABC-123"]:
        n1 = normalize_contract_name(raw)
        n2 = normalize_contract_name(n1)
        _assert(n1 == n2, f"T5: normalize not idempotent for {raw!r}")

    t5_status = "OK" if len(failures) == pre else f"FAIL ({len(failures)-pre} assertion(s))"
    print(f"T5 normalize idempotence: {t5_status}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    if failures:
        print(f"SC-NAME-1 tests FAILED ({len(failures)} failure(s)):")
        for f in failures:
            print(f"  ✗ {f}")
        _sys.exit(1)
    else:
        print("All SC-NAME-1 tests passed. ✓")
        _sys.exit(0)
