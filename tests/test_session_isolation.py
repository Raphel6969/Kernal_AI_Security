import os
import pytest
from fastapi.testclient import TestClient

# Ensure session mode is enabled for the app under test
os.environ['SESSION_MODE'] = 'true'

from backend.app import app


@pytest.fixture
def client():
    return TestClient(app)


def get_token(client):
    r = client.get('/session')
    assert r.status_code == 200
    return r.json()['session_token']


def test_two_sessions_isolated(client):
    # Ensure session mode is enabled for the test environment
    # (the test environment may override settings via env vars)
    t1 = get_token(client)
    t2 = get_token(client)
    assert t1 != t2

    # Post one event under session 1
    r = client.post(f'/analyze?session_token={t1}', json={'command': 'echo hello'})
    assert r.status_code == 200

    # Post one event under session 2
    r = client.post(f'/analyze?session_token={t2}', json={'command': 'echo world'})
    assert r.status_code == 200

    # Retrieve events for session 1
    r = client.get(f'/events?session_token={t1}')
    assert r.status_code == 200
    events1 = r.json()
    assert any('hello' in e.get('command', '') for e in events1)
    assert not any('world' in e.get('command', '') for e in events1)

    # Retrieve events for session 2
    r = client.get(f'/events?session_token={t2}')
    assert r.status_code == 200
    events2 = r.json()
    assert any('world' in e.get('command', '') for e in events2)
    assert not any('hello' in e.get('command', '') for e in events2)
