import asyncio

from backend.agent.bridge import AgentEventPayload
from backend.app import AgentEventRequest, ingest_agent_event
from backend.events.event_store import EventStore


def test_agent_payload_serialization():
    payload = AgentEventPayload(command="echo hello", pid=10, comm="bash")

    data = payload.to_dict()

    assert data["command"] == "echo hello"
    assert data["argv_str"] == "echo hello"
    assert data["pid"] == 10


def test_agent_event_ingest_endpoint(monkeypatch, isolated_event_store):
    """Test that agent events are properly ingested into isolated store."""
    monkeypatch.setattr("backend.app.event_store", isolated_event_store)

    response = asyncio.run(
        ingest_agent_event(
            AgentEventRequest(command="echo hello", pid=10, comm="bash")
        )
    )

    assert response.command == "echo hello"
    assert isolated_event_store.size() == 1