from backend.agent import runtime


def test_detect_capabilities_linux(monkeypatch):
    monkeypatch.setattr(runtime.platform, "system", lambda: "Linux")

    capabilities = runtime.detect_capabilities()

    assert capabilities.os_name == "Linux"
    assert capabilities.run_mode == "kernel"
    assert capabilities.kernel_capture_supported is True


def test_detect_capabilities_macos(monkeypatch):
    monkeypatch.setattr(runtime.platform, "system", lambda: "Darwin")

    capabilities = runtime.detect_capabilities()

    assert capabilities.os_name == "Darwin"
    assert capabilities.run_mode == "api-only"
    assert capabilities.kernel_capture_supported is False
