import pytest

from mcp_fuzzer.exceptions import PayloadValidationError, TransportError
from mcp_fuzzer.transport.wrappers.retrying import RetryingTransport, RetryPolicy
from mcp_fuzzer.transport.interfaces.driver import TransportDriver


class DummyTransport(TransportDriver):
    def __init__(self, fail_times: int = 0):
        self.fail_times = fail_times
        self.calls = 0
        self.batch_calls = 0

    async def send_request(self, method, params=None):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise TransportError("boom")
        return {"ok": True, "method": method}

    async def send_raw(self, payload):
        return payload

    async def send_notification(self, method, params=None):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise TransportError("notify boom")
        return None

    async def send_batch_request(self, batch):
        self.batch_calls += 1
        if self.batch_calls <= self.fail_times:
            raise TransportError("batch boom")
        return [{"id": 1}]

    async def _stream_request(self, payload):
        if False:  # pragma: no cover
            yield payload


class NoBatchTransport(TransportDriver):
    async def send_request(self, method, params=None):
        return {"ok": True}

    async def send_raw(self, payload):
        return payload

    async def send_notification(self, method, params=None):
        return None

    async def _stream_request(self, payload):
        if False:  # pragma: no cover - never executed
            yield payload


class FlakyTransport(TransportDriver):
    def __init__(self, fail_raw=0, fail_notify=0, fail_connect=0):
        self.raw_calls = 0
        self.notify_calls = 0
        self.connect_calls = 0
        self.fail_raw = fail_raw
        self.fail_notify = fail_notify
        self.fail_connect = fail_connect

    async def send_request(self, method, params=None):
        return {"ok": True}

    async def send_raw(self, payload):
        self.raw_calls += 1
        if self.raw_calls <= self.fail_raw:
            raise TransportError("raw boom")
        return payload

    async def send_notification(self, method, params=None):
        self.notify_calls += 1
        if self.notify_calls <= self.fail_notify:
            raise TransportError("notify boom")
        return None

    async def connect(self):
        self.connect_calls += 1
        if self.connect_calls <= self.fail_connect:
            raise TransportError("connect boom")

    async def _stream_request(self, payload):
        if False:  # pragma: no cover - never executed
            yield payload


def test_retry_policy_clamp_and_next_delay(monkeypatch):
    policy = RetryPolicy(
        max_attempts=0,
        base_delay=-1.0,
        max_delay=-5.0,
        backoff_factor=0.0,
        jitter=-0.5,
    )
    clamped = policy.clamp()
    assert clamped.max_attempts == 1
    assert clamped.base_delay == 0.0
    assert clamped.max_delay == 0.0
    assert clamped.backoff_factor == 1.0
    assert clamped.jitter == 0.0

    transport = RetryingTransport(NoBatchTransport(), policy=clamped)
    assert transport._next_delay(1) == 0.0


def test_next_delay_with_jitter(monkeypatch):
    monkeypatch.setattr(
        "mcp_fuzzer.transport.wrappers.retrying.random.uniform", lambda a, b: b
    )
    transport = RetryingTransport(
        NoBatchTransport(),
        policy=RetryPolicy(max_attempts=2, base_delay=1.0, max_delay=5.0, jitter=0.5),
    )
    delay = transport._next_delay(2)
    assert delay == pytest.approx(3.0)


@pytest.mark.asyncio
async def test_retrying_transport_retries_on_transport_error(monkeypatch):
    delays = []

    async def fake_sleep(value):
        delays.append(value)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)
    transport = RetryingTransport(
        DummyTransport(fail_times=2),
        policy=RetryPolicy(max_attempts=3, base_delay=0.1, jitter=0.0),
    )
    result = await transport.send_request("ping")
    assert result["ok"] is True
    assert transport._transport.calls == 3
    assert delays == [0.1, 0.2]


@pytest.mark.asyncio
async def test_retrying_transport_skips_payload_validation_errors():
    class BadPayloadTransport(DummyTransport):
        async def send_request(self, method, params=None):
            raise PayloadValidationError("bad")

    transport = RetryingTransport(
        BadPayloadTransport(),
        policy=RetryPolicy(max_attempts=3, base_delay=0.0, jitter=0.0),
    )
    with pytest.raises(PayloadValidationError):
        await transport.send_request("ping")


@pytest.mark.asyncio
async def test_retrying_transport_send_raw_and_notification(monkeypatch):
    delays = []

    async def fake_sleep(value):
        delays.append(value)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)
    transport = RetryingTransport(
        FlakyTransport(fail_raw=1, fail_notify=1),
        policy=RetryPolicy(max_attempts=2, base_delay=0.25, jitter=0.0),
    )

    result = await transport.send_raw({"id": 1})
    assert result == {"id": 1}
    await transport.send_notification("notify", {"x": 1})
    assert delays == [0.25, 0.25]


@pytest.mark.asyncio
async def test_retrying_transport_connect_retries(monkeypatch):
    delays = []

    async def fake_sleep(value):
        delays.append(value)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)
    transport = RetryingTransport(
        FlakyTransport(fail_connect=1),
        policy=RetryPolicy(max_attempts=2, base_delay=0.1, jitter=0.0),
    )
    await transport.connect()
    assert transport._transport.connect_calls == 2
    assert delays == [0.1]


@pytest.mark.asyncio
async def test_retrying_transport_batch_request():
    transport = RetryingTransport(
        DummyTransport(fail_times=1),
        policy=RetryPolicy(max_attempts=2, base_delay=0.0, jitter=0.0),
    )
    result = await transport.send_batch_request([{"id": 1}])
    assert result == [{"id": 1}]
    assert transport._transport.batch_calls == 2


@pytest.mark.asyncio
async def test_retrying_transport_send_batch_missing():
    transport = RetryingTransport(NoBatchTransport())
    with pytest.raises(AttributeError):
        await transport.send_batch_request([{"id": 1}])


@pytest.mark.asyncio
async def test_retrying_transport_does_not_retry_unlisted_errors():
    class BadTransport(NoBatchTransport):
        def __init__(self):
            self.calls = 0

        async def send_request(self, method, params=None):
            self.calls += 1
            raise TransportError("boom")

    transport = RetryingTransport(
        BadTransport(),
        policy=RetryPolicy(max_attempts=3, base_delay=0.0, jitter=0.0),
        retry_on=(ValueError,),
    )
    with pytest.raises(TransportError):
        await transport.send_request("ping")
    assert transport._transport.calls == 1
