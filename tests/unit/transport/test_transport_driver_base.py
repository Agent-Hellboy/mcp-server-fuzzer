import pytest

from mcp_fuzzer.transport.interfaces.driver import TransportDriver

pytestmark = [pytest.mark.unit, pytest.mark.transport]


class DummyDriver(TransportDriver):
    def __init__(self) -> None:
        self.requests = []
        self.notifications = []
        self.raw_payloads = []

    async def send_request(self, method, params=None):
        self.requests.append((method, params))
        return {"method": method, "params": params}

    async def send_raw(self, payload):
        self.raw_payloads.append(payload)
        return payload

    async def send_notification(self, method, params=None):
        self.notifications.append((method, params))
        return None

    async def _stream_request(self, payload):
        for chunk in (1, 2):
            yield {"chunk": chunk, "payload": payload}


@pytest.mark.asyncio
async def test_stream_request_delegates_to_impl():
    driver = DummyDriver()
    items = [item async for item in driver.stream_request({"id": 1})]
    assert items == [
        {"chunk": 1, "payload": {"id": 1}},
        {"chunk": 2, "payload": {"id": 1}},
    ]


@pytest.mark.asyncio
async def test_default_connect_disconnect_noop():
    driver = DummyDriver()
    await driver.connect()
    await driver.disconnect()
