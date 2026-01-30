#!/usr/bin/env python3
"""
Unit tests for TransportDriver interface behavior.
"""

import pytest

from mcp_fuzzer.transport.interfaces.driver import TransportDriver

pytestmark = [pytest.mark.unit, pytest.mark.transport]


class DummyDriver(TransportDriver):
    async def send_request(self, method, params=None):
        return {"method": method, "params": params}

    async def send_raw(self, payload):
        return payload

    async def send_notification(self, method, params=None):
        return None

    async def _stream_request(self, payload):
        for item in [{"chunk": 1}, {"chunk": 2}]:
            yield item


@pytest.mark.asyncio
async def test_stream_request_delegates():
    driver = DummyDriver()
    results = [item async for item in driver.stream_request({"id": 1})]
    assert results == [{"chunk": 1}, {"chunk": 2}]


@pytest.mark.asyncio
async def test_connect_disconnect_noop():
    driver = DummyDriver()
    await driver.connect()
    await driver.disconnect()
