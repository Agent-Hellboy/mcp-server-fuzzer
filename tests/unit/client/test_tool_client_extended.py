"""Extended tests for tool_client.py to improve coverage."""

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from mcp_fuzzer.client.tool_client import ToolClient
from mcp_fuzzer.auth import AuthManager


@pytest.fixture
def mock_transport():
    """Create a mock transport."""
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"result": "ok"})
    return transport


@pytest.fixture
def mock_safety():
    """Create a mock safety system."""
    safety = MagicMock()
    safety.should_skip_tool_call = MagicMock(return_value=False)
    safety.sanitize_tool_arguments = MagicMock(side_effect=lambda name, args: args)
    return safety


@pytest.fixture
def tool_client(mock_transport, mock_safety):
    """Create a ToolClient with mocked dependencies."""
    return ToolClient(
        transport=mock_transport,
        safety_system=mock_safety,
        auth_manager=AuthManager(),
    )


class TestGetToolsFromServer:
    """Test _get_tools_from_server method."""

    @pytest.mark.asyncio
    async def test_get_tools_success(self, tool_client):
        """Test getting tools successfully."""
        tool_client._rpc.get_tools = AsyncMock(return_value=[
            {"name": "test_tool", "inputSchema": {"type": "object"}}
        ])
        
        result = await tool_client._get_tools_from_server()
        assert len(result) == 1
        assert result[0]["name"] == "test_tool"

    @pytest.mark.asyncio
    async def test_get_tools_empty_list(self, tool_client):
        """Test getting empty tools list."""
        tool_client._rpc.get_tools = AsyncMock(return_value=[])
        
        result = await tool_client._get_tools_from_server()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_tools_exception(self, tool_client):
        """Test handling exception when getting tools."""
        err = Exception("connection failed")
        tool_client._rpc.get_tools = AsyncMock(side_effect=err)
        
        result = await tool_client._get_tools_from_server()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_tools_records_schema_checks(self, tool_client):
        """Test that schema checks are recorded for tools."""
        tool_client._rpc.get_tools = AsyncMock(
            return_value=[
                {"name": "test_tool"}  # Missing inputSchema should trigger check
            ]
        )
        
        with patch(
            "mcp_fuzzer.spec_guard.check_tool_schema_fields"
        ) as mock_check:
            mock_check.return_value = [{"status": "FAIL", "message": "Missing schema"}]
            await tool_client._get_tools_from_server()
            assert "test_tool" in tool_client._tool_schema_checks


class TestFuzzTool:
    """Test fuzz_tool method."""

    @pytest.mark.asyncio
    async def test_fuzz_tool_success(self, tool_client, mock_safety):
        """Test successful tool fuzzing."""
        tool = {"name": "test_tool", "inputSchema": {"type": "object"}}
        tool_client.tool_mutator.mutate = AsyncMock(return_value={"foo": "bar"})
        tool_client._rpc.call_tool = AsyncMock(return_value={"content": []})
        
        results = await tool_client.fuzz_tool(tool, runs=2)
        
        assert len(results) == 2
        assert all(r.get("success") for r in results)

    @pytest.mark.asyncio
    async def test_fuzz_tool_safety_blocked(self, tool_client, mock_safety):
        """Test tool fuzzing when safety blocks the call."""
        mock_safety.should_skip_tool_call.return_value = True
        
        tool = {"name": "dangerous_tool"}
        tool_client.tool_mutator.mutate = AsyncMock(return_value={"cmd": "rm -rf"})
        
        results = await tool_client.fuzz_tool(tool, runs=1)
        
        assert len(results) == 1
        assert results[0]["safety_blocked"] is True
        assert results[0]["exception"] == "safety_blocked"

    @pytest.mark.asyncio
    async def test_fuzz_tool_safety_sanitized(self, tool_client, mock_safety):
        """Test tool fuzzing when safety sanitizes arguments."""
        mock_safety.sanitize_tool_arguments.side_effect = None
        mock_safety.sanitize_tool_arguments.return_value = {"cmd": "safe_value"}
        
        tool = {"name": "test_tool"}
        tool_client.tool_mutator.mutate = AsyncMock(
            return_value={"cmd": "dangerous_value"}
        )
        tool_client._rpc.call_tool = AsyncMock(return_value={"content": []})
        
        results = await tool_client.fuzz_tool(tool, runs=1)
        
        assert len(results) == 1
        assert results[0]["safety_sanitized"] is True

    @pytest.mark.asyncio
    async def test_fuzz_tool_call_exception(self, tool_client):
        """Test handling exception during tool call."""
        tool = {"name": "test_tool"}
        tool_client.tool_mutator.mutate = AsyncMock(return_value={})
        tool_client._rpc.call_tool = AsyncMock(
            side_effect=Exception("call failed")
        )
        
        results = await tool_client.fuzz_tool(tool, runs=1)
        
        assert len(results) == 1
        assert results[0]["success"] is False
        assert "call failed" in results[0]["exception"]

    @pytest.mark.asyncio
    async def test_fuzz_tool_mutator_exception(self, tool_client):
        """Test handling exception from mutator."""
        tool = {"name": "test_tool"}
        tool_client.tool_mutator.mutate = AsyncMock(
            side_effect=Exception("mutator failed")
        )
        
        results = await tool_client.fuzz_tool(tool, runs=1)
        
        assert len(results) == 1
        assert results[0]["success"] is False
        assert "mutator failed" in results[0]["exception"]


class TestFuzzAllTools:
    """Test fuzz_all_tools method."""

    @pytest.mark.asyncio
    async def test_fuzz_all_tools_success(self, tool_client):
        """Test fuzzing all tools successfully."""
        tool_client._get_tools_from_server = AsyncMock(
            return_value=[
                {"name": "tool1"},
                {"name": "tool2"},
            ]
        )
        tool_client._fuzz_single_tool_with_timeout = AsyncMock(
            return_value=[{"success": True}]
        )
        
        results = await tool_client.fuzz_all_tools(runs_per_tool=1)
        
        assert "tool1" in results
        assert "tool2" in results

    @pytest.mark.asyncio
    async def test_fuzz_all_tools_empty(self, tool_client):
        """Test fuzzing when no tools available."""
        tool_client._get_tools_from_server = AsyncMock(return_value=[])
        
        results = await tool_client.fuzz_all_tools()
        assert results == {}

    @pytest.mark.asyncio
    async def test_fuzz_all_tools_timeout_protection(self, tool_client):
        """Test overall timeout protection."""
        tool_client._get_tools_from_server = AsyncMock(
            return_value=[{"name": "tool1"}]
        )
        
        # Simulate very slow fuzzing
        async def slow_fuzz(*args, **kwargs):
            await asyncio.sleep(0.1)
            return [{"success": True}]
        
        tool_client._fuzz_single_tool_with_timeout = slow_fuzz
        
        # This should complete without hanging
        results = await tool_client.fuzz_all_tools(runs_per_tool=1)
        assert "tool1" in results


class TestFuzzSingleToolWithTimeout:
    """Test _fuzz_single_tool_with_timeout method."""

    @pytest.mark.asyncio
    async def test_fuzz_with_timeout_success(self, tool_client):
        """Test successful fuzzing within timeout."""
        tool = {"name": "test_tool"}
        tool_client.fuzz_tool = AsyncMock(return_value=[{"success": True}])
        
        results = await tool_client._fuzz_single_tool_with_timeout(tool, 1)
        
        assert len(results) == 1
        assert results[0]["success"] is True

    @pytest.mark.asyncio
    async def test_fuzz_with_timeout_exceeds(self, tool_client):
        """Test timeout when fuzzing takes too long."""
        tool = {"name": "slow_tool"}
        
        async def slow_fuzz(*args, **kwargs):
            await asyncio.sleep(100)  # Very long
            return [{"success": True}]
        
        tool_client.fuzz_tool = slow_fuzz
        
        # Patch the default max time to be very short
        with patch.object(tool_client, "fuzz_tool", slow_fuzz):
            with patch("mcp_fuzzer.client.tool_client.DEFAULT_MAX_TOOL_TIME", 0.1):
                results = await tool_client._fuzz_single_tool_with_timeout(tool, 1)
        
                assert len(results) == 1
                assert results[0]["error"] == "tool_timeout"

    @pytest.mark.asyncio
    async def test_fuzz_with_timeout_exception(self, tool_client):
        """Test handling exception during fuzzing."""
        tool = {"name": "failing_tool"}
        tool_client.fuzz_tool = AsyncMock(side_effect=Exception("unexpected error"))
        
        results = await tool_client._fuzz_single_tool_with_timeout(tool, 1)
        
        assert len(results) == 1
        assert "unexpected error" in results[0]["error"]


class TestFuzzToolBothPhases:
    """Test fuzz_tool_both_phases method."""

    @pytest.mark.asyncio
    async def test_both_phases_success(self, tool_client):
        """Test successful two-phase fuzzing."""
        tool = {"name": "test_tool"}
        tool_client.tool_mutator.mutate = AsyncMock(return_value={})
        tool_client._process_fuzz_results = AsyncMock(return_value=[{"success": True}])
        
        results = await tool_client.fuzz_tool_both_phases(tool, runs_per_phase=2)
        
        assert "realistic" in results
        assert "aggressive" in results
        assert len(results["realistic"]) == 1
        assert len(results["aggressive"]) == 1

    @pytest.mark.asyncio
    async def test_both_phases_exception(self, tool_client):
        """Test handling exception in two-phase fuzzing."""
        tool = {"name": "test_tool"}
        tool_client.tool_mutator.mutate = AsyncMock(
            side_effect=Exception("mutator error")
        )
        
        results = await tool_client.fuzz_tool_both_phases(tool, runs_per_phase=1)
        
        assert "error" in results
        assert "mutator error" in results["error"]


class TestProcessFuzzResults:
    """Test _process_fuzz_results method."""

    @pytest.mark.asyncio
    async def test_process_results_success(self, tool_client):
        """Test processing fuzz results successfully."""
        tool_client._rpc.call_tool = AsyncMock(return_value={"content": []})
        
        fuzz_results = [{"args": {"foo": "bar"}}]
        
        results = await tool_client._process_fuzz_results("test_tool", fuzz_results)
        
        assert len(results) == 1
        assert results[0]["success"] is True

    @pytest.mark.asyncio
    async def test_process_results_safety_blocked(self, tool_client, mock_safety):
        """Test processing when safety blocks."""
        mock_safety.should_skip_tool_call.return_value = True
        
        fuzz_results = [{"args": {"cmd": "rm -rf"}}]
        
        results = await tool_client._process_fuzz_results("test_tool", fuzz_results)
        
        assert len(results) == 1
        assert results[0]["safety_blocked"] is True

    @pytest.mark.asyncio
    async def test_process_results_call_exception(self, tool_client):
        """Test processing when tool call fails."""
        tool_client._rpc.call_tool = AsyncMock(side_effect=Exception("call failed"))
        
        fuzz_results = [{"args": {}}]
        
        results = await tool_client._process_fuzz_results("test_tool", fuzz_results)
        
        assert len(results) == 1
        assert results[0]["success"] is False
        assert "call failed" in results[0]["exception"]


class TestFuzzAllToolsBothPhases:
    """Test fuzz_all_tools_both_phases method."""

    @pytest.mark.asyncio
    async def test_fuzz_all_both_phases_success(self, tool_client):
        """Test fuzzing all tools in both phases."""
        tool_client._get_tools_from_server = AsyncMock(
            return_value=[{"name": "tool1"}]
        )
        tool_client._fuzz_single_tool_both_phases = AsyncMock(
            return_value={"realistic": [], "aggressive": []}
        )
        
        results = await tool_client.fuzz_all_tools_both_phases(runs_per_phase=1)
        
        assert "tool1" in results

    @pytest.mark.asyncio
    async def test_fuzz_all_both_phases_no_tools(self, tool_client):
        """Test fuzzing all when no tools available."""
        tool_client._get_tools_from_server = AsyncMock(return_value=[])
        
        results = await tool_client.fuzz_all_tools_both_phases()
        
        assert results == {}

    @pytest.mark.asyncio
    async def test_fuzz_all_both_phases_exception(self, tool_client):
        """Test handling exception in fuzz_all_tools_both_phases."""
        tool_client._get_tools_from_server = AsyncMock(side_effect=Exception("error"))
        
        results = await tool_client.fuzz_all_tools_both_phases()
        
        assert results == {}


class TestShutdown:
    """Test shutdown method."""

    @pytest.mark.asyncio
    async def test_shutdown(self, tool_client):
        """Test shutdown is successful."""
        await tool_client.shutdown()
        # Should complete without error


class TestPrintPhaseReport:
    """Test _print_phase_report method."""

    def test_print_phase_report_no_reporter(self, tool_client):
        """Test print phase report when no reporter is set."""
        # Should not raise
        tool_client._print_phase_report("test_tool", "realistic", [])

    def test_print_phase_report_with_reporter(self, tool_client):
        """Test print phase report with reporter."""
        from mcp_fuzzer.reports import FuzzerReporter
        
        mock_reporter = MagicMock(spec=FuzzerReporter)
        mock_reporter.console = MagicMock()
        tool_client.reporter = mock_reporter
        
        results = [{"success": True}, {"success": False}]
        tool_client._print_phase_report("test_tool", "realistic", results)
        
        mock_reporter.console.print.assert_called()


class TestFuzzSingleToolBothPhases:
    """Test _fuzz_single_tool_both_phases method."""

    @pytest.mark.asyncio
    async def test_single_tool_both_phases_success(self, tool_client):
        """Test _fuzz_single_tool_both_phases success."""
        tool = {"name": "test_tool"}
        tool_client.fuzz_tool_both_phases = AsyncMock(
            return_value={"realistic": [], "aggressive": []}
        )
        
        result = await tool_client._fuzz_single_tool_both_phases(tool, 2)
        
        assert "realistic" in result
        assert "aggressive" in result

    @pytest.mark.asyncio
    async def test_single_tool_both_phases_error_result(self, tool_client):
        """Test _fuzz_single_tool_both_phases with error in result."""
        tool = {"name": "test_tool"}
        tool_client.fuzz_tool_both_phases = AsyncMock(
            return_value={"error": "some error"}
        )
        
        result = await tool_client._fuzz_single_tool_both_phases(tool, 2)
        
        assert "error" in result

    @pytest.mark.asyncio
    async def test_single_tool_both_phases_exception(self, tool_client):
        """Test _fuzz_single_tool_both_phases with exception."""
        tool = {"name": "test_tool"}
        tool_client.fuzz_tool_both_phases = AsyncMock(side_effect=Exception("boom"))
        
        result = await tool_client._fuzz_single_tool_both_phases(tool, 2)
        
        assert "error" in result
        assert "boom" in result["error"]


class TestSafetyDisabled:
    """Test behavior when safety is disabled."""

    @pytest.mark.asyncio
    async def test_fuzz_tool_with_safety_disabled(self, mock_transport):
        """Test fuzzing when safety is disabled."""
        client = ToolClient(
            transport=mock_transport,
            safety_system=None,
            enable_safety=False,
        )
        
        tool = {"name": "test_tool"}
        client.tool_mutator.mutate = AsyncMock(return_value={})
        client._rpc.call_tool = AsyncMock(return_value={"content": []})
        
        results = await client.fuzz_tool(tool, runs=1)
        
        assert len(results) == 1
        assert results[0]["safety_blocked"] is False
        assert results[0]["safety_sanitized"] is False
