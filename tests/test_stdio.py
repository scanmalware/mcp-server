from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from scanmalware_mcp import server


class StdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_sdk_initializes_and_discovers_the_same_tools_and_resources(self) -> None:
        params = StdioServerParameters(
            command=sys.executable,
            args=['-m', 'scanmalware_mcp', '--transport', 'stdio'],
            cwd=str(Path(server.__file__).resolve().parent.parent),
            env={'SCANMALWARE_BEARER_TOKEN': '', 'MCP_AUTH_TOKEN': ''},
        )
        with anyio.fail_after(10), tempfile.TemporaryFile(mode='w+') as errors:
            async with stdio_client(params, errlog=errors) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    templates = await session.list_resource_templates()
        self.assertEqual(len(tools.tools), 145)
        self.assertEqual(len(templates.resource_templates), 4)
        semantic = next(tool for tool in tools.tools if tool.name == 'search_semantic')
        self.assertEqual(semantic.input_schema['properties']['threshold']['default'], -0.2)


if __name__ == '__main__': unittest.main()
