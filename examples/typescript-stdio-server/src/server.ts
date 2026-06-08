import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
  name: "mcp-fuzzer-typescript-stdio-example",
  version: "1.0.0",
});

server.registerTool(
  "echo_tool",
  {
    title: "Echo Tool",
    description: "Echo text back to the caller",
    inputSchema: {
      text: z.string().default("default"),
    },
    outputSchema: {
      message: z.string(),
    },
  },
  async ({ text }) => {
    const output = { message: text };
    return {
      content: [{ type: "text", text: output.message }],
      structuredContent: output,
    };
  },
);

server.registerTool(
  "add_numbers",
  {
    title: "Add Numbers",
    description: "Add two integers",
    inputSchema: {
      a: z.number().int().default(0),
      b: z.number().int().default(0),
    },
    outputSchema: {
      sum: z.number().int(),
    },
  },
  async ({ a, b }) => {
    const output = { sum: a + b };
    return {
      content: [{ type: "text", text: String(output.sum) }],
      structuredContent: output,
    };
  },
);

server.registerTool(
  "normalize_text",
  {
    title: "Normalize Text",
    description: "Trim and lowercase text",
    inputSchema: {
      value: z.string().default("Default"),
    },
    outputSchema: {
      value: z.string(),
    },
  },
  async ({ value }) => {
    const output = { value: value.trim().toLowerCase() };
    return {
      content: [{ type: "text", text: output.value }],
      structuredContent: output,
    };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
