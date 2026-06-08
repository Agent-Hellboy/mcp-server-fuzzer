package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type EchoInput struct {
	Text string `json:"text" jsonschema:"text to echo back to the caller"`
}

type EchoOutput struct {
	Message string `json:"message" jsonschema:"echoed message"`
}

type AddInput struct {
	A int `json:"a" jsonschema:"first integer"`
	B int `json:"b" jsonschema:"second integer"`
}

type AddOutput struct {
	Sum int `json:"sum" jsonschema:"sum of a and b"`
}

type NormalizeInput struct {
	Value string `json:"value" jsonschema:"value to trim and lowercase"`
}

type NormalizeOutput struct {
	Value string `json:"value" jsonschema:"normalized value"`
}

func echoTool(_ context.Context, _ *mcp.CallToolRequest, input EchoInput) (*mcp.CallToolResult, EchoOutput, error) {
	return nil, EchoOutput{Message: input.Text}, nil
}

func addTool(_ context.Context, _ *mcp.CallToolRequest, input AddInput) (*mcp.CallToolResult, AddOutput, error) {
	return nil, AddOutput{Sum: input.A + input.B}, nil
}

func normalizeTool(_ context.Context, _ *mcp.CallToolRequest, input NormalizeInput) (*mcp.CallToolResult, NormalizeOutput, error) {
	return nil, NormalizeOutput{Value: strings.ToLower(strings.TrimSpace(input.Value))}, nil
}

func main() {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "mcp-fuzzer-go-stdio-example", Version: "v1.0.0"},
		nil,
	)

	mcp.AddTool(
		server,
		&mcp.Tool{Name: "echo_tool", Description: "Echo text back to the caller"},
		echoTool,
	)
	mcp.AddTool(
		server,
		&mcp.Tool{Name: "add_numbers", Description: "Add two integers"},
		addTool,
	)
	mcp.AddTool(
		server,
		&mcp.Tool{Name: "normalize_text", Description: "Trim and lowercase text"},
		normalizeTool,
	)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(fmt.Errorf("run MCP stdio server: %w", err))
	}
}
