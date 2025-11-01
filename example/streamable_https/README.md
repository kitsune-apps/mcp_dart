# Streamable HTTPS Server Example

This example demonstrates how to create a Streamable HTTP server that supports HTTPS using Dart's `HttpServer`.
It includes a simple Caddy configuration for reverse proxying requests to the server.

## Prerequisites

- Caddy server (<https://caddyserver.com/docs/install>) installed

## How to Run

- Run the Dart server:

  ```bash
  dart run server_streamable_https.dart
  ```

- Start the Caddy server with the provided `Caddyfile` (For web based MCP client):

  ```bash
  caddy run
  ```

- Access the server at `https://localhost:8443/mcp`.

The `Caddyfile` is configured to handle HTTPS termination and reverse proxy requests to the Dart server running on port 3000. It's not required for native MCP clients, which can connect directly to the Dart server on port 3000.

## Note

Caddy is used to handle HTTPS termination and reverse proxying. The Dart server listens on port 3000, while Caddy listens on port 8443 for secure connections. Without Caddy, you would need to implement your own HTTPS handling in the Dart server. Furthermore, The MCP server does not properly work when it's connected from a web based MCP client due to the connection limit while it's working fine with a native MCP client.
