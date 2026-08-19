"""Minimal MCP client supporting stdio and streamable HTTP transports.

Everything a tool returns is untrusted data. This layer only transports and
shapes it; the caller is responsible for wrapping it and filtering injection
attempts before it reaches a prompt.
"""

import json
import logging
import shlex
import subprocess
import uuid

import httpx

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "asp", "version": "1.0"}
DEFAULT_TIMEOUT_SECONDS = 30
STDIO_STARTUP_TIMEOUT = 15


class McpError(RuntimeError):
    pass


class McpToolNotAllowed(McpError):
    """Raised when a tool outside the configured allowlist is requested."""


def _request(method, params=None):
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": params or {},
    }


def _extract_result(body):
    if not isinstance(body, dict):
        raise McpError("MCP server returned a non-object response.")
    if "error" in body:
        error = body["error"] or {}
        raise McpError(f"MCP error {error.get('code')}: {error.get('message')}")
    return body.get("result") or {}


def _parse_sse(text):
    """Streamable HTTP servers may answer with an SSE frame."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload and payload != "[DONE]":
                try:
                    return json.loads(payload)
                except json.JSONDecodeError:
                    continue
    raise McpError("Could not parse an MCP response from the SSE stream.")


class McpClient:
    def __init__(self, config):
        self.config = config
        self.name = config.get("name", "mcp")
        self.transport = (config.get("transport") or "http").lower()
        self.allowed_tools = set(config.get("allowed_tools") or [])
        self.timeout = config.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS

    # ------------------------------------------------------------- transport

    def _headers(self):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        auth_header = (self.config.get("auth_header") or "").strip()
        token = (self.config.get("token") or "").strip()
        if auth_header and token:
            headers[auth_header] = token
        elif token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _http_call(self, payload):
        url = (self.config.get("url_or_command") or "").strip()
        if not url:
            raise McpError(f"MCP server {self.name} has no URL configured.")
        try:
            with httpx.Client(timeout=self.timeout, trust_env=False) as client:
                response = client.post(url, headers=self._headers(), json=payload)
        except httpx.HTTPError as exc:
            raise McpError(f"MCP request to {self.name} failed: {type(exc).__name__}") from exc

        if not response.is_success:
            raise McpError(f"MCP server {self.name} returned HTTP {response.status_code}.")

        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            return _extract_result(_parse_sse(response.text))
        try:
            return _extract_result(response.json())
        except ValueError as exc:
            raise McpError(f"MCP server {self.name} returned non-JSON content.") from exc

    def _stdio_call(self, payloads):
        command = (self.config.get("url_or_command") or "").strip()
        if not command:
            raise McpError(f"MCP server {self.name} has no command configured.")

        lines = "\n".join(json.dumps(item) for item in payloads) + "\n"
        try:
            process = subprocess.run(
                shlex.split(command),
                input=lines,
                capture_output=True,
                text=True,
                timeout=self.timeout + STDIO_STARTUP_TIMEOUT,
            )
        except FileNotFoundError as exc:
            raise McpError(f"MCP command not found for {self.name}: {command}") from exc
        except subprocess.TimeoutExpired as exc:
            raise McpError(f"MCP command timed out for {self.name}.") from exc

        results = []
        for line in (process.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if not results:
            raise McpError(
                f"MCP command for {self.name} produced no JSON-RPC output: {(process.stderr or '')[:200]}"
            )
        return _extract_result(results[-1])

    def _call(self, method, params=None):
        payload = _request(method, params)
        if self.transport == "stdio":
            handshake = _request("initialize", {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            })
            return self._stdio_call([handshake, payload])
        return self._http_call(payload)

    # ----------------------------------------------------------------- tools

    def list_tools(self):
        result = self._call("tools/list")
        return [tool.get("name") for tool in result.get("tools", []) if tool.get("name")]

    def call_tool(self, tool_name, arguments=None):
        if tool_name not in self.allowed_tools:
            # An unlisted tool is a hard error, never a warning.
            raise McpToolNotAllowed(
                f"Tool '{tool_name}' is not in the allowlist for MCP server {self.name}."
            )
        result = self._call("tools/call", {"name": tool_name, "arguments": arguments or {}})
        return self._flatten_content(result)

    @staticmethod
    def _flatten_content(result):
        """Return tool output as plain text blocks. Content stays untrusted."""
        blocks = []
        for item in result.get("content", []) or []:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text" and item.get("text"):
                blocks.append(str(item["text"]))
            elif item.get("type") == "resource":
                resource = item.get("resource") or {}
                if resource.get("text"):
                    blocks.append(str(resource["text"]))
        if not blocks and result.get("structuredContent"):
            blocks.append(json.dumps(result["structuredContent"], ensure_ascii=False))
        return blocks

    def health_check(self):
        try:
            tools = self.list_tools()
        except McpError as exc:
            return {"healthy": False, "detail": str(exc), "tools": []}

        missing = sorted(self.allowed_tools - set(tools))
        detail = f"{len(tools)} tool(s) available."
        if missing:
            detail += f" Allowlisted but not offered: {', '.join(missing)}."
        return {"healthy": True, "detail": detail, "tools": tools}


def get_clients(enabled_only=True):
    from apps.settings.runtime_config import get_mcp_configs

    return [
        McpClient(config)
        for config in get_mcp_configs()
        if config.get("enabled") or not enabled_only
    ]
