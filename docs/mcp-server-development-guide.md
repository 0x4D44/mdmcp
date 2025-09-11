# Model Context Protocol (MCP) Server Development Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Protocol Overview](#protocol-overview)
3. [Architecture](#architecture)
4. [Server Implementation](#server-implementation)
5. [Claude Desktop Integration](#claude-desktop-integration)
6. [Core Components](#core-components)
7. [Transport Mechanisms](#transport-mechanisms)
8. [Security Considerations](#security-considerations)
9. [Development Examples](#development-examples)
10. [Testing and Debugging](#testing-and-debugging)
11. [Deployment and Distribution](#deployment-and-distribution)
12. [Best Practices](#best-practices)
13. [Resources and References](#resources-and-references)

## Introduction

The Model Context Protocol (MCP) is an open standard introduced by Anthropic in November 2024 that standardizes how applications provide context to large language models (LLMs). Often described as "a USB-C port for AI applications," MCP enables secure, two-way connections between AI systems and external data sources, tools, and services.

### Key Benefits

- **Standardized Integration**: Universal protocol for connecting AI models with external systems
- **Security**: Maintains data within your infrastructure while interacting with AI
- **Flexibility**: Easy switching between different AI models and vendors
- **Interoperability**: Single protocol replaces fragmented integrations
- **Open Source**: Community-driven development with official SDKs

## Protocol Overview

### Version Information

- **Current Version**: `2025-06-18`
- **Versioning Format**: `YYYY-MM-DD` (date of last backwards incompatible changes)
- **Version States**: Draft, Current, Final
- **Compatibility**: Backwards compatible updates don't increment version

### Core Principles

1. **Client-Server Architecture**: Clear separation between MCP clients and servers
2. **JSON-RPC Based**: Uses JSON-RPC 2.0 for message exchange
3. **Transport Agnostic**: Supports stdio, HTTP, and custom transports
4. **Security First**: Built-in security considerations and access controls
5. **Multi-Modal Support**: Text, images, and audio content

## Architecture

MCP follows a three-layer architecture:

### 1. Host Applications
- AI applications that want to access external systems
- Examples: Claude Desktop, IDEs, chat interfaces
- Integrate MCP clients to communicate with servers

### 2. MCP Clients
- Embedded within host applications
- Handle protocol communication
- Manage server connections and capabilities

### 3. MCP Servers
- Expose tools, resources, and prompts to clients
- Implement business logic for external system integration
- Run as separate processes or services

### Communication Flow

```
Host Application (Claude Desktop)
    ↓
MCP Client (built into host)
    ↓ (JSON-RPC over transport)
MCP Server (your implementation)
    ↓
External Systems (databases, APIs, etc.)
```

## Server Implementation

### Supported Languages

MCP provides official SDKs for:
- **Python** - Most mature SDK with comprehensive examples
- **TypeScript** - Full-featured with Node.js runtime
- **C#** - .NET implementation
- **Java/Kotlin** - JVM implementations  
- **Go** - Native Go implementation
- **Ruby** - Ruby language support
- **Rust** - Systems programming implementation
- **Swift** - iOS/macOS development

### Basic Server Structure

#### Python Example

```python
import asyncio
from mcp.server import Server
from mcp.types import Tool, TextContent

# Initialize server
app = Server("my-server")

@app.tool()
async def get_weather(location: str) -> str:
    """Get weather information for a location."""
    # Implementation here
    return f"Weather in {location}: Sunny, 72°F"

@app.resource("config://settings")
async def get_settings():
    """Return configuration settings."""
    return TextContent(
        type="text",
        text="Server configuration data"
    )

if __name__ == "__main__":
    asyncio.run(app.run())
```

#### TypeScript Example

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  {
    name: "my-server",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  }
);

// Register a tool
server.setRequestHandler("tools/list", async () => ({
  tools: [
    {
      name: "get_weather",
      description: "Get weather information",
      inputSchema: {
        type: "object",
        properties: {
          location: { type: "string" }
        }
      }
    }
  ]
}));

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
```

### Server Capabilities

Servers can declare support for:

1. **Tools**: `{ "tools": {} }`
2. **Resources**: `{ "resources": { "subscribe": true, "listChanged": true } }`
3. **Prompts**: `{ "prompts": { "listChanged": true } }`
4. **Sampling**: `{ "sampling": {} }`

## Claude Desktop Integration

### Configuration Setup

Claude Desktop reads MCP server configurations from:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Configuration Format

```json
{
  "mcpServers": {
    "my-server": {
      "command": "python",
      "args": ["/path/to/my-server.py"],
      "env": {
        "API_KEY": "your-api-key"
      }
    },
    "typescript-server": {
      "command": "node",
      "args": ["/path/to/server.js"]
    }
  }
}
```

### Installation Best Practices

1. **Use absolute paths** for commands and arguments
2. **Set environment variables** for API keys and configuration
3. **Test server independently** before Claude Desktop integration
4. **Check Claude Desktop logs** for connection issues
5. **Restart Claude Desktop** after configuration changes

## Core Components

### 1. Tools

Tools are **model-controlled** functions that language models can automatically discover and invoke.

#### Tool Definition

```json
{
  "name": "query_database",
  "description": "Query the customer database",
  "inputSchema": {
    "type": "object",
    "properties": {
      "query": {
        "type": "string",
        "description": "SQL query to execute"
      },
      "limit": {
        "type": "integer",
        "default": 10,
        "maximum": 100
      }
    },
    "required": ["query"]
  }
}
```

#### Implementation Requirements

- **Unique name**: Must be unique within the server
- **Clear description**: Helps models understand tool purpose
- **JSON Schema**: Define input validation rules
- **Error handling**: Return structured error responses
- **Security validation**: Always validate inputs

#### Python Tool Example

```python
@app.tool()
async def query_database(query: str, limit: int = 10) -> str:
    """Query the customer database with SQL."""
    # Validate query (prevent SQL injection)
    if not is_safe_query(query):
        raise ValueError("Unsafe query detected")
    
    # Execute query with limits
    result = await db.execute(query, limit=min(limit, 100))
    return json.dumps(result, indent=2)
```

### 2. Resources

Resources are **application-driven** data sources that provide context to language models.

#### Resource Types

- **Text Resources**: Documentation, configuration files, code
- **Binary Resources**: Images, audio, video files  
- **Dynamic Resources**: Database content, API responses
- **File Resources**: Local filesystem access

#### Resource Metadata

```json
{
  "uri": "file:///path/to/document.md",
  "name": "Project Documentation",
  "description": "Main project documentation file",
  "mimeType": "text/markdown",
  "annotations": {
    "audience": ["user", "assistant"],
    "priority": 0.8,
    "lastModified": "2024-01-15T10:30:00Z"
  }
}
```

#### Python Resource Example

```python
@app.resource("config://database")
async def get_database_config():
    """Return database configuration."""
    config = await load_database_config()
    return TextContent(
        type="text", 
        text=json.dumps(config, indent=2),
        mimeType="application/json"
    )

@app.list_resources()
async def list_available_resources():
    """List all available resources."""
    return [
        {
            "uri": "config://database",
            "name": "Database Configuration",
            "mimeType": "application/json"
        }
    ]
```

### 3. Prompts  

Prompts are **user-controlled** templates for interacting with language models.

#### Prompt Structure

```json
{
  "name": "code_review",
  "description": "Review code for best practices",
  "arguments": [
    {
      "name": "code",
      "description": "Code to review",
      "required": true
    },
    {
      "name": "language", 
      "description": "Programming language",
      "required": false
    }
  ]
}
```

#### Python Prompt Example

```python
@app.prompt()
async def code_review(code: str, language: str = "python"):
    """Generate a code review prompt."""
    return [
        UserMessage(
            content=TextContent(
                type="text",
                text=f"""Please review this {language} code for:
1. Best practices
2. Potential bugs
3. Security issues
4. Performance improvements

Code:
```{language}
{code}
```

Provide specific, actionable feedback."""
            )
        )
    ]
```

### 4. Sampling (Advanced)

Sampling allows servers to request language model generations through clients.

#### Sample Request

```json
{
  "method": "sampling/createMessage",
  "params": {
    "messages": [
      {
        "role": "user",
        "content": {
          "type": "text", 
          "text": "Analyze this data and provide insights"
        }
      }
    ],
    "modelPreferences": {
      "hints": [{"name": "claude-3-sonnet"}],
      "intelligencePriority": 0.8,
      "speedPriority": 0.5,
      "costPriority": 0.3
    },
    "systemPrompt": "You are a data analyst...",
    "maxTokens": 1000
  }
}
```

## Transport Mechanisms

### 1. Stdio Transport

**Most common for Claude Desktop integration**

- Server runs as subprocess
- Communication via stdin/stdout
- JSON-RPC messages delimited by newlines
- Logging must go to stderr (never stdout)

#### Configuration

```json
{
  "command": "python",
  "args": ["/path/to/server.py"],
  "env": {"DEBUG": "1"}
}
```

#### Implementation Note

```python
# CRITICAL: Never write to stdout except MCP messages
import sys
import logging

# Configure logging to stderr
logging.basicConfig(stream=sys.stderr, level=logging.INFO)

# All MCP messages go to stdout automatically via SDK
```

### 2. HTTP/SSE Transport

**For web-based integrations**

- HTTP POST for requests
- Server-Sent Events (SSE) for streaming
- Requires authentication and CORS handling
- Supports multiple simultaneous connections

#### Server Setup

```python
from mcp.server.fastapi import FastMCPServer
import uvicorn

app = FastMCPServer("my-server")

# Your tools/resources here

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
```

#### Client Configuration

```json
{
  "httpServers": {
    "my-server": {
      "url": "http://localhost:8000",
      "headers": {
        "Authorization": "Bearer your-token"
      }
    }
  }
}
```

### 3. Custom Transports

You can implement custom transports while maintaining JSON-RPC message format:

- WebSocket connections
- Named pipes
- TCP sockets
- Message queues

## Security Considerations

### Input Validation

**Always validate all inputs:**

```python
def validate_file_path(path: str) -> str:
    """Validate and normalize file paths."""
    # Prevent directory traversal
    if ".." in path or path.startswith("/"):
        raise ValueError("Invalid path")
    
    # Normalize path
    normalized = os.path.normpath(path)
    
    # Ensure within allowed directory
    if not normalized.startswith("allowed/"):
        raise ValueError("Path outside allowed directory")
    
    return normalized
```

### Access Controls

Implement proper authorization:

```python
async def check_permissions(user_id: str, resource: str) -> bool:
    """Check if user has access to resource."""
    permissions = await get_user_permissions(user_id)
    return resource in permissions.get("allowed_resources", [])
```

### Rate Limiting

Prevent abuse with rate limiting:

```python
from collections import defaultdict
import time

class RateLimiter:
    def __init__(self, max_requests=100, window=3600):
        self.max_requests = max_requests
        self.window = window
        self.requests = defaultdict(list)
    
    def allow_request(self, client_id: str) -> bool:
        now = time.time()
        window_start = now - self.window
        
        # Clean old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id] 
            if req_time > window_start
        ]
        
        # Check limit
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        
        self.requests[client_id].append(now)
        return True
```

### Sensitive Data Handling

```python
import hashlib
import json

def sanitize_output(data: dict) -> dict:
    """Remove sensitive information from output."""
    sensitive_keys = ["password", "token", "key", "secret"]
    
    for key in list(data.keys()):
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            # Replace with hash for audit trail
            data[key] = f"<redacted:{hashlib.sha256(str(data[key]).encode()).hexdigest()[:8]}>"
    
    return data
```

## Development Examples

### Complete Weather Server (Python)

```python
#!/usr/bin/env python3
import asyncio
import httpx
import os
from mcp.server import Server
from mcp.types import TextContent, Tool
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Server("weather-server")

@app.tool()
async def get_weather(city: str) -> str:
    """Get current weather for a city using OpenWeatherMap API."""
    api_key = os.getenv("OPENWEATHER_API_KEY")
    if not api_key:
        raise ValueError("OpenWeatherMap API key not configured")
    
    # Validate input
    if not city or len(city.strip()) == 0:
        raise ValueError("City name cannot be empty")
    
    city = city.strip()
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.openweathermap.org/data/2.5/weather",
                params={
                    "q": city,
                    "appid": api_key,
                    "units": "metric"
                },
                timeout=10.0
            )
            response.raise_for_status()
            
            data = response.json()
            
            weather_info = {
                "city": data["name"],
                "country": data["sys"]["country"],
                "temperature": data["main"]["temp"],
                "description": data["weather"][0]["description"],
                "humidity": data["main"]["humidity"],
                "wind_speed": data.get("wind", {}).get("speed", 0)
            }
            
            return f"""Weather in {weather_info['city']}, {weather_info['country']}:
Temperature: {weather_info['temperature']}°C
Conditions: {weather_info['description']}
Humidity: {weather_info['humidity']}%
Wind Speed: {weather_info['wind_speed']} m/s"""
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise ValueError(f"City '{city}' not found")
        else:
            raise ValueError(f"Weather service error: {e.response.status_code}")
    except httpx.TimeoutException:
        raise ValueError("Weather service request timed out")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise ValueError("Failed to fetch weather data")

@app.tool()
async def get_forecast(city: str, days: int = 5) -> str:
    """Get weather forecast for a city."""
    if days < 1 or days > 5:
        raise ValueError("Days must be between 1 and 5")
    
    api_key = os.getenv("OPENWEATHER_API_KEY")
    if not api_key:
        raise ValueError("OpenWeatherMap API key not configured")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.openweathermap.org/data/2.5/forecast",
                params={
                    "q": city.strip(),
                    "appid": api_key,
                    "units": "metric",
                    "cnt": days * 8  # 8 forecasts per day (3-hour intervals)
                },
                timeout=10.0
            )
            response.raise_for_status()
            
            data = response.json()
            
            forecast_text = f"Weather forecast for {data['city']['name']}, {data['city']['country']}:\n\n"
            
            current_date = None
            for item in data["list"][:days * 8:8]:  # One per day
                date = item["dt_txt"].split()[0]
                if date != current_date:
                    current_date = date
                    forecast_text += f"{date}: {item['main']['temp']}°C, {item['weather'][0]['description']}\n"
            
            return forecast_text
            
    except Exception as e:
        logger.error(f"Forecast error: {e}")
        raise ValueError("Failed to fetch forecast data")

if __name__ == "__main__":
    asyncio.run(app.run())
```

### File System Server (TypeScript)

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { promises as fs } from "fs";
import path from "path";

const server = new Server(
  {
    name: "filesystem-server",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
      resources: { subscribe: true, listChanged: true },
    },
  }
);

// Allowed directory (security measure)
const ALLOWED_DIR = process.env.ALLOWED_DIR || "./sandbox";

function validatePath(filePath: string): string {
  const resolved = path.resolve(ALLOWED_DIR, filePath);
  const allowedResolved = path.resolve(ALLOWED_DIR);
  
  if (!resolved.startsWith(allowedResolved)) {
    throw new Error("Path outside allowed directory");
  }
  
  return resolved;
}

// List available tools
server.setRequestHandler("tools/list", async () => ({
  tools: [
    {
      name: "read_file",
      description: "Read contents of a file",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Path to the file to read"
          }
        },
        required: ["path"]
      }
    },
    {
      name: "write_file", 
      description: "Write content to a file",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Path to the file to write"
          },
          content: {
            type: "string",
            description: "Content to write to the file"
          }
        },
        required: ["path", "content"]
      }
    },
    {
      name: "list_directory",
      description: "List contents of a directory",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Path to the directory",
            default: "."
          }
        }
      }
    }
  ]
}));

// Handle tool calls
server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;
  
  try {
    switch (name) {
      case "read_file": {
        const filePath = validatePath(args.path);
        const content = await fs.readFile(filePath, "utf-8");
        return {
          content: [
            {
              type: "text",
              text: content
            }
          ]
        };
      }
      
      case "write_file": {
        const filePath = validatePath(args.path);
        await fs.writeFile(filePath, args.content, "utf-8");
        return {
          content: [
            {
              type: "text",
              text: `Successfully wrote to ${args.path}`
            }
          ]
        };
      }
      
      case "list_directory": {
        const dirPath = validatePath(args.path || ".");
        const entries = await fs.readdir(dirPath, { withFileTypes: true });
        
        const listing = entries.map(entry => ({
          name: entry.name,
          type: entry.isDirectory() ? "directory" : "file",
          size: entry.isFile() ? (fs.stat(path.join(dirPath, entry.name))).then(s => s.size) : null
        }));
        
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(listing, null, 2)
            }
          ]
        };
      }
      
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${error.message}`
        }
      ],
      isError: true
    };
  }
});

// Handle resources
server.setRequestHandler("resources/list", async () => ({
  resources: [
    {
      uri: "file://config",
      name: "Server Configuration",
      mimeType: "application/json"
    }
  ]
}));

server.setRequestHandler("resources/read", async (request) => {
  const { uri } = request.params;
  
  if (uri === "file://config") {
    return {
      contents: [
        {
          type: "text",
          text: JSON.stringify({
            allowedDirectory: ALLOWED_DIR,
            serverVersion: "0.1.0",
            capabilities: ["read", "write", "list"]
          }, null, 2),
          mimeType: "application/json"
        }
      ]
    };
  }
  
  throw new Error(`Unknown resource: ${uri}`);
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("MCP Filesystem Server running on stdio");
}

main().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});
```

## Testing and Debugging

### 1. MCP Inspector

The official MCP Inspector provides a visual testing interface:

```bash
# Install globally
npm install -g @modelcontextprotocol/inspector

# Test your server
mcp-inspector python /path/to/your-server.py

# Or for Node.js servers  
mcp-inspector node /path/to/your-server.js
```

### 2. Unit Testing

#### Python Testing Example

```python
import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from your_server import app

@pytest.mark.asyncio
async def test_weather_tool():
    """Test the weather tool."""
    
    # Mock the HTTP response
    mock_response = {
        "name": "London",
        "sys": {"country": "GB"},
        "main": {"temp": 15, "humidity": 80},
        "weather": [{"description": "cloudy"}]
    }
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_response_obj = AsyncMock()
        mock_response_obj.json.return_value = mock_response
        mock_response_obj.raise_for_status.return_value = None
        mock_get.return_value.__aenter__.return_value.get.return_value = mock_response_obj
        
        result = await app.call_tool("get_weather", {"city": "London"})
        
        assert "London" in result
        assert "15°C" in result
        assert "cloudy" in result

@pytest.mark.asyncio  
async def test_invalid_city():
    """Test error handling for invalid city."""
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_response_obj = AsyncMock()
        mock_response_obj.raise_for_status.side_effect = httpx.HTTPStatusError("Not found", request=None, response=AsyncMock(status_code=404))
        mock_get.return_value.__aenter__.return_value.get.return_value = mock_response_obj
        
        with pytest.raises(ValueError, match="not found"):
            await app.call_tool("get_weather", {"city": "InvalidCity"})
```

### 3. Integration Testing

#### Test Server Connection

```python
import subprocess
import json
import sys

def test_server_stdio():
    """Test server communication over stdio."""
    
    # Start server process
    process = subprocess.Popen(
        [sys.executable, "/path/to/server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Send handshake
    handshake = {
        "jsonrpc": "2.0",
        "method": "mcp/handshake", 
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    }
    
    process.stdin.write(json.dumps(handshake) + "\n")
    process.stdin.flush()
    
    # Read response
    response_line = process.readline()
    response = json.loads(response_line)
    
    # Verify handshake
    assert "protocolVersion" in response.get("result", {})
    
    # Clean up
    process.terminate()
```

### 4. Debugging Tips

#### Enable Debug Logging

```python
import logging
import sys

# Configure detailed logging
logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Log all MCP messages
logger = logging.getLogger(__name__)

@app.tool()
async def debug_tool(data: str) -> str:
    logger.debug(f"Tool called with data: {data}")
    result = process_data(data)
    logger.debug(f"Tool returning: {result}")
    return result
```

#### Message Tracing

```python
import json
from datetime import datetime

class MCPDebugger:
    def __init__(self, log_file="mcp_debug.log"):
        self.log_file = log_file
    
    def log_message(self, direction: str, message: dict):
        """Log MCP messages for debugging."""
        with open(self.log_file, "a") as f:
            f.write(f"{datetime.now().isoformat()} {direction}: {json.dumps(message)}\n")
    
    def log_request(self, message: dict):
        self.log_message("REQ", message)
    
    def log_response(self, message: dict):
        self.log_message("RES", message)

# Usage
debugger = MCPDebugger()

# In your request handlers
@app.tool()
async def my_tool(param: str) -> str:
    debugger.log_request({"tool": "my_tool", "param": param})
    result = do_work(param)
    debugger.log_response({"result": result})
    return result
```

## Deployment and Distribution

### 1. Python Server Packaging

#### Using setuptools

```python
# setup.py
from setuptools import setup, find_packages

setup(
    name="my-mcp-server",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "mcp>=1.2.0",
        "httpx>=0.24.0",
        "pydantic>=2.0.0"
    ],
    entry_points={
        "console_scripts": [
            "my-mcp-server=my_server:main",
        ],
    },
    python_requires=">=3.10",
)
```

#### Using Poetry

```toml
# pyproject.toml
[tool.poetry]
name = "my-mcp-server"
version = "1.0.0"
description = "My MCP Server"

[tool.poetry.dependencies]
python = "^3.10"
mcp = "^1.2.0"
httpx = "^0.24.0"

[tool.poetry.scripts]
my-mcp-server = "my_server:main"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
```

### 2. TypeScript Server Distribution

#### Package.json

```json
{
  "name": "my-mcp-server",
  "version": "1.0.0",
  "type": "module",
  "main": "dist/server.js",
  "bin": {
    "my-mcp-server": "./dist/server.js"
  },
  "scripts": {
    "build": "tsc",
    "start": "node dist/server.js",
    "dev": "tsx src/server.ts"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^0.5.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "tsx": "^4.0.0"
  }
}
```

#### Docker Deployment

```dockerfile
# Dockerfile for Python server
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "server.py"]
```

```dockerfile
# Dockerfile for TypeScript server
FROM node:18-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY dist/ ./dist/

EXPOSE 8000

CMD ["node", "dist/server.js"]
```

### 3. Installation Scripts

#### Python Installation

```bash
#!/bin/bash
# install.sh

set -e

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .

# Create configuration directory
mkdir -p ~/.config/mcp/

# Copy default configuration
cp config/policy.yaml ~/.config/mcp/

echo "MCP server installed successfully!"
echo "Add to Claude Desktop config:"
echo '{
  "mcpServers": {
    "my-server": {
      "command": "'$(pwd)'/venv/bin/my-mcp-server",
      "args": ["--config", "~/.config/mcp/policy.yaml"]
    }
  }
}'
```

#### NPM Installation

```json
{
  "name": "my-mcp-server",
  "version": "1.0.0",
  "preferGlobal": true,
  "bin": {
    "my-mcp-server": "./dist/server.js"
  },
  "scripts": {
    "postinstall": "node scripts/post-install.js"
  }
}
```

```javascript
// scripts/post-install.js
import fs from 'fs';
import path from 'path';
import os from 'os';

const configDir = path.join(os.homedir(), '.config', 'mcp');
const configFile = path.join(configDir, 'my-server-config.json');

// Create config directory
if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
}

// Create default config
if (!fs.existsSync(configFile)) {
    const defaultConfig = {
        name: "my-mcp-server",
        version: "1.0.0",
        settings: {}
    };
    
    fs.writeFileSync(configFile, JSON.stringify(defaultConfig, null, 2));
    console.log(`Configuration created at: ${configFile}`);
}

console.log(`
Installation complete!

Add to your Claude Desktop config:
{
  "mcpServers": {
    "my-server": {
      "command": "my-mcp-server",
      "args": ["--config", "${configFile}"]
    }
  }
}
`);
```

## Best Practices

### 1. Error Handling

Always provide clear, actionable error messages:

```python
class MCPError(Exception):
    """Base exception for MCP server errors."""
    def __init__(self, message: str, code: str = "UNKNOWN_ERROR", details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

@app.tool()
async def safe_tool(param: str) -> str:
    try:
        if not param:
            raise MCPError("Parameter required", "MISSING_PARAMETER")
        
        result = await do_work(param)
        return result
        
    except ValidationError as e:
        raise MCPError(f"Invalid input: {e}", "VALIDATION_ERROR", {"field": e.field})
    except PermissionError as e:
        raise MCPError("Access denied", "PERMISSION_DENIED")
    except Exception as e:
        logger.exception("Unexpected error in safe_tool")
        raise MCPError("Internal server error", "INTERNAL_ERROR")
```

### 2. Performance Optimization

#### Caching

```python
from functools import lru_cache
import asyncio
from typing import Optional
import time

class AsyncLRUCache:
    def __init__(self, maxsize: int = 128, ttl: int = 300):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache = {}
        self.timestamps = {}
    
    def get(self, key: str) -> Optional[any]:
        if key not in self.cache:
            return None
        
        # Check TTL
        if time.time() - self.timestamps[key] > self.ttl:
            del self.cache[key]
            del self.timestamps[key]
            return None
        
        return self.cache[key]
    
    def set(self, key: str, value: any):
        # Remove oldest if at capacity
        if len(self.cache) >= self.maxsize:
            oldest_key = min(self.timestamps.keys(), key=lambda k: self.timestamps[k])
            del self.cache[oldest_key]
            del self.timestamps[oldest_key]
        
        self.cache[key] = value
        self.timestamps[key] = time.time()

# Usage
cache = AsyncLRUCache(maxsize=100, ttl=300)

@app.tool()
async def cached_expensive_operation(query: str) -> str:
    # Check cache first
    cached_result = cache.get(query)
    if cached_result:
        return cached_result
    
    # Expensive operation
    result = await expensive_api_call(query)
    
    # Cache result
    cache.set(query, result)
    return result
```

#### Connection Pooling

```python
import httpx
from contextlib import asynccontextmanager

class HTTPClientManager:
    def __init__(self):
        self.client = None
    
    async def __aenter__(self):
        if self.client is None:
            self.client = httpx.AsyncClient(
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
                timeout=httpx.Timeout(30.0)
            )
        return self.client
    
    async def __aclose__(self):
        if self.client:
            await self.client.aclose()
            self.client = None

# Global client manager
http_manager = HTTPClientManager()

@app.tool()
async def api_call(endpoint: str) -> str:
    async with http_manager as client:
        response = await client.get(endpoint)
        return response.text
```

### 3. Configuration Management

```python
from pydantic import BaseSettings, Field
from typing import List, Optional
import yaml

class ServerConfig(BaseSettings):
    """Server configuration with validation."""
    
    # Server settings
    name: str = Field(default="my-mcp-server", description="Server name")
    version: str = Field(default="1.0.0", description="Server version")
    debug: bool = Field(default=False, description="Enable debug mode")
    
    # API settings  
    api_timeout: float = Field(default=30.0, description="API timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum API retries")
    
    # Security settings
    allowed_origins: List[str] = Field(default=["localhost"], description="Allowed origins")
    api_key: Optional[str] = Field(default=None, description="API key for external services")
    
    # Resource limits
    max_file_size: int = Field(default=10*1024*1024, description="Max file size in bytes")
    max_results: int = Field(default=1000, description="Maximum results per query")
    
    class Config:
        env_prefix = "MCP_"
        case_sensitive = False

def load_config(config_path: str = "config.yaml") -> ServerConfig:
    """Load configuration from YAML file and environment."""
    config_dict = {}
    
    # Load from YAML file
    try:
        with open(config_path, 'r') as f:
            config_dict = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Config file {config_path} not found, using defaults")
    
    # Override with environment variables
    return ServerConfig(**config_dict)

# Usage
config = load_config()

@app.tool()
async def configured_tool(data: str) -> str:
    if len(data) > config.max_file_size:
        raise ValueError(f"Data too large, max size: {config.max_file_size}")
    
    # Use configuration
    async with httpx.AsyncClient(timeout=config.api_timeout) as client:
        # Implementation
        pass
```

### 4. Logging and Monitoring

```python
import logging
import structlog
import sys
from datetime import datetime

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

class RequestLogger:
    """Log all MCP requests and responses."""
    
    def __init__(self):
        self.request_count = 0
    
    def log_request(self, method: str, params: dict, request_id: str = None):
        self.request_count += 1
        logger.info(
            "mcp_request",
            method=method,
            params=params,
            request_id=request_id,
            request_number=self.request_count
        )
    
    def log_response(self, method: str, result: dict, error: str = None, request_id: str = None):
        logger.info(
            "mcp_response",
            method=method,
            result=result,
            error=error,
            request_id=request_id
        )
    
    def log_error(self, method: str, error: str, request_id: str = None):
        logger.error(
            "mcp_error",
            method=method,
            error=error,
            request_id=request_id
        )

# Usage
request_logger = RequestLogger()

@app.tool()
async def monitored_tool(data: str) -> str:
    request_id = f"req_{int(datetime.now().timestamp())}"
    
    try:
        request_logger.log_request("monitored_tool", {"data_length": len(data)}, request_id)
        
        result = await process_data(data)
        
        request_logger.log_response("monitored_tool", {"result_length": len(result)}, request_id=request_id)
        
        return result
        
    except Exception as e:
        request_logger.log_error("monitored_tool", str(e), request_id)
        raise
```

## Resources and References

### Official Documentation

- **Main Website**: https://modelcontextprotocol.io
- **Protocol Specification**: https://modelcontextprotocol.io/specification  
- **Anthropic Documentation**: https://docs.anthropic.com/en/docs/mcp
- **Quickstart Guide**: https://modelcontextprotocol.io/quickstart

### SDKs and Tools

- **Python SDK**: https://github.com/modelcontextprotocol/python-sdk
- **TypeScript SDK**: https://github.com/modelcontextprotocol/typescript-sdk
- **Inspector Tool**: https://github.com/modelcontextprotocol/inspector
- **Example Servers**: https://github.com/modelcontextprotocol/servers

### Community Resources

- **Awesome MCP Servers**: https://github.com/wong2/awesome-mcp-servers
- **MCP Server Guide**: https://github.com/kaianuar/mcp-server-guide
- **Microsoft MCP Curriculum**: https://github.com/microsoft/mcp-for-beginners

### Learning Resources

- **DeepLearning.AI Course**: [MCP: Build Rich-Context AI Apps with Anthropic](https://www.deeplearning.ai/short-courses/mcp-build-rich-context-ai-apps-with-anthropic/)
- **Anthropic Skilljar**: [Introduction to Model Context Protocol](https://anthropic.skilljar.com/introduction-to-model-context-protocol)

### Protocol Specifications

- **Current Version**: `2025-06-18`
- **JSON-RPC 2.0**: Used as the base protocol
- **Transport Mechanisms**: stdio, HTTP/SSE, custom transports
- **Message Format**: Newline-delimited JSON (NDJSON)

### Key Concepts Summary

1. **MCP Servers** expose tools, resources, and prompts
2. **MCP Clients** (built into host applications) communicate with servers
3. **Transport** handles communication (stdio most common for Claude Desktop)
4. **Security** through input validation, access controls, and rate limiting
5. **Capabilities** declared during handshake determine available features

This guide provides a comprehensive foundation for building MCP servers that integrate effectively with Claude Desktop and other MCP-compatible applications. The protocol's standardized approach enables rich AI integrations while maintaining security and flexibility.