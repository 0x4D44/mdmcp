#!/usr/bin/env python3
"""
Test script to verify the new MCP methods work correctly.
Tests prompts/list, prompts/get, resources/list, and resources/read.
"""

import json
import subprocess
import sys
import time
import threading
from queue import Queue, Empty

def run_server_with_input(config_path, inputs):
    """Run the server with a series of JSON-RPC inputs and collect responses."""
    cmd = ["cargo", "run", "-p", "mdmcpsrvr", "--", "--config", config_path, "--stdio"]
    
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd="C:\\language\\mdmcp"
    )
    
    responses = []
    stderr_output = []
    
    def read_stdout():
        for line in process.stdout:
            if line.strip():
                try:
                    response = json.loads(line.strip())
                    responses.append(response)
                except json.JSONDecodeError:
                    print(f"Non-JSON stdout: {line.strip()}")
    
    def read_stderr():
        for line in process.stderr:
            stderr_output.append(line.strip())
            print(f"STDERR: {line.strip()}")
    
    # Start reader threads
    stdout_thread = threading.Thread(target=read_stdout)
    stderr_thread = threading.Thread(target=read_stderr)
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()
    
    # Send inputs
    for input_data in inputs:
        json_line = json.dumps(input_data) + "\\n"
        print(f"Sending: {json_line.strip()}")
        process.stdin.write(json_line)
        process.stdin.flush()
        time.sleep(0.5)  # Wait a bit between requests
    
    # Wait a bit for responses
    time.sleep(2)
    
    # Close stdin to signal completion
    process.stdin.close()
    
    # Wait for process to finish
    process.wait()
    
    return responses, stderr_output

def test_mcp_methods():
    """Test the new MCP methods."""
    print("Testing new MCP methods...")
    
    # Test inputs
    test_inputs = [
        # Initialize
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"}
            }
        },
        # Send initialized notification
        {
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        },
        # Test prompts/list
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "prompts/list",
            "params": {}
        },
        # Test prompts/get
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "prompts/get",
            "params": {
                "name": "file_operation",
                "arguments": {"operation": "read", "path": "/test/file.txt"}
            }
        },
        # Test resources/list
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/list",
            "params": {}
        },
        # Test resources/read
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": {
                "uri": "mdmcp://server/config"
            }
        }
    ]
    
    responses, stderr_logs = run_server_with_input("tests/test_policy.yaml", test_inputs)
    
    print(f"\\nReceived {len(responses)} responses:")
    for i, response in enumerate(responses, 1):
        print(f"\\nResponse {i}:")
        print(json.dumps(response, indent=2))
    
    # Verify we got responses for our methods
    expected_methods = ["initialize", "prompts/list", "prompts/get", "resources/list", "resources/read"]
    
    print(f"\\n=== Test Results ===")
    print(f"Expected responses for: {expected_methods}")
    print(f"Got {len(responses)} total responses")
    
    success_count = 0
    for response in responses:
        if "result" in response:
            success_count += 1
            print(f"✓ ID {response.get('id')}: SUCCESS")
        elif "error" in response:
            print(f"✗ ID {response.get('id')}: ERROR - {response['error']['message']}")
    
    print(f"\\nSummary: {success_count}/{len(responses)} successful responses")
    
    return len(responses) >= 5 and success_count >= 4  # Allow for initialize + 4 new methods

if __name__ == "__main__":
    success = test_mcp_methods()
    sys.exit(0 if success else 1)