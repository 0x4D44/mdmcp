# Anthropic API Documentation

## Messages API

### Endpoint
```
POST https://api.anthropic.com/v1/messages
```

### Authentication
```
x-api-key: $ANTHROPIC_API_KEY
anthropic-version: 2023-06-01
```

### Request Body

#### Required Parameters
- `model` (string): Model version (e.g., "claude-3-opus-20240229", "claude-3-sonnet-20240229")
- `messages` (array): Array of message objects
- `max_tokens` (integer): Maximum tokens to generate (required, unlike OpenAI)

#### Optional Parameters
- `system` (string): System prompt (not part of messages array)
- `temperature` (number, 0-1): Sampling temperature
- `top_p` (number): Nucleus sampling
- `top_k` (integer): Top-k sampling
- `stop_sequences` (array): Custom stop sequences
- `stream` (boolean): Enable streaming responses
- `metadata` (object): Attach metadata to request
- `thinking_budget` (integer): Tokens for internal reasoning (≥1024)

### Tool Use Parameters
- `tools` (array): Tool definitions
- `tool_choice` (object): Control tool usage
  - `type`: "auto" | "any" | "tool"
  - `name`: Specific tool name when type="tool"
- `disable_parallel_tool_use` (boolean): Prevent parallel tool calls

### Message Format
```json
{
  "role": "user" | "assistant",
  "content": "string or array of content blocks"
}
```

Content blocks can be:
- Text: `{"type": "text", "text": "..."}`
- Image: `{"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": "..."}}`
- Tool use: `{"type": "tool_use", "id": "...", "name": "...", "input": {}}`
- Tool result: `{"type": "tool_result", "tool_use_id": "...", "content": "..."}`

### URL-based Content (New 2024)
```json
{
  "type": "image",
  "source": {
    "type": "url",
    "url": "https://example.com/image.jpg"
  }
}
```

### Response Format
```json
{
  "id": "msg_xxx",
  "type": "message",
  "role": "assistant",
  "content": [{
    "type": "text",
    "text": "Response text"
  }],
  "model": "claude-3-opus-20240229",
  "stop_reason": "end_turn" | "max_tokens" | "stop_sequence" | "tool_use",
  "stop_sequence": null,
  "usage": {
    "input_tokens": 100,
    "output_tokens": 50,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0
  }
}
```

### Streaming Format
When `stream: true`, responses use Server-Sent Events:
```
event: message_start
data: {"type": "message_start", "message": {...}}

event: content_block_start
data: {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}

event: content_block_delta
data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}}

event: content_block_stop
data: {"type": "content_block_stop", "index": 0}

event: message_delta
data: {"type": "message_delta", "delta": {"stop_reason": "end_turn"}}

event: message_stop
data: {"type": "message_stop"}
```

## Models

### Claude 3 Family
- `claude-3-opus-20240229` - Most capable, slower
- `claude-3-sonnet-20240229` - Balanced performance
- `claude-3-haiku-20240307` - Fastest, most compact

### Claude 3.5
- `claude-3-5-sonnet-20241022` - Latest Sonnet version
- `claude-3-5-sonnet-20240620` - Previous Sonnet version

### Legacy Models
- `claude-2.1` - Previous generation
- `claude-2.0` - Older version
- `claude-instant-1.2` - Fast, older model

## Context Windows
- Claude 3 models: 200,000 tokens
- Claude 2.1: 200,000 tokens
- Claude 2.0: 100,000 tokens
- Claude Instant: 100,000 tokens

## Vision Capabilities
Claude 3 models support image inputs:
- Maximum image size: 5MB
- Supported formats: JPEG, PNG, GIF, WebP
- Multiple images per message supported
- Images can be base64 encoded or provided via URL (2024 feature)

## Tool Use

### Tool Definition
```json
{
  "name": "get_weather",
  "description": "Get current weather",
  "input_schema": {
    "type": "object",
    "properties": {
      "location": {
        "type": "string",
        "description": "City and state"
      }
    },
    "required": ["location"]
  }
}
```

### Tool Response
```json
{
  "type": "tool_use",
  "id": "toolu_xxx",
  "name": "get_weather",
  "input": {
    "location": "San Francisco, CA"
  }
}
```

## Prompt Caching (Beta)
- Cache prompts for reuse across requests
- Reduces latency and costs for repeated contexts
- Use `cache_control` blocks in messages

## Message Batches
Process multiple requests asynchronously:
```
POST https://api.anthropic.com/v1/messages/batches
```

## Rate Limits
- Vary by model and account tier
- Headers: `anthropic-ratelimit-requests-remaining`, `anthropic-ratelimit-tokens-remaining`
- Implement exponential backoff for 429 errors

## Error Response Format
```json
{
  "type": "error",
  "error": {
    "type": "invalid_request_error",
    "message": "Description of error"
  }
}
```

## Error Types
- `invalid_request_error` - Invalid parameters
- `authentication_error` - API key issues
- `permission_error` - Insufficient permissions
- `not_found_error` - Resource not found
- `rate_limit_error` - Too many requests
- `api_error` - Server-side error
- `overloaded_error` - Temporary overload

## Best Practices
1. Always include `max_tokens` parameter
2. Use system prompts for consistent behavior
3. Structure prompts with XML tags for clarity
4. Keep image sizes reasonable for performance
5. Use prompt caching for repeated contexts
6. Implement streaming for better UX
7. Monitor token usage closely
8. Use appropriate model for task complexity

## OpenAI Compatibility Mode (2024)
Anthropic now offers an OpenAI-compatible endpoint:
- Change base URL to Anthropic's
- Use Anthropic API key
- Adjust model names
- Most OpenAI SDK code works unchanged