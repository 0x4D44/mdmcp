# OpenAI API Documentation

## Chat Completions API

### Endpoint
```
POST https://api.openai.com/v1/chat/completions
```

### Authentication
```
Authorization: Bearer $OPENAI_API_KEY
```

### Request Body

#### Required Parameters
- `model` (string): ID of the model to use (e.g., "gpt-4", "gpt-4-turbo", "gpt-3.5-turbo")
- `messages` (array): List of messages comprising the conversation

#### Optional Parameters
- `temperature` (number, 0-2): Sampling temperature, higher = more random
- `max_tokens` (integer): Maximum tokens to generate
- `top_p` (number, 0-1): Nucleus sampling parameter
- `n` (integer): Number of completions to generate
- `stream` (boolean): Stream partial message deltas
- `stop` (string/array): Sequences where API will stop generating
- `presence_penalty` (number, -2 to 2): Penalize new tokens based on presence
- `frequency_penalty` (number, -2 to 2): Penalize tokens based on frequency
- `logit_bias` (map): Modify likelihood of specific tokens
- `user` (string): Unique identifier for end-user
- `seed` (integer): For deterministic sampling
- `response_format` (object): Format like `{"type": "json_object"}`
- `tools` (array): List of tools the model may call
- `tool_choice` (string/object): Controls tool use

### Message Format
```json
{
  "role": "system" | "user" | "assistant" | "tool",
  "content": "string or array of content parts",
  "name": "optional name",
  "tool_calls": "array of tool calls (assistant messages)",
  "tool_call_id": "string (tool messages)"
}
```

### Response Format
```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1234567890,
  "model": "gpt-4",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "response text"
    },
    "finish_reason": "stop" | "length" | "tool_calls" | "content_filter",
    "logprobs": null
  }],
  "usage": {
    "prompt_tokens": 100,
    "completion_tokens": 50,
    "total_tokens": 150
  }
}
```

### Streaming Response
When `stream: true`, responses come as Server-Sent Events:
```
data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"content":"token"}}]}
data: [DONE]
```

## Assistants API

### Key Concepts
- **Assistant**: A purpose-built AI with instructions and access to tools
- **Thread**: A conversation session between an assistant and user
- **Message**: Individual messages within a thread
- **Run**: An invocation of an assistant on a thread
- **Vector Store**: Storage for file embeddings used in file search

### Vector Stores

#### Create Vector Store
```
POST https://api.openai.com/v1/vector_stores
```
```json
{
  "name": "Product Documentation",
  "file_ids": ["file-abc123", "file-def456"],
  "expires_after": {
    "anchor": "last_active_at",
    "days": 7
  }
}
```

#### File Operations
```
POST https://api.openai.com/v1/files
Content-Type: multipart/form-data

purpose=assistants
file=@document.pdf
```

#### Attach to Assistant
```json
{
  "model": "gpt-4-turbo",
  "instructions": "You are a helpful assistant",
  "tools": [{"type": "file_search"}],
  "tool_resources": {
    "file_search": {
      "vector_store_ids": ["vs_xxx"]
    }
  }
}
```

### File Search Pricing
- $0.10/GB per day for vector store storage
- First 1GB free
- Files stored indefinitely until manually deleted

### Supported File Types
- Text: .txt, .md, .rtf
- Documents: .pdf, .docx, .pptx, .xlsx
- Code: .py, .js, .java, .c, .cpp, .html, .css
- Data: .json, .csv, .xml

## Models

### GPT-4 Series
- `gpt-4-turbo` - Latest GPT-4 Turbo (128k context)
- `gpt-4` - Standard GPT-4 (8k context)
- `gpt-4-32k` - Extended context GPT-4

### GPT-3.5 Series
- `gpt-3.5-turbo` - Most capable GPT-3.5 (16k context)
- `gpt-3.5-turbo-16k` - Extended context

### Embeddings
- `text-embedding-3-large` - Latest large embedding model
- `text-embedding-3-small` - Smaller, faster embedding model
- `text-embedding-ada-002` - Previous generation

## Rate Limits
- Vary by model and account tier
- Headers returned: `x-ratelimit-limit-requests`, `x-ratelimit-remaining-requests`
- Implement exponential backoff for 429 errors

## Error Codes
- `400` - Bad Request (invalid parameters)
- `401` - Invalid Authentication
- `403` - Forbidden
- `404` - Not Found
- `429` - Rate Limit Exceeded
- `500` - Internal Server Error
- `503` - Service Unavailable

## Best Practices
1. Use system messages for instructions
2. Keep conversations focused
3. Implement retry logic with exponential backoff
4. Monitor token usage to control costs
5. Use temperature=0 for deterministic outputs
6. Cache responses when appropriate
7. Use streaming for better UX in long responses