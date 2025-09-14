# OpenRouter API Documentation

## Overview
OpenRouter provides unified access to 200+ AI models through a single API endpoint, with automatic failover and cost optimization.

## Chat Completions API

### Endpoint
```
POST https://openrouter.ai/api/v1/chat/completions
```

### Authentication
```
Authorization: Bearer $OPENROUTER_API_KEY
HTTP-Referer: https://your-app.com (optional but recommended)
X-Title: Your App Name (optional)
```

### Request Body

#### Required Parameters
- `messages` (array): Conversation messages

#### Optional Parameters
- `model` (string): Model ID (if not specified, uses account default)
- `stream` (boolean): Enable streaming responses
- `max_tokens` (integer): Maximum tokens to generate
- `temperature` (number, 0-2): Sampling temperature
- `top_p` (number, 0-1): Nucleus sampling
- `top_k` (integer): Top-k sampling
- `frequency_penalty` (number, -2 to 2): Frequency penalty
- `presence_penalty` (number, -2 to 2): Presence penalty
- `repetition_penalty` (number, 0-2): Repetition penalty
- `seed` (integer): For deterministic outputs
- `response_format` (object): Structured output format
- `stop` (string/array): Stop sequences
- `tools` (array): Available tools for the model
- `tool_choice` (string/object): Tool selection strategy

### Provider Routing
Control how requests are routed to different providers:

```json
{
  "provider": {
    "order": ["openai", "anthropic", "together"],
    "require_parameters": true,
    "data_collection": "deny",
    "allow_fallbacks": true,
    "quantization": "fp16"
  }
}
```

#### Provider Options
- `order`: Preference order for providers
- `require_parameters`: Require specific parameter support
- `data_collection`: "allow" | "deny" 
- `allow_fallbacks`: Enable automatic failover
- `quantization`: Model quantization preference

### Transforms
Apply prompt transformations:

```json
{
  "transforms": ["middle-out"]
}
```

### Route Selection
Specify routing strategy:

```json
{
  "route": "fallback"
}
```

### Model Selection
Models can be specified in multiple ways:

1. **Specific model**: `"model": "openai/gpt-4"`
2. **Auto routing**: `"model": "auto"` (best model for prompt)
3. **Model class**: `"model": "@cf/meta/llama-2-7b"` (Cloudflare Workers AI)

### Response Format
OpenRouter normalizes responses to match OpenAI's format:

```json
{
  "id": "gen-xxx",
  "object": "chat.completion",
  "created": 1234567890,
  "model": "openai/gpt-4",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "Response text"
    },
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 100,
    "completion_tokens": 50,
    "total_tokens": 150
  },
  "x_groq": {
    "id": "provider-specific-id"
  }
}
```

### Streaming Response
Server-Sent Events format when `stream: true`:

```
data: {"id":"gen-xxx","choices":[{"delta":{"content":"token"}}]}
data: [DONE]
```

## Models API

### List Available Models
```
GET https://openrouter.ai/api/v1/models
```

Response includes:
- Model ID
- Pricing (per token)
- Context length
- Supported features
- Provider information

## Key Features

### Multi-Provider Support
Access models from:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude 3)
- Google (Gemini, PaLM)
- Meta (Llama)
- Mistral
- Cohere
- Together AI
- Replicate
- And 20+ more providers

### Automatic Fallbacks
If a provider fails, OpenRouter automatically routes to alternatives:
- Network errors trigger immediate fallback
- Rate limits route to other providers
- Model-specific errors handled gracefully

### Cost Optimization
- Automatically selects cheapest provider for equivalent models
- Shows cost breakdown in responses
- Usage tracking and limits

### Content Moderation
Built-in moderation with configurable levels:
- Filter inappropriate content
- Comply with provider policies
- Custom moderation rules

## Pricing

### Token Costs
- Pricing varies by model and provider
- Costs shown in USD per token
- Volume discounts available

### Credits System
- Prepaid credits for usage
- Automatic top-ups available
- Real-time balance tracking

## Rate Limits
- Generous default limits
- Increases with usage history
- Custom limits for enterprise

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": 429,
    "message": "Rate limit exceeded",
    "metadata": {
      "provider": "openai",
      "model": "gpt-4"
    }
  }
}
```

### Error Codes
- `400` - Invalid request
- `401` - Authentication failed
- `402` - Insufficient credits
- `403` - Forbidden
- `404` - Model not found
- `429` - Rate limited
- `500` - Internal error
- `502` - Provider error
- `503` - Service unavailable

## SDK Compatibility
OpenRouter is OpenAI-compatible, works with:
- OpenAI Python SDK
- OpenAI Node.js SDK
- LangChain
- LlamaIndex
- Any OpenAI-compatible library

Just change:
- Base URL to `https://openrouter.ai/api/v1`
- API key to OpenRouter key
- Model names to OpenRouter format

## Best Practices

1. **Set Referer Header**: Helps with rate limits and debugging
2. **Use Provider Preferences**: Control routing behavior
3. **Enable Fallbacks**: Improve reliability
4. **Monitor Usage**: Track costs and optimize model selection
5. **Cache Responses**: Reduce costs for repeated queries
6. **Use Appropriate Models**: Match model capability to task
7. **Implement Retries**: Handle transient failures
8. **Stream Long Responses**: Better UX for lengthy outputs

## Advanced Features

### Prompt Caching
Some providers support prompt caching:
- Reduces latency for repeated contexts
- Lower costs for cached tokens
- Automatic cache management

### Function Calling
Supported on compatible models:
- OpenAI function calling format
- Anthropic tool use
- Automatic format conversion

### Vision Models
Multimodal models available:
- GPT-4 Vision
- Claude 3 Vision
- Gemini Vision
- LLaVA models

### Fine-Tuned Models
Access to:
- Custom fine-tuned models
- Specialized domain models
- Community models

## Limits and Quotas

### Request Limits
- Body size: 100MB max
- Timeout: 10 minutes
- Concurrent requests: Based on tier

### Token Limits
- Input: Model-specific (up to 200k+)
- Output: Configurable per request
- Total: Account-based quotas