# OAuth2 Token Orchestrator Policy — Design Spec

**Date:** 2026-05-13
**Project:** `gravitee-policy-token-exchange`
**Copyright:** Fluent Health (https://fluentinhealth.com)

---

## Purpose

A Gravitee APIM policy plugin that encapsulates the "Cache-Check -> Token Request -> Cache Store -> Header Injection" lifecycle. It is designed to replace fragmented multi-policy flows (Data Cache + HTTP Callout + Transform Headers) currently used for various OAuth2 token exchange and refresh flows.

By consolidating these steps into a single Java execution unit, we improve performance (reduced EL evaluation overhead), simplify API definitions, and ensure consistent error handling and trace context propagation.


---

## Architecture

### Execution Pipeline

```
Gravitee Gateway (Request Phase)
  └─ OAuth2TokenOrchestratorPolicy
       ├─ 1. Resolve Cache Key (EL)
       ├─ 2. Lookup in Cache Resource (e.g., Redis)
       │    ├─ HIT: Skip to step 5
       │    └─ MISS ↓
       ├─ 3. Construct OAuth2 Request (application/x-www-form-urlencoded)
       │    └─ Execute HTTP Callout (Vert.x HttpClient)
       ├─ 4. Parse Response & Store in Cache
       │    └─ Use 'expires_in' for TTL
       └─ 5. Inject Authorization Header (Bearer <token>)
```

### Key Components

*   **Policy Engine:** Executes the workflow asynchronously using Vert.x non-blocking patterns.
*   **Cache Wrapper:** Interfaces with Gravitee's `CacheResource` to ensure multi-node consistency.
*   **Token Client:** A specialized HTTP client that handles form-encoding and JSON response parsing.

---

## Configuration Schema (`gravitee.json`)

The policy is highly configurable via Expression Language (EL) to support diverse OAuth2 providers.

### Core Fields

| Property | Type | Default | Description |
|---|---|---|---|
| `cacheResource` | string | (Required) | Name of the Gravitee Cache Resource to use. |
| `tokenEndpoint` | string | (Required) | The full URL to the OAuth2 provider token endpoint. *Supports EL.* |
| `grantType` | string | (Required) | The OAuth2 `grant_type` (e.g., `urn:ietf:params:oauth:grant-type:token-exchange`). *Supports EL.* |
| `clientId` | string | - | The OAuth2 client identifier. *Supports EL.* |
| `clientSecret` | string | - | The OAuth2 client secret. *Supports EL.* |

### Input & Caching

| Property | Type | Default | Description |
|---|---|---|---|
| `cacheKey` | string | `{#context.attributes['jwt.claims']['sub']}` | Expression used to generate the unique key for the cached token. |
| `defaultTtl` | integer | `3600` | Fallback TTL in seconds if the provider does not return `expires_in`. |

### Dynamic Parameters

| Property | Type | Description |
|---|---|---|
| `parameters` | Map<String, String> | Additional body parameters (e.g., `subject_token`, `refresh_token`, `scope`). Values support EL. |

---

## Error Handling

*   **Provider Errors:** If the token provider returns a non-2xx status or a JSON body containing an `error` field, the policy will:
    *   If `exitOnError` is true: Interrupt the flow.
    *   Return the configured `errorStatusCode` (default 401).
    *   Evaluate and return `errorContent`. This allows including context, e.g., `{"error": "Exchange failed for sub {#context.attributes['jwt.claims']['sub']}"}`.
    *   Log the actual provider error message internally for auditing.
*   **Cache Failures:** If the Cache Resource is unavailable, the policy will proceed with the token exchange but log a warning.

---

## Testing Strategy

### 1. Unit Tests (JUnit 5 + Mockito)
*   Validate `cacheKey` resolution logic.
*   Verify body construction for RFC 8693 and standard refresh token scenarios.
*   Assert `Authorization` header injection.

### 2. Integration Tests (WireMock)
*   Simulate token providers with various response payloads.
*   Test handling of expired tokens and invalid credentials.

### 3. Container Tests (TestContainers + Redis)
*   Verify real-world interactions with a Redis-backed Cache Resource.
*   Ensure TTLs are respected across multiple "requests."

---

## Trace Context Integration

The policy will automatically propagate W3C `traceparent` and `X-Request-ID` headers to the token provider if they are present on the inbound request, ensuring the token exchange call is correlated in Cloud Trace/Sentry.
ross multiple "requests."

---

## Trace Context Integration

The policy will automatically propagate W3C `traceparent` and `X-Request-ID` headers to the token provider if they are present on the inbound request, ensuring the token exchange call is correlated in Cloud Trace/Sentry.
