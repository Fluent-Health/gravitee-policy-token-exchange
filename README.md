# Gravitee Policy OAuth2 Token Orchestrator

A Gravitee APIM policy plugin that orchestrates the "Cache -> Token Request -> Cache Store -> Header Injection" lifecycle for RFC 8693 (Token Exchange) and standard OAuth2 refresh token flows.

By consolidating these steps into a single execution unit, it improves performance, simplifies API definitions, and ensures consistent error handling and trace context propagation.

A project by [Fluent Health](https://github.com/Fluent-Health).

## Key Features

- **Unified Flow**: Handles cache lookup, asynchronous token request, cache update, and header injection.
- **RFC 8693 Support**: Specialized for generic OAuth2 Token Exchange.
- **Refresh Token Support**: Configurable for standard OAuth2 refresh flows.
- **Asynchronous**: Built on Vert.x 4.x `HttpClient` for non-blocking gateway execution.
- **Trace Context**: Propagates W3C `traceparent` and `X-Request-ID` headers to the token provider.

## Compatibility

**Pick the plugin line that matches your APIM version — they are not interchangeable.**

| Plugin | Requires APIM | Vert.x runtime |
| --- | --- | --- |
| **2.x** | **>= 4.12** | 5.0.x |
| 1.x | <= 4.11 | 4.5.x |

APIM 4.12 upgraded Vert.x from 4.5 to 5.0, and Vert.x 5 changed the return type of `Vertx.createHttpClient()` from `HttpClient` to `HttpClientAgent`. Because the JVM resolves methods by name *and descriptor*, a build compiled against one major cannot run on the other. The failure mode is deliberately worth knowing: **the plugin loads and deploys normally, then every request fails at exchange time with `NoSuchMethodError`.** A green gateway startup is not evidence that you picked the right line.

2.x is verified end to end by CI against APIM 4.12.0 and 4.12.12 (see `.github/workflows/integration-matrix.yml`). If you are still on APIM 4.11 or earlier, use the latest 1.x release.

## Development

Prerequisites: `asdf`, Docker.

```bash
mvn clean install
```

To run the full end-to-end integration tests (requires Docker):

```bash
mvn verify
```

## Configuration

The policy is configured via the Gravitee Management Console or API. Below are examples using the Gravitee Terraform APIM provider.

### OAuth2 Token Exchange (RFC 8693)

This example requires a preceding **JWT** security policy to populate the `jwt.token` attribute and uses a **Shared Redis Cache** resource.

```hcl
resource "gravitee_api_v4" "exchange_api" {
  name = "Token Exchange API"
  # ... other API config ...

  # 1. Define the Cache Resource
  resources = [{
    name = "shared-redis"
    type = "cache"
    configuration = jsonencode({
      # Redis or In-Memory configuration
      timeToIdleSeconds = 0
      timeToLiveSeconds = 3600
    })
  }]

  plans = [{
    name     = "Standard JWT Plan"
    security = { type = "JWT" } # Populates #context.attributes['jwt.token']
    
    flows = [{
      name = "Token Exchange Flow"
      selectors = [{
        type = "HTTP"
        path = "/secure"
      }]
      request = [{
        policy = "oauth2-token-orchestrator"
        configuration = jsonencode({
          cacheResource = "shared-redis"
          tokenEndpoint = "https://idp.example.com/oauth2/token"
          grantType     = "urn:ietf:params:oauth:grant-type:token-exchange"
          clientId      = "YOUR_CLIENT_ID"
          parameters = {
            subject_token      = "{#context.attributes['jwt.token']}"
            subject_token_type = "urn:ietf:params:oauth:token-type:access_token"
          }
        })
      }]
    }]
  }]
}
```

### OAuth2 Refresh Token

This example handles the automated refresh and caching of an access token using a long-lived refresh token stored in API properties.

```hcl
resource "gravitee_api_v4" "refresh_api" {
  name = "Token Refresh API"
  # ... other API config ...

  resources = [{
    name = "shared-redis"
    type = "cache"
    configuration = jsonencode({
      timeToLiveSeconds = 3600
    })
  }]

  flows = [{
    name = "Token Refresh Flow"
    request = [{
      policy = "oauth2-token-orchestrator"
      configuration = jsonencode({
        cacheResource = "shared-redis"
        tokenEndpoint = "https://oauth.example.com/token"
        grantType     = "refresh_token"
        clientId      = "{#api.properties['client-id']}"
        clientSecret  = "{#api.properties['client-secret']}"
        parameters = {
          refresh_token = "{#api.properties['refresh-token']}"
        }
        cacheKey   = "provider-global-token"
        defaultTtl = 3500
      })
    }]
  }]
}
```

### Required Fields
- `cacheResource`: Name of the Gravitee Cache Resource to use.
- `tokenEndpoint`: The full URL to the OAuth2 provider token endpoint.
- `grantType`: The OAuth2 `grant_type` (e.g., `urn:ietf:params:oauth:grant-type:token-exchange`).

### Optional Fields
- `clientId`, `clientSecret`: Credentials, both EL-templated (e.g. `{#api.properties['client-id']}`).
- `cacheKey`: Expression for the unique cache key. Default: `{#context.attributes['jwt.claims']['sub']}`. Use a compound expression when one user holds tokens for multiple audiences, e.g. `{#context.attributes['jwt.claims']['aud'] + ' ' + #context.attributes['jwt.claims']['sub']}` — otherwise tokens for different audiences will collide. If the expression fails to resolve, the policy falls back to a hash of the inbound `Authorization` header.
- `parameters`: Map of additional body parameters (values support EL).
- `defaultTtl` (default `3600`): Fallback cache TTL in seconds. The policy first tries the IDP's `expires_in` field, then a JWT `exp` claim if `access_token` is a JWT, and only falls back to this value when neither is present.
- `errorStatusCode` (default `401`): HTTP status returned to the gateway client when the IDP rejects the exchange.
- `errorContent` (default `{"message": "Token exchange failed"}`): Body returned with that status. Supports EL and has access to the IDP response via two context attributes the policy sets before resolving the template (see below).

### Error template attributes

When the IDP returns a non-2xx response, the policy publishes the response status and body as context attributes **before** evaluating `errorContent`, so detailed operator-facing messages are possible:

| Attribute | Type | Description |
|---|---|---|
| `tokenexchange.response.status` | int | Status code returned by the IDP token endpoint |
| `tokenexchange.response.content` | string | Raw response body returned by the IDP |

Example template that surfaces the underlying IDP failure:

```hcl
errorContent = "Could not exchange token for subject '{#context.attributes['jwt.claims']['sub']}': ({#context.attributes['tokenexchange.response.status']}) {#context.attributes['tokenexchange.response.content']}"
```

These attributes are only populated on IDP rejection (non-2xx). Transport-level failures (DNS, connection refused, body read errors) produce a generic `502 Token exchange failed` and do not set the attributes.

## Relationship to Gravitee AM's built-in Token Exchange

Gravitee Access Management gained native RFC 8693 support in **AM 4.11**, configured per security domain. That feature and this policy solve different halves of the problem, and one does not replace the other:

| | AM native Token Exchange | This policy |
|---|---|---|
| Role | **Token issuer** — AM validates a presented token and mints a *new AM token* (impersonation or delegation with an `act` claim) | **Token client** — the gateway presents the inbound token to *somebody else's* token endpoint and injects the token that endpoint returns |
| Who issues the resulting token | AM | Any third-party OAuth2 provider |
| Caching | Not applicable | Delegated to a Gravitee `CacheResource`, TTL derived from `expires_in` / JWT `exp` |
| Grant types | Token exchange | Token exchange, `refresh_token`, or any other form-encoded grant |

Use AM's native feature when the *audience trusts AM* and an AM-issued token is what the backend wants. Use this policy when the backend requires a token issued by its **own** authorization server — a SaaS API reached with a `refresh_token`, or a downstream product that implements its own RFC 8693 endpoint and trusts AM as an external issuer. AM cannot fill that role: it never acts as an HTTP client of a foreign token endpoint.

There is also no first-party APIM policy that covers this. The closest built-in equivalent is chaining `policy-cache` → `policy-callout-http` → `policy-cache` → `policy-transform-headers`, which this policy collapses into one step (and which cannot derive its cache TTL from the token response).

## Deployment

Releases follow **semver tagging**. To publish a new release:

1. Create a GitHub Release with a semver tag (e.g. `v2.0.0`).
2. The `release.yml` workflow sets the Maven version, builds the plugin ZIP, and attaches it to the release automatically.
3. Copy the released ZIP into the Gravitee gateway `plugins-ext/` directory and restart the gateway.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.
