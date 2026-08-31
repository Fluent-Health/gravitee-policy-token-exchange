# Gravitee Policy OAuth2 Token Orchestrator

A Gravitee APIM policy plugin that orchestrates the "Cache -> Token Request -> Cache Store -> Header Injection" lifecycle for RFC 8693 (Token Exchange) and standard OAuth2 refresh token flows.

By consolidating these steps into a single execution unit, it improves performance, simplifies API definitions, and ensures consistent error handling and trace context propagation.

A project by [Fluent Health](https://github.com/Fluent-Health).

## Key Features

- **Unified Flow**: Handles cache lookup, asynchronous token request, cache update, and header injection.
- **RFC 8693 Support**: Specialized for generic OAuth2 Token Exchange.
- **Refresh Token Support**: Configurable for standard OAuth2 refresh flows.
- **Both client authentication methods**: `client_secret_post` and `client_secret_basic` (RFC 6749 §2.3.1).
- **Non-OAuth2 mint endpoints**: JSON request bodies and a configurable token field path, for services that hand out tokens without speaking OAuth2.
- **Bounded caching**: TTL derived from the response, optionally capped so a credential rotation takes effect within a known window.
- **Asynchronous**: Built on Vert.x `HttpClient` for non-blocking gateway execution.
- **Trace Context**: Propagates W3C `traceparent` and `X-Request-ID` headers to the token provider.

## Compatibility

**Pick the plugin line that matches your APIM version — they are not interchangeable.**

| Plugin | Requires APIM | Vert.x runtime |
| --- | --- | --- |
| **2.x** | **>= 4.12** | 5.0.x |
| 0.1.x | <= 4.11 | 4.5.x |

APIM 4.12 upgraded Vert.x from 4.5 to 5.0, and Vert.x 5 changed the return type of `Vertx.createHttpClient()` from `HttpClient` to `HttpClientAgent`. Because the JVM resolves methods by name *and descriptor*, a build compiled against one major cannot run on the other. The failure mode is deliberately worth knowing: **the plugin loads and deploys normally, then every request fails at exchange time with `NoSuchMethodError`.** A green gateway startup is not evidence that you picked the right line.

2.x is verified end to end by CI against APIM 4.12.0 and 4.12.12 (see `.github/workflows/integration-matrix.yml`). If you are still on APIM 4.11 or earlier, use the `0.1.x` line — the latest is [`0.1.1`](https://github.com/Fluent-Health/gravitee-policy-token-exchange/releases/tag/0.1.1). There is no 1.x line; the version jumps from `0.1.x` to `2.0.0` to make the Vert.x boundary a major bump.

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
- `tokenEndpoint`: The full URL to the token endpoint.
- `grantType`: The OAuth2 `grant_type` (e.g., `urn:ietf:params:oauth:grant-type:token-exchange`). Required for `requestFormat: form`; ignored for `json`.

### Optional Fields
- `clientId`, `clientSecret`: Credentials, both EL-templated (e.g. `{#api.properties['client-id']}`, or a secret-provider reference — see [Expression values](#expression-values-including-asynchronous-ones)).
- `clientAuthMethod` (default `client_secret_post`): How the credentials are presented — see [Client authentication](#client-authentication).
- `requestFormat` (default `form`): Request body encoding — see [Non-OAuth2 mint endpoints](#non-oauth2-mint-endpoints-requestformat-json).
- `tokenPath` (default `access_token`): Dot-separated path to the token in the response, e.g. `accessToken` or `data.token`. A leading `$.` is accepted and ignored. Not JSONPath — plain field names only.
- `cacheKey`: Expression for the unique cache key. Default: `{#context.attributes['jwt.claims']['sub']}`. Use a compound expression when one user holds tokens for multiple audiences, e.g. `{#context.attributes['jwt.claims']['aud'] + ' ' + #context.attributes['jwt.claims']['sub']}` — otherwise tokens for different audiences will collide. If the expression fails to resolve, the policy falls back to a hash of the inbound `Authorization` header.
- `parameters`: Map of additional body parameters (values support EL). Under `requestFormat: json` this map **is** the request body.
- `defaultTtl` (default `3600`): Fallback cache TTL in seconds. The policy first tries the provider's `expires_in` field, then a JWT `exp` claim if the token is a JWT, and only falls back to this value when neither is present.
- `maxTtl` (default `0`, meaning unbounded): Upper bound on the cache TTL. See [Bounding the TTL](#bounding-the-ttl-maxttl).
- `errorStatusCode` (default `401`): HTTP status returned to the gateway client when the provider rejects the exchange.
- `errorContent` (default `{"message": "Token exchange failed"}`): Body returned with that status. Supports EL and has access to the provider response via two context attributes the policy sets before resolving the template (see below).

### Expression values, including asynchronous ones

Every templated field — `tokenEndpoint`, `clientId`, `clientSecret`, each `parameters` value, `cacheKey`, `errorContent` — is resolved through the gateway's expression language on the reactive path, so a value that arrives *asynchronously* resolves correctly. That matters for a secret provider, where the reference is a lookup rather than a lookup table:

```hcl
clientSecret = "{#secrets.get('/gcp/idp-credentials:client_secret')}"
```

The value is fetched per request (behind whatever caching the provider itself does), never stored in the API definition, and a rotation takes effect without redeploying the API.

There is no configuration to turn on, and plain literals and ordinary in-memory expressions such as `{#api.properties['client-id']}` are unaffected. It is called out because the failure mode of getting it wrong is silent: a policy that resolves through one of the expression language's synchronous entry points gets the *expression string itself* back for an asynchronous variable, with no error anywhere, and sends `{#secrets.get('...')}` to the token endpoint as the credential. The endpoint answers `401`, which the policy reports as a `502`, and nothing in the logs points at the expression.

### Client authentication

`clientAuthMethod` selects how client credentials reach the token endpoint, per [RFC 6749 §2.3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1):

| Value | Behaviour |
| --- | --- |
| `client_secret_post` (default) | `client_id` / `client_secret` in the request body. |
| `client_secret_basic` | `Authorization: Basic base64(urlencode(id):urlencode(secret))`, and both are omitted from the body. |

Endpoints are not consistent about which they accept, and one that requires Basic answers `client_secret_post` with a `401` — which surfaces as a `502` on every proxied call, since the policy could not obtain a token. If a token endpoint rejects credentials that you are sure are correct, try the other method before suspecting the credentials.

The components are form-urlencoded before being joined and base64-encoded, which is what keeps a secret containing `:` unambiguous.

### Non-OAuth2 mint endpoints (`requestFormat: json`)

Not every "give me a token" endpoint is an OAuth2 token endpoint. Some take a JSON body and return the token under their own field name. `requestFormat: json` covers those:

```hcl
configuration = jsonencode({
  cacheResource = "cache-global"
  tokenEndpoint = "https://example.internal/api/public/generatetoken"
  requestFormat = "json"
  tokenPath     = "accessToken"
  parameters = {
    username = "{#api.properties['svc-user']}"
    password = "{#api.properties['svc-password']}"
  }
  cacheKey   = "example-service-token"
  maxTtl     = 3600
})
```

In `json` mode the body is built from `parameters` **alone** — no `grant_type`, no client credentials are added implicitly, because those are OAuth2 concepts the endpoint may not recognise. Anything the endpoint needs goes in `parameters` verbatim. Values are serialised by Jackson, so quotes and backslashes in a resolved value cannot break out of their JSON string.

`clientAuthMethod` still applies in `json` mode — it is a header concern, independent of the body format.

### Bounding the TTL (`maxTtl`)

TTL is normally derived from the response: `expires_in`, else the token's own JWT `exp` claim, else `defaultTtl`. That is the right default, but it ties the cache lifetime to the token's lifetime.

Set `maxTtl` when the provider issues a **long-lived** token whose underlying credential can be rotated. Without a bound, a 24-hour token is cached for 24 hours, so rotating the password behind it has no effect until that token finally expires. With `maxTtl = 3600` the token is still valid when served (the bound only ever shortens the cached lifetime) and a rotation takes effect within the hour.

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

1. Create a GitHub Release with a semver tag, unprefixed to match existing tags (e.g. `2.0.0`).
2. The `release.yml` workflow sets the Maven version, builds the plugin ZIP, and attaches it to the release automatically.
3. Copy the released ZIP into the Gravitee gateway `plugins-ext/` directory and restart the gateway.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.
