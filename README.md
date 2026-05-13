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
- `clientId`, `clientSecret`
- `cacheKey`: Expression for the unique cache key (Default: `{#context.attributes['jwt.claims']['sub']}`).
- `parameters`: Map of additional body parameters (Values support EL).

## Deployment

Releases follow **semver tagging**. To publish a new release:

1. Create a GitHub Release with a semver tag (e.g. `v1.0.0`).
2. The `release.yml` workflow sets the Maven version, builds the plugin ZIP, and attaches it to the release automatically.
3. Copy the released ZIP into the Gravitee gateway `plugins-ext/` directory and restart the gateway.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.
