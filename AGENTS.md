# Agent guidance — gravitee-policy-token-exchange

## Verification rule (non-negotiable)

**Never claim the policy works, is fixed, refactored, or "verified" until `E2EGatewayIT` has passed in this working tree.** `mvn test` alone is insufficient — it exercises mocks. The only authoritative check is the full end-to-end test that runs Gravitee APIM (management + gateway), MongoDB, and WireMock as real containers and configures the API via the official Terraform provider.

The required command:

```bash
mvn verify
```

This runs unit tests (surefire) **and** `**/*IT.java` (failsafe). If you want to skip the unit tests but still run the IT, use:

```bash
mvn verify -Dtest='!*' -DfailIfNoTests=false
```

Do **not** use `-DskipTests=true` with `verify` — Maven interprets that as "skip failsafe too", and the IT will silently be skipped (failsafe will log `Tests are skipped`). If you see that line in the output, you have NOT verified anything.

### Prerequisites

- Docker daemon running (`docker info` succeeds).
- `terraform` 1.15.1 installed (asdf manages it; the IT writes `.tool-versions` into its working directory). `asdf list terraform` should include `1.15.1`.
- Network access to pull `mongo:7.0`, `wiremock/wiremock:3.5.4`, `graviteeio/apim-management-api:4.9.13`, and `graviteeio/apim-gateway:4.9.13` (first run is slow).

### What "passed" looks like

Failsafe reports `Tests run: 1, Failures: 0, Errors: 0, Skipped: 0` for `E2EGatewayIT` and the build ends with `BUILD SUCCESS`. The test logs the line `E2E Test Passed: Native caching with User Isolation verified.` and WireMock confirms exactly 2 `POST /token` calls and 3 `GET /backend` calls with the exchanged bearer token.

### When the IT cannot run

If Docker is genuinely unavailable in the environment (CI sandbox without docker-in-docker, etc.), **say so explicitly in the response** rather than claiming success. Do not silently fall back to "unit tests pass".

## Architecture notes

- The policy is **V4 reactive only**. It implements `io.gravitee.gateway.reactive.api.policy.Policy` and returns a `Completable` from `onRequest(HttpExecutionContext)`. There is no V2 (`@OnRequest`) code path. Do not reintroduce one unless a deployment target actually requires it.
- Caching is delegated entirely to a Gravitee `CacheResource` — there is no in-process fallback map. The cache resource is mandatory; the policy returns 500 if it is missing.
- TTL is derived from the OAuth2 response (`expires_in`) or, failing that, the JWT `exp` claim. `defaultTtl` is the last-resort fallback.
- The default `cacheKey` expression is `{#context.attributes['jwt.claims']['sub']}`. When that expression fails to resolve, the policy isolates per-user by hashing the inbound `Authorization` header — relevant for KEY_LESS plans where there is no JWT plugin upstream.

## Repo conventions

- Java 21, Maven, Mockito with `LENIENT` strictness for the policy tests.
- Tests use AssertJ + RxJava `TestObserver` (`.test().awaitDone(...)`); WireMock for the IDP stub; Testcontainers for E2E.
- Do not commit `debug_*.sh` / `deploy_*.sh` scripts to the repo root — those are scratch files and belong in `.gitignore` if needed.
