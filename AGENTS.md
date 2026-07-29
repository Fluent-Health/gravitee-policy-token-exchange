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
- Network access to pull `mongo:7.0`, `wiremock/wiremock:3.5.4`, and the `graviteeio/apim-*` / `graviteeio/am-*` images for the version under test (see [Version matrix](#version-matrix); first run is slow).

### What "passed" looks like

Failsafe reports `Tests run: 1, Failures: 0, Errors: 0, Skipped: 0` for `E2EGatewayIT` and the build ends with `BUILD SUCCESS`. The test logs the line `E2E Test Passed: Native caching with User Isolation verified.` and WireMock confirms exactly 2 `POST /token` calls and 3 `GET /backend` calls with the exchanged bearer token.

### When the IT cannot run

If Docker is genuinely unavailable in the environment (CI sandbox without docker-in-docker, etc.), **say so explicitly in the response** rather than claiming success. Do not silently fall back to "unit tests pass".

## The second IT: `AmDomainV2GatewayIT`

`E2EGatewayIT` mints its own JWTs. `AmDomainV2GatewayIT` additionally boots **real Gravitee AM** (management + gateway on their own MongoDB), bootstraps a v2.0 security domain with one user and one OIDC app, mints a token via the password grant, and pushes that token through the APIM gateway's policy. It exists to catch two things a hand-rolled JWT cannot:

1. The policy forwards a genuine AM access token verbatim as `subject_token`.
2. The AM domain-v2 `sub` algorithm — `sub == UUID.nameUUIDFromBytes(("<source>:" + externalId).getBytes(UTF_8))`, i.e. the `gis` claim — still holds. The default `cacheKey` keys off `jwt.claims.sub`, so a change here silently changes cache partitioning.

Run it alone with:

```bash
mvn verify -Dtest='!*' -Dsurefire.failIfNoSpecifiedTests=false -Dit.test=AmDomainV2GatewayIT
```

## Version matrix

Both ITs take their container versions from system properties, and CI runs them across a matrix defined once in `.github/workflows/integration-matrix.yml` (a reusable workflow, shared by `ci.yml` and `release.yml` so the two cannot drift):

| Leg | APIM | AM | Purpose |
| --- | --- | --- | --- |
| floor | `4.12.0` | `4.12.2` | Oldest APIM this major supports — the first release on Vert.x 5. Catches accidental reliance on a later 4.12.x addition. |
| latest | `4.12.12` | `4.12.2` | Early warning for upstream breakage. |

**Do not add an APIM 4.11 leg** — see the Vert.x note above. 4.11 support lives on the `0.1.x` line.

The Java defaults are the **latest** versions, so a bare `mvn verify` exercises the newest supported combination. To test another locally:

```bash
mvn verify -Dapim.version=4.12.0 -Dam.version=4.10.12
```

Every leg is explicitly pinned rather than tracking the floating `latest` Docker tag — CI stays deterministic, and moving a pin is always a deliberate, reviewable change. When bumping, check the newest published tags first:

```bash
curl -s "https://hub.docker.com/v2/repositories/graviteeio/apim-gateway/tags?page_size=100&ordering=last_updated" | jq -r '.results[].name' | head
```

### Deployment sequencing

A 2.x ZIP and an APIM 4.12 gateway have to arrive together. **Upgrade APIM first, then the plugin** — never the other way round, and never the plugin alone. A gateway still on 4.11 keeps running `0.1.x` until it is upgraded.

There is no guard rail at deploy time: dropping a 2.x ZIP into `plugins-ext/` on a 4.11 gateway succeeds, the API deploys, and only then does every request fail. The policy turns that into an explanatory error rather than a bare `NoSuchMethodError` (see `createHttpClient`), but the deploy itself will not stop you.

## Architecture notes

- The policy is **V4 reactive only**. It implements `io.gravitee.gateway.reactive.api.policy.Policy` and returns a `Completable` from `onRequest(HttpExecutionContext)`. There is no V2 (`@OnRequest`) code path. Do not reintroduce one unless a deployment target actually requires it.
- Caching is delegated entirely to a Gravitee `CacheResource` — there is no in-process fallback map. The cache resource is mandatory; the policy returns 500 if it is missing.
- TTL is derived from the OAuth2 response (`expires_in`) or, failing that, the JWT `exp` claim. `defaultTtl` is the last-resort fallback.
- The default `cacheKey` expression is `{#context.attributes['jwt.claims']['sub']}`. When that expression fails to resolve, the policy isolates per-user by hashing the inbound `Authorization` header — relevant for KEY_LESS plans where there is no JWT plugin upstream.

### This major requires APIM >= 4.12 (Vert.x 5)

The `2.x` line is compiled against **Vert.x 5.0.12**, as shipped by APIM 4.12. It **cannot run on APIM 4.11 or earlier** (Vert.x 4.5) — `Vertx.createHttpClient()` returns `HttpClient` on Vert.x 4 and `HttpClientAgent` on Vert.x 5, and the JVM resolves methods by name **and descriptor**. The failure mode is nasty: the plugin loads and the API deploys cleanly, then every request fails at exchange time with `NoSuchMethodError`. A clean gateway startup proves nothing here.

APIM 4.11 and earlier are served by the `0.1.x` line (latest `0.1.1`), which is compiled against Vert.x 4. There is no 1.x line — the version deliberately jumps from `0.1.x` to `2.0.0` so the Vert.x boundary is a major bump. Do not try to make one artifact span both — the only way to do that is to resolve the factory method reflectively, and that was deliberately abandoned in favour of a clean major split.

The gateway API versions in `pom.xml` are all `provided` and must track the target APIM release. Read them off the image rather than guessing:

```bash
docker run --rm --entrypoint sh graviteeio/apim-gateway:4.12.12 \
  -c 'ls /opt/graviteeio-gateway/lib /opt/graviteeio-gateway/lib/ext' \
  | grep -iE 'gravitee-(gateway-api|policy-api|common|resource|expression)|vertx-core-'
```

After any APIM bump, re-audit the descriptors the compiled policy actually references against the new runtime jars — this is what would have caught the Vert.x 5 break before it reached a test run:

```bash
javap -c -p -cp target/classes io.fluenthealth.gravitee.policy.tokenexchange.OAuth2TokenOrchestratorPolicy \
  | grep -oE '(InterfaceMethod|Method) io/vertx/[^ ]*' | sort -u
```

Note the compile/runtime split on the expression language: gateway-api 6.3.0 pulls EL **3.2.1** transitively, while the APIM 4.12 runtime ships EL **4.4.0**. `TemplateEngine.getValue` exists in both (the ITs prove it resolves at runtime); `evalNow` exists only in 4.2.0+, so using it would mean declaring EL explicitly as `provided` instead of inheriting it.

## Repo conventions

- Java 21, Maven, Mockito with `LENIENT` strictness for the policy tests.
- Tests use AssertJ + RxJava `TestObserver` (`.test().awaitDone(...)`); WireMock for the IDP stub; Testcontainers for E2E.
- Do not commit `debug_*.sh` / `deploy_*.sh` scripts to the repo root — those are scratch files and belong in `.gitignore` if needed.
