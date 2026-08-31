package io.fluenthealth.gravitee.policy.tokenexchange;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fluenthealth.gravitee.policy.tokenexchange.configuration.OAuth2TokenOrchestratorPolicyConfiguration;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.policy.http.HttpPolicy;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.Cache;
import io.gravitee.resource.cache.api.CacheResource;
import io.gravitee.resource.cache.api.Element;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OAuth2 Token Orchestrator Policy.
 *
 * <p>Exchanges the inbound bearer token via an IDP token endpoint and caches the result in a
 * Gravitee {@link CacheResource}. Cache TTL is derived from the OAuth2 response (the
 * {@code expires_in} field or, failing that, the JWT {@code exp} claim).
 */
public class OAuth2TokenOrchestratorPolicy implements HttpPolicy {

    private static final Logger log = LoggerFactory.getLogger(OAuth2TokenOrchestratorPolicy.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    static final String ATTR_RESPONSE_STATUS = "tokenexchange.response.status";
    static final String ATTR_RESPONSE_CONTENT = "tokenexchange.response.content";

    private final OAuth2TokenOrchestratorPolicyConfiguration configuration;
    private volatile HttpClient httpClient;

    public OAuth2TokenOrchestratorPolicy(OAuth2TokenOrchestratorPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public String id() {
        return "oauth2-token-orchestrator";
    }

    @Override
    public Completable onRequest(HttpPlainExecutionContext ctx) {
        return Completable.defer(() -> {
            var cacheResource = ctx
                .getComponent(ResourceManager.class)
                .getResource(configuration.getCacheResource(), CacheResource.class);
            if (cacheResource == null) {
                log.error("Cache resource [{}] not found", configuration.getCacheResource());
                return ctx.interruptWith(
                    new ExecutionFailure(500).message("Cache resource [" + configuration.getCacheResource() + "] not found")
                );
            }

            var cache = cacheResource.getCache(ctx);
            return resolveCacheKey(ctx).flatMapCompletable(cacheKey -> {
                var cached = cache.get(cacheKey);
                if (cached != null && cached.value() != null) {
                    log.debug("Cache hit for key [{}]", cacheKey);
                    ctx.request().headers().set(AUTHORIZATION, BEARER_PREFIX + cached.value());
                    return Completable.complete();
                }

                log.debug("Cache miss for key [{}]", cacheKey);
                return doExchange(ctx, cache, cacheKey);
            });
        });
    }

    // ── Expression resolution ─────────────────────────────────────────────────

    /**
     * Evaluates a template expression — and the only place this policy is allowed to do so.
     *
     * <p>{@code TemplateEngine.eval} is the sole entry point that resolves <em>deferred</em>
     * variables: ones whose value is produced asynchronously, as a secret-provider lookup is. The
     * synchronous entry points do not. {@code getValue} is deprecated and blocking, {@code convert}
     * delegates to it, and {@code evalNow} is documented as not supporting deferred variables — and
     * none of them report the problem. A deferred reference simply comes back as the literal
     * expression string, which for {@code clientSecret} means the text {@code {#secrets.get(...)}}
     * reaches the IDP as the credential.
     *
     * <p>An empty {@link Maybe} means "no value": either nothing was configured, or the expression
     * resolved to null. What that means is the caller's decision — see {@link #resolve} and
     * {@link #resolveOrLiteral}.
     */
    private static Maybe<String> evaluate(HttpPlainExecutionContext ctx, String expression) {
        if (expression == null) {
            return Maybe.empty();
        }
        // defer: an engine that rejects a malformed expression throws out of eval itself rather
        // than signalling it, and that has to become an onError rather than escaping assembly.
        return Maybe.defer(() -> ctx.getTemplateEngine().eval(expression, String.class));
    }

    /**
     * Strict resolution: a failure propagates and fails the exchange. Used for credentials and
     * request parameters, where substituting anything for the resolved value is the whole bug.
     */
    private static Single<Optional<String>> resolve(HttpPlainExecutionContext ctx, String expression) {
        return evaluate(ctx, expression).map(Optional::of).defaultIfEmpty(Optional.empty());
    }

    /**
     * Lenient resolution: on failure the expression stands as its own literal value. Applies to the
     * token endpoint and the error content — ordinarily plain strings, and neither a credential.
     */
    private static Single<Optional<String>> resolveOrLiteral(HttpPlainExecutionContext ctx, String expression) {
        return evaluate(ctx, expression)
            .onErrorResumeNext(e -> Maybe.just(expression))
            .map(Optional::of)
            .defaultIfEmpty(Optional.empty());
    }

    private Single<String> resolveCacheKey(HttpPlainExecutionContext ctx) {
        var expression = configuration.getCacheKey();
        if (expression == null || expression.isEmpty()) {
            return Single.fromCallable(() -> fallbackCacheKey(ctx));
        }
        return evaluate(ctx, expression)
            .onErrorResumeNext(e -> {
                log.debug("Failed to resolve cache key expression [{}]: {}", expression, e.toString());
                return Maybe.empty();
            })
            .filter(resolved -> !resolved.isEmpty())
            .switchIfEmpty(Single.fromCallable(() -> fallbackCacheKey(ctx)));
    }

    /**
     * Per-user isolation for when the cache key expression yields nothing — relevant on KEY_LESS
     * plans, where no JWT plugin runs upstream to populate {@code jwt.claims}.
     */
    private String fallbackCacheKey(HttpPlainExecutionContext ctx) {
        var authHeader = ctx.request().headers().get(AUTHORIZATION);
        return authHeader != null ? "u_" + Integer.toHexString(authHeader.hashCode()) : "anon_token";
    }

    // ── Exchange ──────────────────────────────────────────────────────────────

    private Completable doExchange(HttpPlainExecutionContext ctx, Cache cache, String cacheKey) {
        return Single
            .defer(() -> requestToken(ctx))
            .flatMapCompletable(token -> {
                ctx.request().headers().set(AUTHORIZATION, BEARER_PREFIX + token.accessToken());
                log.debug("Storing token for [{}] with TTL {}s", cacheKey, token.ttl());
                cache.put(new CachedToken(cacheKey, token.accessToken(), token.ttl()));
                return Completable.complete();
            })
            .onErrorResumeNext(t -> {
                if (t instanceof TokenExchangeException te) {
                    log.warn("Token exchange failed: status={}, body={}", te.statusCode, te.responseBody);
                    // Expose IDP response to the errorContent template so callers can build
                    // detailed messages, mirroring policy-http-callout's #calloutResponse.* — which
                    // means the attributes have to be in place before errorContent is resolved.
                    ctx.putAttribute(ATTR_RESPONSE_STATUS, te.statusCode);
                    ctx.putAttribute(ATTR_RESPONSE_CONTENT, te.responseBody);
                    return resolveOrLiteral(ctx, configuration.getErrorContent()).flatMapCompletable(message ->
                        ctx.interruptWith(new ExecutionFailure(configuration.getErrorStatusCode()).message(message.orElse(null)))
                    );
                }
                log.warn("Token exchange failed: {}", t.toString());
                return ctx.interruptWith(new ExecutionFailure(502).message("Token exchange failed"));
            });
    }

    /**
     * Resolves everything the token request needs, then sends it.
     *
     * <p>Endpoint, body and Basic header are gathered as a unit because any of them may sit behind
     * a deferred value; only once all three have arrived is there a request to send.
     */
    private Single<TokenInfo> requestToken(HttpPlainExecutionContext ctx) {
        var json = configuration.usesJsonRequestFormat();
        var contentType = json ? "application/json" : "application/x-www-form-urlencoded";
        return Single
            .zip(
                resolveOrLiteral(ctx, configuration.getTokenEndpoint()),
                json ? buildJsonBody(ctx) : buildFormBody(ctx),
                buildBasicAuthHeader(ctx).map(Optional::of).defaultIfEmpty(Optional.empty()),
                TokenRequest::new
            )
            .flatMap(tokenRequest -> send(ctx, tokenRequest, contentType));
    }

    private Single<TokenInfo> send(HttpPlainExecutionContext ctx, TokenRequest tokenRequest, String contentType) {
        var body = tokenRequest.body();
        // Byte length, not String.length(): a form body is percent-encoded and therefore ASCII, but a
        // JSON body carries raw UTF-8, where one character can be several bytes. Sending the
        // character count as Content-Length truncates the body server-side.
        var contentLength = String.valueOf(body.getBytes(StandardCharsets.UTF_8).length);
        var traceparent = ctx.request().headers().get("traceparent");

        return Single.create(emitter -> {
            URI uri;
            try {
                uri = URI.create(tokenRequest.endpoint().orElse(null));
            } catch (Exception e) {
                emitter.onError(e);
                return;
            }
            var secure = "https".equalsIgnoreCase(uri.getScheme());
            var port = uri.getPort() != -1 ? uri.getPort() : (secure ? 443 : 80);
            var options = new RequestOptions()
                .setMethod(HttpMethod.POST)
                .setHost(uri.getHost())
                .setPort(port)
                .setURI(uri.getRawPath() + (uri.getRawQuery() != null ? "?" + uri.getRawQuery() : ""))
                .setSsl(secure);

            getHttpClient(ctx)
                .request(options)
                .onFailure(emitter::onError)
                .onSuccess(req -> {
                    req.putHeader("Content-Type", contentType);
                    req.putHeader("Content-Length", contentLength);
                    tokenRequest.basicAuth().ifPresent(basicAuth -> req.putHeader(AUTHORIZATION, basicAuth));
                    if (traceparent != null) {
                        req.putHeader("traceparent", traceparent);
                    }
                    req
                        .send(body)
                        .onFailure(emitter::onError)
                        .onSuccess(res ->
                            res
                                .body()
                                .onFailure(emitter::onError)
                                .onSuccess(buf -> {
                                    var responseBody = buf != null ? buf.toString() : "";
                                    if (res.statusCode() < 200 || res.statusCode() >= 300) {
                                        emitter.onError(new TokenExchangeException(res.statusCode(), responseBody));
                                        return;
                                    }
                                    try {
                                        var node = MAPPER.readTree(responseBody);
                                        var accessToken = extractToken(node);
                                        if (accessToken == null) {
                                            emitter.onError(new RuntimeException("Missing " + tokenPath() + " in IDP response"));
                                            return;
                                        }
                                        emitter.onSuccess(new TokenInfo(accessToken, extractTtl(node, accessToken)));
                                    } catch (Exception e) {
                                        emitter.onError(new RuntimeException("Failed to parse token response", e));
                                    }
                                })
                        );
                });
        });
    }

    /** Configured token path, defaulted. A leading {@code $.} is accepted and ignored. */
    private String tokenPath() {
        var path = configuration.getTokenPath();
        if (path == null || path.isBlank()) {
            return OAuth2TokenOrchestratorPolicyConfiguration.DEFAULT_TOKEN_PATH;
        }
        return path.startsWith("$.") ? path.substring(2) : path;
    }

    /**
     * Reads the token out of the response by walking dot-separated field names — {@code access_token},
     * {@code accessToken}, {@code data.token}. Deliberately not JSONPath: no array indexing, no
     * filters, no extra dependency, and every token endpoint met so far returns the token at a fixed
     * field.
     */
    String extractToken(JsonNode node) {
        var cursor = node;
        for (var segment : tokenPath().split("\\.")) {
            if (segment.isEmpty()) {
                continue;
            }
            cursor = cursor.path(segment);
        }
        return cursor.isValueNode() ? cursor.asText(null) : null;
    }

    int extractTtl(JsonNode node, String accessToken) {
        var ttl = deriveTtl(node, accessToken);
        var max = configuration.getMaxTtl();
        return max > 0 ? Math.min(ttl, max) : ttl;
    }

    private int deriveTtl(JsonNode node, String accessToken) {
        if (node.has("expires_in")) {
            return node.get("expires_in").asInt();
        }
        try {
            var parts = accessToken.split("\\.");
            if (parts.length == 3) {
                var payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                var jwt = MAPPER.readTree(payload);
                if (jwt.has("exp")) {
                    var exp = jwt.get("exp").asLong();
                    var now = System.currentTimeMillis() / 1000;
                    return (int) Math.max(1, exp - now);
                }
            }
        } catch (Exception e) {
            log.debug("Could not derive TTL from JWT exp claim: {}", e.toString());
        }
        return configuration.getDefaultTtl();
    }

    // ── Request body and credentials ──────────────────────────────────────────

    Single<String> buildFormBody(HttpPlainExecutionContext ctx) {
        // Keyed by field name in a LinkedHashMap, exactly as when the values were resolved inline:
        // a `parameters` entry colliding with grant_type or a credential overwrites it in place
        // rather than being emitted a second time.
        var fields = new LinkedHashMap<String, Single<Optional<String>>>();

        // grant_type is taken verbatim; it has never gone through the template engine.
        if (configuration.getGrantType() != null) {
            fields.put("grant_type", Single.just(Optional.of(configuration.getGrantType())));
        }
        // Under client_secret_basic the credentials travel in the Authorization header instead, and
        // RFC 6749 §2.3.1 is explicit that a client using one method must not use the other.
        if (!configuration.usesClientSecretBasic()) {
            if (configuration.getClientId() != null) {
                fields.put("client_id", resolve(ctx, configuration.getClientId()));
            }
            if (configuration.getClientSecret() != null) {
                fields.put("client_secret", resolve(ctx, configuration.getClientSecret()));
            }
        }
        if (configuration.getParameters() != null) {
            configuration.getParameters().forEach((name, expression) -> fields.put(name, resolve(ctx, expression)));
        }

        if (fields.isEmpty()) {
            return Single.just("");
        }
        var names = List.copyOf(fields.keySet());
        return zipResolved(fields.values(), values -> {
            var pairs = new ArrayList<String>(names.size());
            for (var i = 0; i < names.size(); i++) {
                var value = values.get(i);
                pairs.add(encode(names.get(i)) + "=" + (value != null ? encode(value) : ""));
            }
            return String.join("&", pairs);
        });
    }

    /**
     * Builds a JSON object body from {@code parameters} alone.
     *
     * <p>Nothing is added implicitly — no {@code grant_type}, no client credentials. A JSON mint
     * endpoint is not an OAuth2 token endpoint and has its own field names, so anything it needs in
     * the body goes in {@code parameters} verbatim. Credentials still work through
     * {@code clientAuthMethod}, which is a header concern and orthogonal to the body format.
     *
     * <p>Serialised by Jackson rather than string-concatenated so that quotes, backslashes and
     * control characters in a resolved value cannot break out of their JSON string.
     */
    Single<String> buildJsonBody(HttpPlainExecutionContext ctx) {
        var parameters = configuration.getParameters();
        if (parameters == null || parameters.isEmpty()) {
            return Single.fromCallable(() -> MAPPER.createObjectNode().toString());
        }
        var names = List.copyOf(parameters.keySet());
        var resolvers = parameters.values().stream().map(expression -> resolve(ctx, expression)).toList();
        return zipResolved(resolvers, values -> {
            var body = MAPPER.createObjectNode();
            for (var i = 0; i < names.size(); i++) {
                body.put(names.get(i), values.get(i));
            }
            return body.toString();
        });
    }

    /**
     * {@code Authorization: Basic base64(urlencode(id) ":" urlencode(secret))}, or empty when
     * credentials belong in the body.
     *
     * <p>The components are form-urlencoded before being joined and encoded, per RFC 6749 §2.3.1 —
     * that is what keeps a secret containing {@code :} unambiguous.
     */
    Maybe<String> buildBasicAuthHeader(HttpPlainExecutionContext ctx) {
        if (!configuration.usesClientSecretBasic()) {
            return Maybe.empty();
        }
        return Single
            .zip(resolve(ctx, configuration.getClientId()), resolve(ctx, configuration.getClientSecret()), (id, secret) -> {
                var credentials = encode(id.orElse("")) + ":" + encode(secret.orElse(""));
                return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            })
            .toMaybe();
    }

    /**
     * Awaits an ordered set of resolutions and hands the combiner a same-order list, in which an
     * element is null when that expression resolved to nothing — which is what a null meant on the
     * synchronous path too.
     */
    private static <R> Single<R> zipResolved(Iterable<Single<Optional<String>>> resolvers, Function<List<String>, R> combiner) {
        return Single.zip(resolvers, resolved -> {
            var values = new ArrayList<String>(resolved.length);
            for (var element : resolved) {
                @SuppressWarnings("unchecked")
                var value = (Optional<String>) element;
                values.add(value.orElse(null));
            }
            return combiner.apply(values);
        });
    }

    private static String encode(String v) {
        return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    // ── HTTP client ───────────────────────────────────────────────────────────

    private HttpClient getHttpClient(HttpPlainExecutionContext ctx) {
        var client = httpClient;
        if (client == null) {
            synchronized (this) {
                client = httpClient;
                if (client == null) {
                    try {
                        client = ctx.getComponent(HttpClient.class);
                    } catch (Exception e) {
                        log.debug("No HttpClient component bound to context, falling back to Vertx: {}", e.toString());
                    }
                    if (client == null) {
                        client = createHttpClient(ctx.getComponent(Vertx.class));
                    }
                    httpClient = client;
                }
            }
        }
        return client;
    }

    /**
     * Creates the Vert.x {@link HttpClient} used for token requests.
     *
     * <p>Compiled against Vert.x 5, where {@code Vertx.createHttpClient()} returns
     * {@code HttpClientAgent} rather than {@code HttpClient}. Because the JVM resolves methods by
     * name <em>and descriptor</em>, this call does not link against the Vert.x 4.5 that APIM 4.11
     * and earlier ship. The plugin loads and the API deploys normally on those gateways, and only
     * then does every request fail here — so translate the linkage error into something that
     * names the actual problem instead of leaving a bare {@code NoSuchMethodError} in the log.
     */
    private static HttpClient createHttpClient(Vertx vertx) {
        try {
            return vertx.createHttpClient();
        } catch (LinkageError e) {
            // LinkageError, not just NoSuchMethodError: resolving this call site on a Vert.x 4
            // runtime can also surface as NoClassDefFoundError, since HttpClientAgent (the
            // Vert.x 5 return type named in the descriptor) does not exist there at all.
            throw new IllegalStateException(
                "Incompatible Gravitee runtime: this plugin (2.x) is built for Vert.x 5 and requires APIM 4.12 or later. " +
                "The gateway appears to be running Vert.x 4 (APIM 4.11 or earlier) — deploy the 0.1.x line of the plugin instead.",
                e
            );
        }
    }

    private record TokenInfo(String accessToken, int ttl) {}

    /** Everything the token POST needs, once every deferred value behind it has resolved. */
    private record TokenRequest(Optional<String> endpoint, String body, Optional<String> basicAuth) {}

    private record CachedToken(Object key, Object value, int timeToLive) implements Element {}

    private static final class TokenExchangeException extends RuntimeException {

        final int statusCode;
        final String responseBody;

        TokenExchangeException(int statusCode, String responseBody) {
            super("Token exchange failed (" + statusCode + ")");
            this.statusCode = statusCode;
            this.responseBody = responseBody;
        }
    }
}
