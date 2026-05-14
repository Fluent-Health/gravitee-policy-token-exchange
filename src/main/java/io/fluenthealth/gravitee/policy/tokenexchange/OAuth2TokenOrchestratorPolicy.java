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
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OAuth2 Token Orchestrator Policy.
 *
 * <p>Exchanges the inbound bearer token via an IDP token endpoint and caches the result in a
 * Gravitee {@link CacheResource}. Cache TTL is derived from the OAuth2 response (the
 * {@code expires_in} field or, failing that, the JWT {@code exp} claim).
 */
// TemplateEngine.getValue is deprecated in newer EL releases (replaced by evalNow). The version
// of gravitee-expression-language pulled transitively by gateway-api 3.13.0 does not yet expose
// evalNow, and the only non-deprecated alternative is the reactive Maybe<T> eval(...). Revisit
// when the gateway-api version is bumped past EL 4.x.
@SuppressWarnings({ "deprecation", "removal" })
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
            var cacheKey = resolveCacheKey(ctx);
            var cached = cache.get(cacheKey);
            if (cached != null && cached.value() != null) {
                log.debug("Cache hit for key [{}]", cacheKey);
                ctx.request().headers().set(AUTHORIZATION, BEARER_PREFIX + cached.value());
                return Completable.complete();
            }

            log.debug("Cache miss for key [{}]", cacheKey);
            return doExchange(ctx, cache, cacheKey);
        });
    }

    private String resolveCacheKey(HttpPlainExecutionContext ctx) {
        var expression = configuration.getCacheKey();
        if (expression != null && !expression.isEmpty()) {
            try {
                var resolved = ctx.getTemplateEngine().getValue(expression, String.class);
                if (resolved != null && !resolved.isEmpty()) {
                    return resolved;
                }
            } catch (Exception e) {
                log.debug("Failed to resolve cache key expression [{}]: {}", expression, e.toString());
            }
        }
        var authHeader = ctx.request().headers().get(AUTHORIZATION);
        return authHeader != null ? "u_" + Integer.toHexString(authHeader.hashCode()) : "anon_token";
    }

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
                    // detailed messages, mirroring policy-http-callout's #calloutResponse.*
                    ctx.putAttribute(ATTR_RESPONSE_STATUS, te.statusCode);
                    ctx.putAttribute(ATTR_RESPONSE_CONTENT, te.responseBody);
                    return ctx.interruptWith(
                        new ExecutionFailure(configuration.getErrorStatusCode()).message(resolveValue(ctx, configuration.getErrorContent()))
                    );
                }
                log.warn("Token exchange failed: {}", t.toString());
                return ctx.interruptWith(new ExecutionFailure(502).message("Token exchange failed"));
            });
    }

    private Single<TokenInfo> requestToken(HttpPlainExecutionContext ctx) {
        var endpoint = resolveValue(ctx, configuration.getTokenEndpoint());
        var body = buildFormBody(ctx);
        var traceparent = ctx.request().headers().get("traceparent");

        return Single.create(emitter -> {
            URI uri;
            try {
                uri = URI.create(endpoint);
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
                    req.putHeader("Content-Type", "application/x-www-form-urlencoded");
                    req.putHeader("Content-Length", String.valueOf(body.length()));
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
                                        var accessToken = node.path("access_token").asText(null);
                                        if (accessToken == null) {
                                            emitter.onError(new RuntimeException("Missing access_token in IDP response"));
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

    private int extractTtl(JsonNode node, String accessToken) {
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

    private String resolveValue(HttpPlainExecutionContext ctx, String expression) {
        if (expression == null) {
            return null;
        }
        try {
            return ctx.getTemplateEngine().getValue(expression, String.class);
        } catch (Exception e) {
            return expression;
        }
    }

    private String buildFormBody(HttpPlainExecutionContext ctx) {
        var params = new LinkedHashMap<String, String>();
        params.put("grant_type", configuration.getGrantType());

        var engine = ctx.getTemplateEngine();
        if (configuration.getClientId() != null) {
            params.put("client_id", engine.getValue(configuration.getClientId(), String.class));
        }
        if (configuration.getClientSecret() != null) {
            params.put("client_secret", engine.getValue(configuration.getClientSecret(), String.class));
        }
        if (configuration.getParameters() != null) {
            configuration.getParameters().forEach((k, v) -> params.put(k, engine.getValue(v, String.class)));
        }

        return params
            .entrySet()
            .stream()
            .map(e -> encode(e.getKey()) + "=" + (e.getValue() != null ? encode(e.getValue()) : ""))
            .collect(Collectors.joining("&"));
    }

    private static String encode(String v) {
        return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

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
                        client = ctx.getComponent(Vertx.class).createHttpClient();
                    }
                    httpClient = client;
                }
            }
        }
        return client;
    }

    private record TokenInfo(String accessToken, int ttl) {}

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
