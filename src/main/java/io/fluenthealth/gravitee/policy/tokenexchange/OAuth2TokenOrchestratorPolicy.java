package io.fluenthealth.gravitee.policy.tokenexchange;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fluenthealth.gravitee.policy.tokenexchange.configuration.OAuth2TokenOrchestratorPolicyConfiguration;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.Cache;
import io.gravitee.resource.cache.api.CacheResource;
import io.gravitee.resource.cache.api.Element;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuth2TokenOrchestratorPolicy {

    private static final Logger log = LoggerFactory.getLogger(OAuth2TokenOrchestratorPolicy.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final OAuth2TokenOrchestratorPolicyConfiguration configuration;

    public OAuth2TokenOrchestratorPolicy(OAuth2TokenOrchestratorPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext context, PolicyChain policyChain) {
        var cacheResource = getCacheResource(context);
        if (cacheResource == null) {
            policyChain.failWith(PolicyResult.failure(500, "Cache resource [" + configuration.getCacheResource() + "] not found"));
            return;
        }

        var cache = cacheResource.getCache(context);
        var cacheKey = context.getTemplateEngine().getValue(configuration.getCacheKey(), String.class);

        var cachedToken = cache.get(cacheKey);
        if (cachedToken != null) {
            Object finalToken = cachedToken;
            if (cachedToken instanceof io.gravitee.resource.cache.api.Element element) {
                finalToken = element.value();
            }
            request.headers().set("Authorization", "Bearer " + finalToken);
            policyChain.doNext(request, response);
            return;
        }

        // Cache miss -> perform token exchange
        doExchange(request, response, context, policyChain, cache, cacheKey);
    }

    private void doExchange(Request request, Response response, ExecutionContext context, PolicyChain policyChain, Cache cache, String cacheKey) {
        var httpClient = context.getComponent(HttpClient.class);
        var tokenEndpoint = context.getTemplateEngine().getValue(configuration.getTokenEndpoint(), String.class);
        
        var body = buildFormBody(context);

        try {
            var url = new URL(tokenEndpoint);
            var secure = "https".equalsIgnoreCase(url.getProtocol());
            var port = url.getPort() != -1 ? url.getPort() : (secure ? 443 : 80);

            var options = new RequestOptions()
                .setMethod(HttpMethod.POST)
                .setHost(url.getHost())
                .setPort(port)
                .setURI(url.getFile())
                .setSsl(secure);

            httpClient.request(options)
                .onFailure(t -> {
                    log.error("Token exchange request creation failed", t);
                    policyChain.failWith(PolicyResult.failure(502, "Token exchange connection failed: " + t.getMessage()));
                })
                .onSuccess(req -> {
                    req.putHeader("Content-Type", "application/x-www-form-urlencoded");
                    req.putHeader("Content-Length", String.valueOf(body.length()));
                    
                    // Propagate trace context
                    var traceparent = request.headers().getFirst("traceparent");
                    if (traceparent != null) req.putHeader("traceparent", traceparent);
                    var requestId = request.headers().getFirst("X-Request-ID");
                    if (requestId != null) req.putHeader("X-Request-ID", requestId);

                    req.send(body)
                        .onFailure(t -> {
                            log.error("Token exchange execution failed", t);
                            policyChain.failWith(PolicyResult.failure(502, "Token exchange request failed: " + t.getMessage()));
                        })
                        .onSuccess(res -> {
                            if (res.statusCode() >= 200 && res.statusCode() < 300) {
                                res.body().onSuccess(buf -> {
                                    try {
                                        var node = MAPPER.readTree(buf.toString());
                                        var accessToken = node.get("access_token").asText();
                                        var expiresIn = node.has("expires_in") ? node.get("expires_in").asInt() : configuration.getDefaultTtl();

                                        // Store in cache
                                        cache.put(new Element() {
                                            @Override
                                            public Object key() { return cacheKey; }
                                            @Override
                                            public Object value() { return accessToken; }
                                            @Override
                                            public int timeToLive() { return expiresIn; }
                                        });

                                        request.headers().set("Authorization", "Bearer " + accessToken);
                                        policyChain.doNext(request, response);
                                    } catch (Exception e) {
                                        log.error("Failed to parse token response", e);
                                        policyChain.failWith(PolicyResult.failure(502, "Failed to parse token response: " + e.getMessage()));
                                    }
                                }).onFailure(t -> {
                                    log.error("Failed to read token response body", t);
                                    policyChain.failWith(PolicyResult.failure(502, "Failed to read token response body: " + t.getMessage()));
                                });
                            } else {
                                res.body().onSuccess(buf -> {
                                    log.warn("Token exchange failed with status {}: {}", res.statusCode(), buf.toString());
                                    var errorMsg = context.getTemplateEngine().getValue(configuration.getErrorContent(), String.class);
                                    policyChain.failWith(PolicyResult.failure(configuration.getErrorStatusCode(), errorMsg));
                                }).onFailure(t -> {
                                    log.error("Token exchange failed and body read failed", t);
                                    policyChain.failWith(PolicyResult.failure(configuration.getErrorStatusCode(), "Token exchange failed with status " + res.statusCode()));
                                });
                            }
                        });
                });
        } catch (Exception e) {
            log.error("Invalid token endpoint URL: {}", tokenEndpoint, e);
            policyChain.failWith(PolicyResult.failure(500, "Invalid token endpoint URL: " + e.getMessage()));
        }
    }

    private String buildFormBody(ExecutionContext context) {
        var params = new HashMap<String, String>();
        params.put("grant_type", configuration.getGrantType());
        if (configuration.getClientId() != null) {
            params.put("client_id", context.getTemplateEngine().getValue(configuration.getClientId(), String.class));
        }
        if (configuration.getClientSecret() != null) {
            params.put("client_secret", context.getTemplateEngine().getValue(configuration.getClientSecret(), String.class));
        }

        if (configuration.getParameters() != null) {
            for (var entry : configuration.getParameters().entrySet()) {
                params.put(entry.getKey(), context.getTemplateEngine().getValue(entry.getValue(), String.class));
            }
        }

        return params.entrySet().stream()
            .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
    }

    private CacheResource getCacheResource(ExecutionContext context) {
        return context.getComponent(ResourceManager.class).getResource(configuration.getCacheResource(), CacheResource.class);
    }
}
