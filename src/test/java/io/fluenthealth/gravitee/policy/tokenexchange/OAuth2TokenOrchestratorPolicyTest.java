package io.fluenthealth.gravitee.policy.tokenexchange;

import io.fluenthealth.gravitee.policy.tokenexchange.configuration.OAuth2TokenOrchestratorPolicyConfiguration;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.Cache;
import io.gravitee.resource.cache.api.CacheResource;
import io.gravitee.resource.cache.api.Element;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
public class OAuth2TokenOrchestratorPolicyTest {

    @Mock
    private ExecutionContext executionContext;
    @Mock
    private Request request;
    @Mock
    private Response response;
    @Mock
    private PolicyChain policyChain;
    @Mock
    private ResourceManager resourceManager;
    @Mock
    private TemplateEngine templateEngine;
    @Mock
    private CacheResource cacheResource;
    @Mock
    private Cache cache;
    @Mock
    private Element element;

    private OAuth2TokenOrchestratorPolicyConfiguration configuration;

    @BeforeEach
    public void setUp() {
        configuration = new OAuth2TokenOrchestratorPolicyConfiguration();
        configuration.setCacheResource("test-cache");
    }

    @Test
    public void shouldFailIfCacheResourceNotFound() {
        when(executionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(configuration.getCacheResource(), CacheResource.class)).thenReturn(null);

        OAuth2TokenOrchestratorPolicy policy = new OAuth2TokenOrchestratorPolicy(configuration);
        policy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain).failWith(argThat(result -> result.statusCode() == 500));
    }

    @Test
    public void shouldPerformExchangeOnCacheMiss() {
        String cacheKey = "user123";
        String tokenEndpoint = "http://idp/token";

        when(executionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(configuration.getCacheResource(), CacheResource.class)).thenReturn(cacheResource);
        when(cacheResource.getCache(executionContext)).thenReturn(cache);
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.getValue(configuration.getCacheKey(), String.class)).thenReturn(cacheKey);
        when(cache.get(cacheKey)).thenReturn(null); // MISS

        configuration.setTokenEndpoint(tokenEndpoint);
        configuration.setGrantType("client_credentials");
        when(templateEngine.getValue(tokenEndpoint, String.class)).thenReturn(tokenEndpoint);

        HttpClient httpClient = mock(HttpClient.class);
        when(executionContext.getComponent(HttpClient.class)).thenReturn(httpClient);
        when(httpClient.request(any(io.vertx.core.http.RequestOptions.class))).thenReturn(io.vertx.core.Future.failedFuture("mock-miss"));

        HttpHeaders requestHeaders = HttpHeaders.create();
        when(request.headers()).thenReturn(requestHeaders);

        OAuth2TokenOrchestratorPolicy policy = new OAuth2TokenOrchestratorPolicy(configuration);
        policy.onRequest(request, response, executionContext, policyChain);

        verify(httpClient).request(any(io.vertx.core.http.RequestOptions.class));
    }
}
