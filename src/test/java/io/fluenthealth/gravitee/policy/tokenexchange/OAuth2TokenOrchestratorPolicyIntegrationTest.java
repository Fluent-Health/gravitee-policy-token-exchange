package io.fluenthealth.gravitee.policy.tokenexchange;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
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
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@WireMockTest(httpPort = 8089)
public class OAuth2TokenOrchestratorPolicyIntegrationTest {

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

    private Vertx vertx;
    private HttpClient httpClient;
    private OAuth2TokenOrchestratorPolicyConfiguration configuration;

    @BeforeEach
    public void setUp() {
        vertx = Vertx.vertx();
        httpClient = vertx.createHttpClient();
        configuration = new OAuth2TokenOrchestratorPolicyConfiguration();
        configuration.setCacheResource("test-cache");
        configuration.setTokenEndpoint("http://localhost:8089/token");
        configuration.setGrantType("token_exchange");

        when(executionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(configuration.getCacheResource(), CacheResource.class)).thenReturn(cacheResource);
        when(cacheResource.getCache(executionContext)).thenReturn(cache);
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.getValue(any(), eq(String.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(executionContext.getComponent(HttpClient.class)).thenReturn(httpClient);
        
        HttpHeaders requestHeaders = HttpHeaders.create();
        when(request.headers()).thenReturn(requestHeaders);
    }

    @AfterEach
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldExchangeTokenOnCacheMiss() throws InterruptedException {
        stubFor(post(urlEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"new-token\", \"expires_in\":3600}")));

        when(cache.get(any())).thenReturn(null);

        CountDownLatch latch = new CountDownLatch(1);
        doAnswer(invocation -> {
            latch.countDown();
            return null;
        }).when(policyChain).doNext(any(), any());

        OAuth2TokenOrchestratorPolicy policy = new OAuth2TokenOrchestratorPolicy(configuration);
        policy.onRequest(request, response, executionContext, policyChain);

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        Mockito.verify(cache).put(any());
        assertEquals("Bearer new-token", request.headers().getFirst("Authorization"));
    }

    @Test
    public void shouldFailOnIdpError() throws InterruptedException {
        stubFor(post(urlEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withBody("{\"error\":\"invalid_grant\"}")));

        when(cache.get(any())).thenReturn(null);

        CountDownLatch latch = new CountDownLatch(1);
        doAnswer(invocation -> {
            latch.countDown();
            return null;
        }).when(policyChain).failWith(any());

        OAuth2TokenOrchestratorPolicy policy = new OAuth2TokenOrchestratorPolicy(configuration);
        policy.onRequest(request, response, executionContext, policyChain);

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        Mockito.verify(policyChain).failWith(Mockito.argThat(result -> result.statusCode() == 401));
    }
}
