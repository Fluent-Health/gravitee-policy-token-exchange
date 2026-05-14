package io.fluenthealth.gravitee.policy.tokenexchange;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.fluenthealth.gravitee.policy.tokenexchange.configuration.OAuth2TokenOrchestratorPolicyConfiguration;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.Cache;
import io.gravitee.resource.cache.api.CacheResource;
import io.gravitee.resource.cache.api.Element;
import io.reactivex.rxjava3.core.Completable;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@WireMockTest(httpPort = 8089)
@SuppressWarnings({ "deprecation", "removal" })
class OAuth2TokenOrchestratorPolicyIntegrationTest {

    @Mock
    HttpPlainExecutionContext ctx;

    @Mock
    HttpPlainRequest request;

    @Mock
    ResourceManager resourceManager;

    @Mock
    TemplateEngine templateEngine;

    @Mock
    CacheResource<?> cacheResource;

    @Mock
    Cache cache;

    Vertx vertx;
    HttpClient httpClient;
    HttpHeaders headers;
    OAuth2TokenOrchestratorPolicyConfiguration configuration;
    OAuth2TokenOrchestratorPolicy policy;

    @BeforeEach
    @SuppressWarnings({ "rawtypes", "unchecked" })
    void setUp() {
        vertx = Vertx.vertx();
        httpClient = vertx.createHttpClient();
        headers = HttpHeaders.create();

        configuration = new OAuth2TokenOrchestratorPolicyConfiguration();
        configuration.setCacheResource("test-cache");
        configuration.setTokenEndpoint("http://localhost:8089/token");
        configuration.setGrantType("token_exchange");
        policy = new OAuth2TokenOrchestratorPolicy(configuration);

        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.getValue(any(String.class), eq(String.class))).thenAnswer(inv -> inv.getArgument(0));
        when(ctx.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(ctx.getComponent(HttpClient.class)).thenReturn(httpClient);
        when(resourceManager.getResource("test-cache", CacheResource.class)).thenReturn((CacheResource) cacheResource);
        when(((CacheResource) cacheResource).getCache(ctx)).thenReturn(cache);
    }

    @AfterEach
    void tearDown() {
        vertx.close();
    }

    @Test
    void exchangesAndCachesOnCacheMiss() {
        stubFor(
            post(urlEqualTo("/token"))
                .willReturn(
                    aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"new-token\",\"expires_in\":3600}")
                )
        );
        when(cache.get(any())).thenReturn(null);

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete().assertNoErrors();

        assertThat(headers.get("Authorization")).isEqualTo("Bearer new-token");
        var captor = ArgumentCaptor.forClass(Element.class);
        verify(cache).put(captor.capture());
        assertThat(captor.getValue().value()).isEqualTo("new-token");
        assertThat(captor.getValue().timeToLive()).isEqualTo(3600);
    }

    @Test
    void interruptsWithConfiguredErrorOnIdpFailure() {
        stubFor(post(urlEqualTo("/token")).willReturn(aResponse().withStatus(400).withBody("{\"error\":\"invalid_grant\"}")));
        when(cache.get(any())).thenReturn(null);
        when(ctx.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.error(new RuntimeException("interrupted")));

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertError(RuntimeException.class);

        verify(ctx).interruptWith(org.mockito.ArgumentMatchers.argThat(f -> f.statusCode() == configuration.getErrorStatusCode()));
    }

    @Test
    void exposesIdpResponseAsContextAttributesBeforeResolvingErrorContent() {
        stubFor(post(urlEqualTo("/token")).willReturn(aResponse().withStatus(403).withBody("{\"error\":\"invalid_client\"}")));
        when(cache.get(any())).thenReturn(null);
        when(ctx.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.error(new RuntimeException("interrupted")));

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertError(RuntimeException.class);

        verify(ctx).putAttribute(OAuth2TokenOrchestratorPolicy.ATTR_RESPONSE_STATUS, 403);
        verify(ctx).putAttribute(OAuth2TokenOrchestratorPolicy.ATTR_RESPONSE_CONTENT, "{\"error\":\"invalid_client\"}");
    }
}
