package io.fluenthealth.gravitee.policy.tokenexchange;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.github.tomakehurst.wiremock.client.WireMock;
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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
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

    // ── Client authentication method ──────────────────────────────────────────

    /**
     * The default must stay byte-identical to what shipped before the option existed — every
     * deployed configuration relies on it.
     */
    @Test
    void defaultsToClientSecretPostWithCredentialsInTheFormBody() {
        stubToken("{\"access_token\":\"t\",\"expires_in\":60}");
        configuration.setClientId("the-client");
        configuration.setClientSecret("the-secret");

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        WireMock.verify(
            postRequestedFor(urlEqualTo("/token"))
                .withHeader("Content-Type", equalTo("application/x-www-form-urlencoded"))
                .withoutHeader("Authorization")
                .withRequestBody(equalTo("grant_type=token_exchange&client_id=the-client&client_secret=the-secret"))
        );
    }

    @Test
    void clientSecretBasicSendsBasicHeaderAndOmitsCredentialsFromTheBody() {
        stubToken("{\"access_token\":\"t\",\"expires_in\":60}");
        configuration.setClientAuthMethod("client_secret_basic");
        configuration.setClientId("the-client");
        configuration.setClientSecret("the-secret");

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        var expected = "Basic " + Base64.getEncoder().encodeToString("the-client:the-secret".getBytes(StandardCharsets.UTF_8));
        WireMock.verify(
            postRequestedFor(urlEqualTo("/token"))
                .withHeader("Authorization", equalTo(expected))
                .withRequestBody(equalTo("grant_type=token_exchange"))
        );
    }

    /** RFC 6749 §2.3.1: components are form-urlencoded before joining, so a ':' stays unambiguous. */
    @Test
    void clientSecretBasicUrlEncodesCredentialComponents() {
        stubToken("{\"access_token\":\"t\",\"expires_in\":60}");
        configuration.setClientAuthMethod("client_secret_basic");
        configuration.setClientId("id with space");
        configuration.setClientSecret("secret:with/colon");

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        var expected =
            "Basic " + Base64.getEncoder().encodeToString("id+with+space:secret%3Awith%2Fcolon".getBytes(StandardCharsets.UTF_8));
        WireMock.verify(postRequestedFor(urlEqualTo("/token")).withHeader("Authorization", equalTo(expected)));
    }

    // ── JSON request format ──────────────────────────────────────────────────

    @Test
    void jsonRequestFormatSendsParametersAsAJsonObjectAndNothingElse() {
        stubToken("{\"accessToken\":\"minted\"}");
        configuration.setRequestFormat("json");
        configuration.setTokenPath("$.accessToken");
        configuration.setClientId("not-in-body");
        configuration.setClientSecret("not-in-body-either");
        configuration.setParameters(new LinkedHashMap<>(Map.of("username", "svc-user")));

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        assertThat(headers.get("Authorization")).isEqualTo("Bearer minted");
        WireMock.verify(
            postRequestedFor(urlEqualTo("/token"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("{\"username\":\"svc-user\"}"))
        );
    }

    /** A quote in a resolved value must not be able to break out of its JSON string. */
    @Test
    void jsonRequestFormatEscapesValues() {
        stubToken("{\"accessToken\":\"minted\"}");
        configuration.setRequestFormat("json");
        configuration.setTokenPath("accessToken");
        configuration.setParameters(new LinkedHashMap<>(Map.of("password", "qu\"ote\\and\nnewline")));

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        WireMock.verify(postRequestedFor(urlEqualTo("/token")).withRequestBody(equalToJson("{\"password\":\"qu\\\"ote\\\\and\\nnewline\"}")));
    }

    /**
     * Content-Length has to be the UTF-8 byte count. With a character count a multi-byte value is
     * truncated server-side, which WireMock surfaces as a body that no longer parses as the JSON sent.
     */
    @Test
    void jsonRequestFormatSendsByteLengthNotCharacterLength() {
        stubToken("{\"accessToken\":\"minted\"}");
        configuration.setRequestFormat("json");
        configuration.setTokenPath("accessToken");
        configuration.setParameters(new LinkedHashMap<>(Map.of("password", "pä§§word-€")));

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        WireMock.verify(postRequestedFor(urlEqualTo("/token")).withRequestBody(equalToJson("{\"password\":\"pä§§word-€\"}")));
    }

    // ── Token path and TTL bound ─────────────────────────────────────────────

    @Test
    void tokenPathWalksNestedFields() {
        stubToken("{\"data\":{\"token\":\"nested\"}}");
        configuration.setTokenPath("data.token");

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        assertThat(headers.get("Authorization")).isEqualTo("Bearer nested");
    }

    @Test
    void failsWhenTheConfiguredTokenPathIsAbsent() {
        stubToken("{\"access_token\":\"wrong-field\"}");
        configuration.setTokenPath("accessToken");
        when(ctx.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.error(new RuntimeException("interrupted")));

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertError(RuntimeException.class);
    }

    /**
     * A long-lived token with a maxTtl bound must be cached for the bound, not its own lifetime —
     * this is what keeps a credential rotation taking effect within a known window.
     */
    @Test
    void maxTtlBoundsTheDerivedTtl() {
        stubToken("{\"access_token\":\"t\",\"expires_in\":86400}");
        configuration.setMaxTtl(3600);

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        var captor = ArgumentCaptor.forClass(Element.class);
        verify(cache).put(captor.capture());
        assertThat(captor.getValue().timeToLive()).isEqualTo(3600);
    }

    @Test
    void maxTtlLeavesAShorterDerivedTtlAlone() {
        stubToken("{\"access_token\":\"t\",\"expires_in\":60}");
        configuration.setMaxTtl(3600);

        policy.onRequest(ctx).test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        var captor = ArgumentCaptor.forClass(Element.class);
        verify(cache).put(captor.capture());
        assertThat(captor.getValue().timeToLive()).isEqualTo(60);
    }

    private void stubToken(String responseBody) {
        stubFor(
            post(urlEqualTo("/token"))
                .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json").withBody(responseBody))
        );
        when(cache.get(any())).thenReturn(null);
    }
}
