package io.fluenthealth.gravitee.policy.tokenexchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import io.reactivex.rxjava3.core.Maybe;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2TokenOrchestratorPolicyTest {

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

    @Mock
    Element cachedElement;

    HttpHeaders headers;
    OAuth2TokenOrchestratorPolicyConfiguration configuration;
    OAuth2TokenOrchestratorPolicy policy;

    @BeforeEach
    void setUp() {
        headers = HttpHeaders.create();
        configuration = new OAuth2TokenOrchestratorPolicyConfiguration();
        configuration.setCacheResource("test-cache");
        configuration.setTokenEndpoint("http://idp/token");
        configuration.setGrantType("client_credentials");
        policy = new OAuth2TokenOrchestratorPolicy(configuration);

        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);
        when(ctx.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);
        // eval, not getValue: the synchronous entry points cannot resolve a deferred value.
        when(templateEngine.<String>eval(any(String.class), eq(String.class))).thenAnswer(inv -> Maybe.just(inv.getArgument(0)));
    }

    @Test
    void interruptsWith500WhenCacheResourceMissing() {
        when(resourceManager.getResource("test-cache", CacheResource.class)).thenReturn(null);
        when(ctx.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.error(new RuntimeException("interrupted")));

        policy.onRequest(ctx).test().assertError(RuntimeException.class);

        verify(ctx)
            .interruptWith(
                org.mockito.ArgumentMatchers.argThat(f -> f.statusCode() == 500 && f.message().contains("test-cache"))
            );
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    void servesCachedTokenWithoutExchange() {
        when(resourceManager.getResource("test-cache", CacheResource.class)).thenReturn((CacheResource) cacheResource);
        when(((CacheResource) cacheResource).getCache(ctx)).thenReturn(cache);
        headers.set("Authorization", "Bearer inbound");
        when(cache.get(any())).thenReturn(cachedElement);
        when(cachedElement.value()).thenReturn("cached-access-token");

        policy.onRequest(ctx).test().assertComplete().assertNoErrors();

        assertThat(headers.get("Authorization")).isEqualTo("Bearer cached-access-token");
        verify(cache, never()).put(any());
        verify(ctx, never()).interruptWith(any());
    }
}
