package io.fluenthealth.gravitee.policy.tokenexchange.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import java.util.Map;

public class OAuth2TokenOrchestratorPolicyConfiguration implements PolicyConfiguration {

    /** {@code form} sends {@code application/x-www-form-urlencoded}; {@code json} sends a JSON object. */
    public static final String FORMAT_FORM = "form";

    public static final String FORMAT_JSON = "json";

    /** Credentials in the request body (RFC 6749 §2.3.1 "client_secret_post"). */
    public static final String AUTH_CLIENT_SECRET_POST = "client_secret_post";

    /** Credentials in an {@code Authorization: Basic} header (RFC 6749 §2.3.1 "client_secret_basic"). */
    public static final String AUTH_CLIENT_SECRET_BASIC = "client_secret_basic";

    public static final String DEFAULT_TOKEN_PATH = "access_token";

    private String cacheResource;
    private String tokenEndpoint;
    private String grantType;
    private String clientId;
    private String clientSecret;
    private String cacheKey = "{#context.attributes['jwt.claims']['sub']}";
    private int defaultTtl = 3600;
    private int errorStatusCode = 401;
    private String errorContent = "{\"message\": \"Token exchange failed\"}";
    private Map<String, String> parameters;
    private String clientAuthMethod = AUTH_CLIENT_SECRET_POST;
    private String requestFormat = FORMAT_FORM;
    private String tokenPath = DEFAULT_TOKEN_PATH;

    /**
     * Upper bound on the cache TTL, in seconds. {@code 0} (the default) means no bound, leaving the
     * TTL exactly as derived from the response.
     *
     * <p>Worth setting when the provider issues a long-lived token but the credential behind it can
     * be rotated: the derived TTL follows the token's own lifetime, so without a bound a rotated
     * secret stays unused until the cached token finally expires.
     */
    private int maxTtl = 0;

    public String getCacheResource() {
        return cacheResource;
    }

    public void setCacheResource(String cacheResource) {
        this.cacheResource = cacheResource;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getCacheKey() {
        return cacheKey;
    }

    public void setCacheKey(String cacheKey) {
        this.cacheKey = cacheKey;
    }

    public int getDefaultTtl() {
        return defaultTtl;
    }

    public void setDefaultTtl(int defaultTtl) {
        this.defaultTtl = defaultTtl;
    }

    public int getErrorStatusCode() {
        return errorStatusCode;
    }

    public void setErrorStatusCode(int errorStatusCode) {
        this.errorStatusCode = errorStatusCode;
    }

    public String getErrorContent() {
        return errorContent;
    }

    public void setErrorContent(String errorContent) {
        this.errorContent = errorContent;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    public String getClientAuthMethod() {
        return clientAuthMethod;
    }

    public void setClientAuthMethod(String clientAuthMethod) {
        this.clientAuthMethod = clientAuthMethod;
    }

    public String getRequestFormat() {
        return requestFormat;
    }

    public void setRequestFormat(String requestFormat) {
        this.requestFormat = requestFormat;
    }

    public String getTokenPath() {
        return tokenPath;
    }

    public void setTokenPath(String tokenPath) {
        this.tokenPath = tokenPath;
    }

    public int getMaxTtl() {
        return maxTtl;
    }

    public void setMaxTtl(int maxTtl) {
        this.maxTtl = maxTtl;
    }

    /** True when credentials belong in an {@code Authorization: Basic} header rather than the body. */
    public boolean usesClientSecretBasic() {
        return AUTH_CLIENT_SECRET_BASIC.equalsIgnoreCase(clientAuthMethod);
    }

    /** True when the token request body is a JSON object rather than a form encoding. */
    public boolean usesJsonRequestFormat() {
        return FORMAT_JSON.equalsIgnoreCase(requestFormat);
    }
}
