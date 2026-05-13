package io.fluenthealth.gravitee.policy.tokenexchange.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import java.util.Map;

public class OAuth2TokenOrchestratorPolicyConfiguration implements PolicyConfiguration {

    private String cacheResource;
    private String tokenEndpoint;
    private String grantType;
    private String clientId;
    private String clientSecret;
    private String cacheKey = "{#context.attributes['jwt.claims']['sub']}";
    private int defaultTtl = 3600;
    private int errorStatusCode = 401;
    private String errorContent = "{\"message\": \"Token exchange failed\"}";
    private boolean exitOnError = true;
    private Map<String, String> parameters;

    // Getters and Setters
    public String getCacheResource() { return cacheResource; }
    public void setCacheResource(String cacheResource) { this.cacheResource = cacheResource; }
    public String getTokenEndpoint() { return tokenEndpoint; }
    public void setTokenEndpoint(String tokenEndpoint) { this.tokenEndpoint = tokenEndpoint; }
    public String getGrantType() { return grantType; }
    public void setGrantType(String grantType) { this.grantType = grantType; }
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    public String getCacheKey() { return cacheKey; }
    public void setCacheKey(String cacheKey) { this.cacheKey = cacheKey; }
    public int getDefaultTtl() { return defaultTtl; }
    public void setDefaultTtl(int defaultTtl) { this.defaultTtl = defaultTtl; }
    public int getErrorStatusCode() { return errorStatusCode; }
    public void setErrorStatusCode(int errorStatusCode) { this.errorStatusCode = errorStatusCode; }
    public String getErrorContent() { return errorContent; }
    public void setErrorContent(String errorContent) { this.errorContent = errorContent; }
    public boolean isExitOnError() { return exitOnError; }
    public void setExitOnError(boolean exitOnError) { this.exitOnError = exitOnError; }
    public Map<String, String> getParameters() { return parameters; }
    public void setParameters(Map<String, String> parameters) { this.parameters = parameters; }
}
