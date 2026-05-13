# OAuth2 Token Orchestrator Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Gravitee APIM policy plugin that orchestrates the "Cache -> Token Request -> Cache Store -> Header Injection" lifecycle for RFC 8693 and Zoho OAuth2 flows.

**Architecture:** A Java-based Gravitee policy that executes in the Request phase. It uses the asynchronous Vert.x `HttpClient` for token requests and the Gravitee `CacheResource` for multi-node token persistence. It consolidates multiple built-in policies into a single optimized unit.

**Tech Stack:** Java 21, Maven, Gravitee APIM Gateway API, Vert.x, JUnit 5, Mockito, WireMock, TestContainers (Redis).

---

## File Map

```
pom.xml
src/main/resources/
  plugin.properties
  gravitee.json
src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/
  OAuth2TokenOrchestratorPolicy.java
  configuration/OAuth2TokenOrchestratorPolicyConfiguration.java
src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/
  OAuth2TokenOrchestratorPolicyTest.java
  OAuth2TokenOrchestratorPolicyIntegrationTest.java
```

---

## Task 1: Maven Scaffold + build files

**Files:**
- Create: `pom.xml`
- Create: `src/main/resources/plugin.properties`
- Create: `src/main/resources/gravitee.json`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/configuration
mkdir -p src/test/java/io/fluenthealth/gravitee/policy/tokenexchange
mkdir -p src/main/resources
```

- [ ] **Step 2: Create `pom.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>io.fluenthealth.gravitee.policy</groupId>
    <artifactId>gravitee-policy-token-exchange</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <name>Fluent Health - Gravitee Policy - OAuth2 Token Orchestrator</name>
    <description>Consolidated OAuth2 token exchange and caching policy</description>

    <properties>
        <maven.compiler.release>21</maven.compiler.release>
        <gravitee-policy-api.version>1.11.0</gravitee-policy-api.version>
        <gravitee-gateway-api.version>4.0.1</gravitee-gateway-api.version>
        <gravitee-common.version>4.2.0</gravitee-common.version>
        <jackson-databind.version>2.17.1</jackson-databind.version>
        <junit-jupiter.version>5.10.2</junit-jupiter.version>
        <mockito.version>5.11.0</mockito.version>
        <wiremock.version>3.5.4</wiremock.version>
    </properties>

    <dependencies>
        <!-- Gravitee API (Provided) -->
        <dependency>
            <groupId>io.gravitee.policy</groupId>
            <artifactId>gravitee-policy-api</artifactId>
            <version>${gravitee-policy-api.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>io.gravitee.gateway</groupId>
            <artifactId>gravitee-gateway-api</artifactId>
            <version>${gravitee-gateway-api.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>io.gravitee.common</groupId>
            <artifactId>gravitee-common</artifactId>
            <version>${gravitee-common.version}</version>
            <scope>provided</scope>
        </dependency>

        <!-- JSON -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>${jackson-databind.version}</version>
            <scope>provided</scope>
        </dependency>

        <!-- Test -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-engine</artifactId>
            <version>${junit-jupiter.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-junit-jupiter</artifactId>
            <version>${mockito.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.assertj</groupId>
            <artifactId>assertj-core</artifactId>
            <version>3.25.3</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.13.0</version>
                <configuration>
                    <release>${maven.compiler.release}</release>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

- [ ] **Step 3: Create `src/main/resources/plugin.properties`**

```properties
id=oauth2-token-orchestrator
name=OAuth2 Token Orchestrator
description=Consolidated OAuth2 token exchange and caching policy
class=io.fluenthealth.gravitee.policy.tokenexchange.OAuth2TokenOrchestratorPolicy
type=policy
```

- [ ] **Step 4: Create `src/main/resources/gravitee.json`**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "title": "OAuth2 Token Orchestrator",
  "description": "Consolidated OAuth2 token exchange and caching policy",
  "properties": {
    "cacheResource": {
      "type": "string",
      "title": "Cache Resource",
      "description": "Name of the Gravitee Cache Resource to use."
    },
    "tokenEndpoint": {
      "type": "string",
      "title": "Token Endpoint",
      "description": "The full URL to the OAuth2 provider token endpoint."
    },
    "grantType": {
      "type": "string",
      "title": "Grant Type",
      "description": "The OAuth2 grant_type (e.g., urn:ietf:params:oauth:grant-type:token-exchange)."
    },
    "clientId": {
      "type": "string",
      "title": "Client ID"
    },
    "clientSecret": {
      "type": "string",
      "title": "Client Secret"
    },
    "cacheKey": {
      "type": "string",
      "title": "Cache Key Expression",
      "default": "{#context.attributes['jwt.claims']['sub']}"
    },
    "defaultTtl": {
      "type": "integer",
      "title": "Default TTL (seconds)",
      "default": 3600
    },
    "errorStatusCode": {
      "type": "integer",
      "title": "Error Status Code",
      "default": 401
    },
    "errorContent": {
      "type": "string",
      "title": "Error Content",
      "default": "{\"message\": \"Token exchange failed\"}"
    },
    "exitOnError": {
      "type": "boolean",
      "title": "Exit on Error",
      "default": true
    },
    "parameters": {
      "type": "object",
      "title": "Additional Parameters",
      "additionalProperties": {
        "type": "string"
      }
    }
  },
  "required": ["cacheResource", "tokenEndpoint", "grantType"]
}
```

- [ ] **Step 5: Verify build**

Run: `mvn compile`
Expected: `BUILD SUCCESS`

- [ ] **Step 6: Commit**

```bash
git add pom.xml src/main/resources/
git commit -m "chore: initial maven scaffold and plugin descriptors"
```

---

## Task 2: Configuration Class

**Files:**
- Create: `src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/configuration/OAuth2TokenOrchestratorPolicyConfiguration.java`

- [ ] **Step 1: Implement the configuration class**

```java
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
```

- [ ] **Step 2: Verify build**

Run: `mvn compile`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: Commit**

```bash
git add src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/configuration/
git commit -m "feat: add policy configuration class"
```

---

## Task 3: Policy Skeleton + Cache Lookup Logic

**Files:**
- Create: `src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicy.java`
- Create: `src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicyTest.java`

- [ ] **Step 1: Create the failing unit test for cache lookup**

```java
package io.fluenthealth.gravitee.policy.tokenexchange;

import io.fluenthealth.gravitee.policy.tokenexchange.configuration.OAuth2TokenOrchestratorPolicyConfiguration;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OAuth2TokenOrchestratorPolicyTest {

    @Mock
    private ExecutionContext executionContext;
    @Mock
    private Request request;
    @Mock
    private Response response;
    @Mock
    private PolicyChain policyChain;

    private OAuth2TokenOrchestratorPolicyConfiguration configuration;

    @BeforeEach
    public void setUp() {
        configuration = new OAuth2TokenOrchestratorPolicyConfiguration();
        configuration.setCacheResource("test-cache");
    }

    @Test
    public void shouldFailIfCacheResourceNotFound() {
        when(executionContext.getComponent(any())).thenReturn(null);
        OAuth2TokenOrchestratorPolicy policy = new OAuth2TokenOrchestratorPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain).failWith(argThat(result -> result.statusCode() == 500));
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `mvn test -Dtest=OAuth2TokenOrchestratorPolicyTest`
Expected: FAIL (Compilation error - Policy class missing)

- [ ] **Step 3: Implement Policy Skeleton and Cache Resolution**

```java
package io.fluenthealth.gravitee.policy.tokenexchange;

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

public class OAuth2TokenOrchestratorPolicy {

    private final OAuth2TokenOrchestratorPolicyConfiguration configuration;

    public OAuth2TokenOrchestratorPolicy(OAuth2TokenOrchestratorPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext context, PolicyChain policyChain) {
        CacheResource cacheResource = getCacheResource(context);
        if (cacheResource == null) {
            policyChain.failWith(PolicyResult.failure("Cache resource [" + configuration.getCacheResource() + "] not found", 500));
            return;
        }

        Cache cache = cacheResource.getCache(context);
        String cacheKey = context.getTemplateEngine().getValue(configuration.getCacheKey(), String.class);

        // TODO: Proceed with lookup
        policyChain.doNext(request, response);
    }

    private CacheResource getCacheResource(ExecutionContext context) {
        return context.getComponent(ResourceManager.class).getResource(configuration.getCacheResource(), CacheResource.class);
    }
}
```

- [ ] **Step 4: Update test and verify pass**

Update test `shouldFailIfCacheResourceNotFound` to mock `ResourceManager` component.

Run: `mvn test -Dtest=OAuth2TokenOrchestratorPolicyTest`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicy.java \
        src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicyTest.java
git commit -m "feat: add policy skeleton and cache resource resolution"
```

---

## Task 4: Token Request (Callout) Implementation

**Files:**
- Modify: `src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicy.java`
- Modify: `src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicyTest.java`

- [ ] **Step 1: Write test for OAuth2 body construction**

Add a test that verifies the `application/x-www-form-urlencoded` body is built correctly from `grantType` and `parameters`.

- [ ] **Step 2: Implement HTTP Callout logic using `HttpClient`**

Update `onRequest` to check the cache. On miss, use `context.getComponent(HttpClient.class)` to perform the POST request. Ensure all values in the `parameters` map are evaluated via the `TemplateEngine` before inclusion in the form-encoded body.

- [ ] **Step 3: Parse JSON Response**

Implement parsing of `access_token` and `expires_in` using Jackson.

- [ ] **Step 4: Verify with Unit Tests**

- [ ] **Step 5: Commit**

```bash
git add src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicy.java
git commit -m "feat: implement oauth2 callout and response parsing"
```

---

## Task 5: Cache Update and Header Injection

**Files:**
- Modify: `src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicy.java`

- [ ] **Step 1: Implement Cache SET**

On successful response, put the token in the `Cache` using the resolved `cacheKey` and `expires_in` (falling back to `defaultTtl`).

- [ ] **Step 2: Implement Header Injection**

Set `Authorization: Bearer <token>` on the `request` object before calling `policyChain.doNext()`.

- [ ] **Step 3: Implement Error Handling**

Use `configuration.getErrorStatusCode()` and `configuration.getErrorContent()` (evaluating EL) when the callout fails.

- [ ] **Step 4: Verify with tests**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat: implement cache update and authorization header injection"
```

---

## Task 6: End-to-End Testing (WireMock)

**Files:**
- Create: `src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicyIntegrationTest.java`

- [ ] **Step 1: Set up WireMock to simulate an IDP**

- [ ] **Step 2: Write integration tests**
    *   Scenario: Cache Miss -> IDP Call -> Cache Hit -> Upstream Header set.
    *   Scenario: IDP Error -> Policy Failure.

- [ ] **Step 3: Run integration tests**

Run: `mvn verify`
Expected: `BUILD SUCCESS`

- [ ] **Step 4: Commit**

```bash
git add src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicyIntegrationTest.java
git commit -m "test: add integration tests with wiremock"
```

---

## Task 7: Trace Context Integration

**Files:**
- Modify: `src/main/java/io/fluenthealth/gravitee/policy/tokenexchange/OAuth2TokenOrchestratorPolicy.java`

- [ ] **Step 1: Implement Header Propagation**

Update the callout request to copy `traceparent` and `X-Request-ID` headers from the inbound request to the token provider request.

- [ ] **Step 2: Write test to verify propagation**

- [ ] **Step 3: Commit**

```bash
git commit -am "feat: propagate trace context headers to token provider"
```
