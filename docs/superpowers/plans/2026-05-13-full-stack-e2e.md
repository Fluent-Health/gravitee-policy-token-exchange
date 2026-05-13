# Full-Stack Gravitee E2E Testing Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a robust end-to-end integration test using TestContainers that spins up a full Gravitee APIM stack (MongoDB, Management API, Gateway) and WireMock to verify the `OAuth2 Token Orchestrator` policy in a production-like environment.

**Architecture:** 
1. **Container Orchestration:** Spin up a shared Docker network with MongoDB, Gravitee Management API, Gravitee Gateway, and WireMock.
2. **Plugin Injection:** Mount the compiled plugin ZIP directly into the Gateway's `plugins-ext` directory.
3. **API Deployment:** Use the Management API's REST interface to programmatically create and deploy a v4 proxy API that utilizes the new policy.
4. **Execution:** Send a request to the Gateway and verify that the token exchange logic is executed and the downstream request to WireMock contains the expected `Authorization` header.

**Tech Stack:** Java 21, Maven, TestContainers, Gravitee APIM 4.9.13.

---

## File Map

```
src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/integration/
  E2EGatewayIT.java
  ManagementApiHelper.java
```

---

## Task 1: Refactor `E2EGatewayIT.java` for Full Stack

**Files:**
- Modify: `src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/integration/E2EGatewayIT.java`
- Create: `src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/integration/ManagementApiHelper.java`

- [ ] **Step 1: Create `ManagementApiHelper.java`**

Create a helper class to interact with the Management API to deploy our test API.
```java
package io.fluenthealth.gravitee.policy.tokenexchange.integration;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.time.Duration;

public class ManagementApiHelper {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final String baseUrl;
    private final String authHeader;

    public ManagementApiHelper(String host, int port) {
        this.baseUrl = "http://" + host + ":" + port + "/management/v2/environments/DEFAULT";
        this.authHeader = "Basic " + Base64.getEncoder().encodeToString("admin:admin".getBytes());
    }

    public void createAndDeployApi(String name, String contextPath, String targetUrl, String tokenEndpoint) throws Exception {
        String apiPayload = """
        {
          "name": "%s",
          "apiVersion": "1.0",
          "definitionVersion": "V4",
          "type": "PROXY",
          "description": "E2E Test API",
          "listeners": [
            {
              "type": "HTTP",
              "paths": [
                {
                  "path": "%s"
                }
              ],
              "entrypoints": [
                {
                  "type": "http-proxy",
                  "configuration": {}
                }
              ]
            }
          ],
          "endpointGroups": [
            {
              "name": "default-group",
              "type": "http-proxy",
              "endpoints": [
                {
                  "name": "default",
                  "type": "http-proxy",
                  "inheritConfiguration": false,
                  "configuration": {
                    "target": "%s"
                  }
                }
              ]
            }
          ],
          "flows": [
            {
              "name": "Exchange Flow",
              "enabled": true,
              "selectors": [
                {
                  "type": "HTTP",
                  "path": "/",
                  "pathOperator": "STARTS_WITH"
                }
              ],
              "request": [
                {
                  "name": "Token Exchange",
                  "policy": "oauth2-token-orchestrator",
                  "enabled": true,
                  "configuration": {
                    "cacheResource": "cache",
                    "tokenEndpoint": "%s",
                    "grantType": "token_exchange",
                    "cacheKey": "static-key",
                    "errorStatusCode": 401,
                    "errorContent": "{\\\"message\\\": \\\"Token exchange failed\\\"}",
                    "exitOnError": true
                  }
                }
              ]
            }
          ],
          "resources": [
            {
              "name": "cache",
              "type": "cache",
              "enabled": true,
              "configuration": {
                "timeToIdleSeconds": 0,
                "timeToLiveSeconds": 3600,
                "maxEntriesLocalHeap": 1000
              }
            }
          ]
        }
        """.formatted(name, contextPath, targetUrl, tokenEndpoint);

        // 1. Create API
        HttpRequest createReq = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/apis"))
            .header("Authorization", authHeader)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(apiPayload))
            .build();
        
        HttpResponse<String> createRes = client.send(createReq, HttpResponse.BodyHandlers.ofString());
        if (createRes.statusCode() >= 300) {
            throw new RuntimeException("Failed to create API: " + createRes.statusCode() + " - " + createRes.body());
        }
        
        // Extract API ID (naive JSON parsing)
        String apiId = createRes.body().split("\\\"id\\\":\\\"")[1].split("\\\"")[0];

        // 2. Create Keyless Plan
        String planPayload = """
        {
            "name": "Free Plan",
            "description": "Keyless access",
            "security": { "type": "KEY_LESS" },
            "validation": "AUTO"
        }
        """;
        HttpRequest planReq = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/apis/" + apiId + "/plans"))
            .header("Authorization", authHeader)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(planPayload))
            .build();
        
        HttpResponse<String> planRes = client.send(planReq, HttpResponse.BodyHandlers.ofString());
        if (planRes.statusCode() >= 300) {
            throw new RuntimeException("Failed to create Plan: " + planRes.statusCode() + " - " + planRes.body());
        }

        // Publish Plan
        String planId = planRes.body().split("\\\"id\\\":\\\"")[1].split("\\\"")[0];
        HttpRequest publishPlanReq = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/apis/" + apiId + "/plans/" + planId + "/_publish"))
            .header("Authorization", authHeader)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();
        client.send(publishPlanReq, HttpResponse.BodyHandlers.discarding());

        // 3. Start API
        HttpRequest startReq = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/apis/" + apiId + "/_start"))
            .header("Authorization", authHeader)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();
        client.send(startReq, HttpResponse.BodyHandlers.discarding());

        // 4. Deploy API
        String deployPayload = "{\\\"deploymentLabel\\\":\\\"Initial deployment\\\"}";
        HttpRequest deployReq = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/apis/" + apiId + "/deployments"))
            .header("Authorization", authHeader)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(deployPayload))
            .build();
        client.send(deployReq, HttpResponse.BodyHandlers.discarding());
    }
}
```

- [ ] **Step 2: Rewrite `E2EGatewayIT.java`**

```java
package io.fluenthealth.gravitee.policy.tokenexchange.integration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import org.awaitility.Awaitility;

public class E2EGatewayIT {

    private static final Logger logger = LoggerFactory.getLogger(E2EGatewayIT.class);
    private static final Network network = Network.newNetwork();

    private static final GenericContainer<?> mongodb = new GenericContainer<>("mongo:7.0")
            .withNetwork(network)
            .withNetworkAliases("mongodb")
            .withExposedPorts(27017);

    private static final GenericContainer<?> wiremock = new GenericContainer<>("wiremock/wiremock:3.5.4")
            .withNetwork(network)
            .withNetworkAliases("wiremock")
            .withExposedPorts(8080)
            .withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("wiremock"))
            .waitingFor(Wait.forHttp("/__admin").forStatusCode(200));

    private static final GenericContainer<?> managementApi = new GenericContainer<>("graviteeio/apim-management-api:4.4.0")
            .withNetwork(network)
            .withNetworkAliases("management")
            .withExposedPorts(8083)
            .withEnv("gravitee_management_mongodb_uri", "mongodb://mongodb:27017/gravitee")
            .withEnv("gravitee_analytics_type", "none")
            .withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("mgmt"))
            .dependsOn(mongodb)
            .waitingFor(Wait.forHttp("/_node/health").forPort(8083).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(120)));

    private static final GenericContainer<?> gateway = new GenericContainer<>("graviteeio/apim-gateway:4.4.0")
            .withNetwork(network)
            .withNetworkAliases("gateway")
            .withExposedPorts(8082)
            .withEnv("gravitee_management_mongodb_uri", "mongodb://mongodb:27017/gravitee")
            .withEnv("gravitee_analytics_type", "none")
            .withEnv("gravitee_plugins_path_0", "/opt/graviteeio-gateway/plugins")
            .withEnv("gravitee_plugins_path_1", "/opt/graviteeio-gateway/plugins-ext")
            .withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("gateway"))
            .dependsOn(mongodb)
            .waitingFor(Wait.forHttp("/_node/health").forPort(8082).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(120)));

    @BeforeAll
    static void setup() throws Exception {
        // Find the plugin ZIP
        Path targetDir = Paths.get("target");
        Optional<Path> pluginZip = Files.list(targetDir)
                .filter(p -> p.toString().endsWith(".zip"))
                .findFirst();

        if (pluginZip.isEmpty()) {
            throw new RuntimeException("Plugin ZIP not found in target/. Run 'mvn package' first.");
        }

        mongodb.start();
        wiremock.start();
        managementApi.start();

        gateway.withCopyFileToContainer(
                MountableFile.forHostPath(pluginZip.get()),
                "/opt/graviteeio-gateway/plugins-ext/" + pluginZip.get().getFileName().toString()
        );

        gateway.start();

        // Configure WireMock stubs
        com.github.tomakehurst.wiremock.client.WireMock.configureFor(wiremock.getHost(), wiremock.getMappedPort(8080));

        stubFor(post(urlEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"e2e-token\", \"expires_in\":3600}")));

        stubFor(get(urlEqualTo("/backend"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"status\":\"ok\"}")));

        // Deploy API
        ManagementApiHelper mgmtHelper = new ManagementApiHelper(managementApi.getHost(), managementApi.getMappedPort(8083));
        mgmtHelper.createAndDeployApi("E2E Test API", "/test", "http://wiremock:8080/backend", "http://wiremock:8080/token");
    }

    @org.junit.jupiter.api.AfterAll
    static void tearDown() {
        gateway.stop();
        managementApi.stop();
        wiremock.stop();
        mongodb.stop();
        network.close();
    }

    @Test
    void shouldExchangeTokenAndForwardToBackend() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String gatewayUrl = "http://" + gateway.getHost() + ":" + gateway.getMappedPort(8082) + "/test";

        // Wait for gateway to sync the new API
        Awaitility.await()
                .atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofSeconds(2))
                .until(() -> {
                    HttpRequest probe = HttpRequest.newBuilder().uri(URI.create(gatewayUrl)).GET().build();
                    return client.send(probe, HttpResponse.BodyHandlers.discarding()).statusCode() != 404;
                });

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(gatewayUrl))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("ok");

        // Verify WireMock received the request at /backend with the expected Authorization header
        verify(getRequestedFor(urlEqualTo("/backend"))
                .withHeader("Authorization", equalTo("Bearer e2e-token")));
    }
}
```

- [ ] **Step 3: Test and Commit**

Run: `mvn clean verify -DskipTests=false -q`
Expected: `BUILD SUCCESS`

```bash
git add src/test/java/io/fluenthealth/gravitee/policy/tokenexchange/integration/
git commit -m "test: implement full-stack Gravitee E2E integration test"
```
