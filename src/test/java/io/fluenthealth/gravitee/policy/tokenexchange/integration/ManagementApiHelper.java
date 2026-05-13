package io.fluenthealth.gravitee.policy.tokenexchange.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.time.Duration;

public class ManagementApiHelper {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final ObjectMapper mapper = new ObjectMapper();
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
                    "errorContent": "{\\"message\\": \\"Token exchange failed\\"}",
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
        
        String apiId = mapper.readTree(createRes.body()).get("id").asText();

        // 2. Create Keyless Plan
        String planPayload = """
        {
            "name": "Free Plan",
            "description": "Keyless access",
            "definitionVersion": "V4",
            "mode": "STANDARD",
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
        String planId = mapper.readTree(planRes.body()).get("id").asText();
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
        String deployPayload = "{\"deploymentLabel\":\"Initial deployment\"}";
        HttpRequest deployReq = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/apis/" + apiId + "/deployments"))
            .header("Authorization", authHeader)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(deployPayload))
            .build();
        client.send(deployReq, HttpResponse.BodyHandlers.discarding());
    }
}
