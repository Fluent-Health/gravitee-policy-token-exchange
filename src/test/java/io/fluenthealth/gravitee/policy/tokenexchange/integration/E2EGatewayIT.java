package io.fluenthealth.gravitee.policy.tokenexchange.integration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.lifecycle.Startables;
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
    private static final String MONGO_URI = "mongodb://mongodb:27017/gravitee";

    private static final MongoDBContainer mongodb = new MongoDBContainer("mongo:7.0")
            .withNetwork(network)
            .withNetworkAliases("mongodb");

    private static final GenericContainer<?> wiremock = new GenericContainer<>("wiremock/wiremock:3.5.4")
            .withNetwork(network)
            .withNetworkAliases("wiremock")
            .withExposedPorts(8080)
            .withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("wiremock"))
            .waitingFor(Wait.forHttp("/__admin").forStatusCode(200));

    private static final GenericContainer<?> managementApi = new GenericContainer<>("graviteeio/apim-management-api:4.9.13")
            .withNetwork(network)
            .withNetworkAliases("management")
            .withExposedPorts(8083, 18083)
            .withEnv("gravitee_management_mongodb_uri", MONGO_URI)
            .withEnv("gravitee_analytics_type", "none")
            .withEnv("gravitee_services_core_http_enabled", "true")
            .withEnv("gravitee_services_core_http_port", "18083")
            .withEnv("gravitee_services_core_http_authentication_type", "none")
            .withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("mgmt"))
            .dependsOn(mongodb)
            .waitingFor(Wait.forHttp("/_node/health").forPort(18083).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(120)));

    private static final GenericContainer<?> gateway = new GenericContainer<>("graviteeio/apim-gateway:4.9.13")
            .withNetwork(network)
            .withNetworkAliases("gateway")
            .withExposedPorts(8082, 18082)
            .withEnv("gravitee_management_mongodb_uri", MONGO_URI)
            .withEnv("gravitee_analytics_type", "none")
            .withEnv("gravitee_plugins_path_0", "/opt/graviteeio-gateway/plugins")
            .withEnv("gravitee_plugins_path_1", "/opt/graviteeio-gateway/plugins-ext")
            .withEnv("gravitee_services_core_http_enabled", "true")
            .withEnv("gravitee_services_core_http_port", "18082")
            .withEnv("gravitee_services_core_http_authentication_type", "none")
            .withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("gateway"))
            .dependsOn(mongodb, managementApi)
            .waitingFor(Wait.forHttp("/_node/health").forPort(18082).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(120)));

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
        
        // Wait for Management API to be truly ready for REST calls (on technical port)
        Awaitility.await()
                .atMost(Duration.ofSeconds(60))
                .pollInterval(Duration.ofSeconds(2))
                .until(() -> {
                    try {
                        HttpRequest probe = HttpRequest.newBuilder()
                                .uri(URI.create("http://" + managementApi.getHost() + ":" + managementApi.getMappedPort(18083) + "/_node/health"))
                                .GET().build();
                        return HttpClient.newHttpClient().send(probe, HttpResponse.BodyHandlers.discarding()).statusCode() == 200;
                    } catch (Exception e) {
                        return false;
                    }
                });

        mgmtHelper.createAndDeployApi("E2E Test API", "/test", "http://wiremock:8080/backend", "http://wiremock:8080/token");
    }

    @AfterAll
    static void tearDown() {
        if (gateway != null) gateway.stop();
        if (managementApi != null) managementApi.stop();
        if (wiremock != null) wiremock.stop();
        if (mongodb != null) mongodb.stop();
        network.close();
    }

    @Test
    void shouldExchangeTokenAndForwardToBackend() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String gatewayUrl = "http://" + gateway.getHost() + ":" + gateway.getMappedPort(8082) + "/test";

        // Wait for gateway to sync the new API
        Awaitility.await()
                .atMost(Duration.ofSeconds(60))
                .pollInterval(Duration.ofSeconds(5))
                .until(() -> {
                    try {
                        HttpRequest probe = HttpRequest.newBuilder().uri(URI.create(gatewayUrl)).GET().build();
                        return client.send(probe, HttpResponse.BodyHandlers.discarding()).statusCode() != 404;
                    } catch (Exception e) {
                        return false;
                    }
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
