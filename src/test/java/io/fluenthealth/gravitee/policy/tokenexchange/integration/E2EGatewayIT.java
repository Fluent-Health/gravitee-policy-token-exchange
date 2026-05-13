package io.fluenthealth.gravitee.policy.tokenexchange.integration;

import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
public class E2EGatewayIT {

    private static final Logger logger = LoggerFactory.getLogger(E2EGatewayIT.class);
    private static final Network network = Network.newNetwork();

    @Container
    private static final GenericContainer<?> wiremock = new GenericContainer<>("wiremock/wiremock:3.5.4")
            .withNetwork(network)
            .withNetworkAliases("wiremock")
            .withExposedPorts(8080)
            .withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("wiremock"))
            .waitingFor(Wait.forHttp("/__admin").forStatusCode(200));

    @Container
    private static final GenericContainer<?> gateway = new GenericContainer<>("graviteeio/apim-gateway:4.0.1")
            .withNetwork(network)
            .withNetworkAliases("gateway")
            .withExposedPorts(8082)
            .withEnv("gravitee_services_localregistry_path", "/opt/graviteeio-gateway/apis")
            .withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("gateway"))
            .waitingFor(Wait.forHttp("/").forPort(8082).forStatusCode(404));

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

        gateway.withCopyFileToContainer(
                MountableFile.forHostPath(pluginZip.get()),
                "/opt/graviteeio-gateway/plugins-ext/" + pluginZip.get().getFileName().toString()
        );

        gateway.withCopyFileToContainer(
                MountableFile.forHostPath("src/test/resources/gateway/gravitee.yml"),
                "/opt/graviteeio-gateway/config/gravitee.yml"
        );

        gateway.withCopyFileToContainer(
                MountableFile.forHostPath("src/test/resources/gateway/apis/test-api.json"),
                "/opt/graviteeio-gateway/apis/test-api.json"
        );

        // Configure WireMock stubs using the Java client
        WireMock.configureFor(wiremock.getHost(), wiremock.getMappedPort(8080));

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
    }

    @Test
    void shouldExchangeTokenAndForwardToBackend() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String gatewayUrl = "http://" + gateway.getHost() + ":" + gateway.getMappedPort(8082) + "/test";

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
