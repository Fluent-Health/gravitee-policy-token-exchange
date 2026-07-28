package io.fluenthealth.gravitee.policy.tokenexchange.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.OutputFrame;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import com.github.tomakehurst.wiremock.client.WireMock;

public class E2EGatewayIT {

    private static final Logger logger = LoggerFactory.getLogger(E2EGatewayIT.class);
    private static final Network network = Network.newNetwork();
    private static final String MONGO_URI = "mongodb://mongodb:27017/gravitee?serverSelectionTimeoutMS=5000&connectTimeoutMS=5000&socketTimeoutMS=5000";

    /**
     * APIM version under test. Defaults to the latest release. This plugin major requires
     * APIM >= 4.12 (Vert.x 5) — pointing it at 4.11 or earlier fails at exchange time with a
     * {@code NoSuchMethodError}, which is expected, not a bug. CI runs the full supported range;
     * see {@code .github/workflows/integration-matrix.yml}.
     */
    private static final String APIM_VERSION = System.getProperty("apim.version", "4.12.12");

    private static final MongoDBContainer mongodb = new MongoDBContainer("mongo:7.0")
            .withNetwork(network)
            .withNetworkAliases("mongodb");

    private static final GenericContainer<?> wiremock = new GenericContainer<>("wiremock/wiremock:3.5.4")
            .withNetwork(network)
            .withNetworkAliases("wiremock")
            .withExposedPorts(8080)
            .withLogConsumer(filteredLogConsumer("wiremock"))
            .waitingFor(Wait.forHttp("/__admin").forStatusCode(200));

    private static final GenericContainer<?> managementApi = new GenericContainer<>("graviteeio/apim-management-api:" + APIM_VERSION)
            .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
            .withNetwork(network)
            .withNetworkAliases("management")
            .withExposedPorts(8083, 18083)
            .withEnv("gravitee_management_mongodb_uri", MONGO_URI)
            .withEnv("gravitee_analytics_type", "none")
            .withEnv("gravitee_reporters_elasticsearch_enabled", "false")
            .withEnv("gravitee_alerts_enabled", "false")
            .withEnv("gravitee_services_dictionary_enabled", "false")
            .withEnv("gravitee_services_organization_enabled", "false")
            .withEnv("gravitee_services_access_point_enabled", "false")
            .withEnv("gravitee_services_sync_delay", "1000")
            .withEnv("gravitee_services_sync_unit", "MILLISECONDS")
            .withEnv("gravitee_plugins_path_0", "/opt/graviteeio-management-api/plugins")
            .withEnv("gravitee_plugins_path_1", "/opt/graviteeio-management-api/plugins-ext")
            .withEnv("gravitee_services_core_http_enabled", "true")
            .withEnv("gravitee_services_core_http_port", "18083")
            .withEnv("gravitee_services_core_http_host", "0.0.0.0")
            .withEnv("gravitee_services_core_http_authentication_type", "none")
            .withLogConsumer(filteredLogConsumer("mgmt"))
            .dependsOn(mongodb)
            .waitingFor(Wait.forHttp("/_node/health").forPort(18083).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(300)));

    private static final GenericContainer<?> gateway = new GenericContainer<>("graviteeio/apim-gateway:" + APIM_VERSION)
            .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
            .withNetwork(network)
            .withNetworkAliases("gateway")
            .withExposedPorts(8082, 18082)
            .withEnv("gravitee_management_mongodb_uri", MONGO_URI)
            .withEnv("gravitee_ratelimit_mongodb_uri", MONGO_URI)
            .withEnv("gravitee_analytics_type", "none")
            .withEnv("gravitee_reporters_elasticsearch_enabled", "false")
            .withEnv("gravitee_plugins_path_0", "/opt/graviteeio-gateway/plugins")
            .withEnv("gravitee_plugins_path_1", "/opt/graviteeio-gateway/plugins-ext")
            .withEnv("gravitee_services_core_http_enabled", "true")
            .withEnv("gravitee_services_core_http_port", "18082")
            .withEnv("gravitee_services_core_http_host", "0.0.0.0")
            .withEnv("gravitee_services_core_http_authentication_type", "none")
            .withEnv("gravitee_services_sync_delay", "1000")
            .withEnv("gravitee_services_sync_unit", "MILLISECONDS")
            .withEnv("gravitee_logging_categories_io.fluenthealth.gravitee.policy.tokenexchange", "DEBUG")
            .withLogConsumer(filteredLogConsumer("gateway"))
            .dependsOn(mongodb, managementApi)
            .waitingFor(Wait.forHttp("/_node/health").forPort(18082).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(300)));

    private static Path terraformDir;
    private static HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private static WireMock wireMockClient;

    @BeforeAll
    static void setup() throws Exception {
        Path targetDir = Paths.get("target");
        Optional<Path> pluginZip = Files.list(targetDir)
                .filter(p -> p.toString().endsWith(".zip"))
                .findFirst();

        if (pluginZip.isEmpty()) throw new RuntimeException("Plugin ZIP not found");

        mongodb.start();
        wiremock.start();
        wireMockClient = new WireMock(wiremock.getHost(), wiremock.getMappedPort(8080));
        WireMock.configureFor(wiremock.getHost(), wiremock.getMappedPort(8080));

        managementApi.withCopyFileToContainer(MountableFile.forHostPath(pluginZip.get()), "/opt/graviteeio-management-api/plugins-ext/" + pluginZip.get().getFileName().toString());
        managementApi.start();

        gateway.withCopyFileToContainer(MountableFile.forHostPath(pluginZip.get()), "/opt/graviteeio-gateway/plugins-ext/" + pluginZip.get().getFileName().toString());
        gateway.start();

        terraformDir = Files.createDirectories(Paths.get("target/terraform-it"));
        Files.writeString(terraformDir.resolve(".tool-versions"), "terraform 1.15.1\n");
    }

    @AfterAll
    static void tearDown() {
        Stream.of(gateway, managementApi, wiremock, mongodb).filter(Objects::nonNull).forEach(GenericContainer::stop);
        network.close();
    }

    @Test
    void shouldVerifyUserIsolationAndNativeCaching() throws Exception {
        // 1. Setup WireMock stubs
        stubFor(post(urlEqualTo("/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\": \"e2e-token\", \"expires_in\": 3600}")));

        stubFor(get(urlEqualTo("/backend"))
                .willReturn(aResponse().withStatus(200).withBody("{\"status\": \"ok\"}")));

        // 2. Configure API via Terraform
        String mgmtBase = "http://" + managementApi.getHost() + ":" + managementApi.getMappedPort(8083);
        String tfConfig = """
          terraform {
            required_providers {
              apim = {
                source = "gravitee-io/apim"
                version = "~> 0.5.0"
              }
            }
          }

          provider "apim" {
            server_url = "%s/automation"
            username   = "admin"
            password   = "admin"
          }

          resource "apim_apiv4" "token_exchange_api" {
            name            = "Token Exchange E2E"
            hrid            = "token-exchange-e2e"
            version         = "1.0.0"
            lifecycle_state = "PUBLISHED"
            type            = "PROXY"
            state           = "STARTED"

            listeners = [{
              http = {
                type = "HTTP"
                paths = [{ path = "/e2e-test" }]
                entrypoints = [{ type = "http-proxy" }]
              }
            }]

            endpoint_groups = [{
              name = "default-group"
              type = "http-proxy",
              endpoints = [{
                name = "main-endpoint"
                type = "http-proxy"
                configuration = jsonencode({ target = "http://wiremock:8080/backend" })
              }]
            }]

            flows = [{
              name = "Exchange Flow"
              enabled = true
              selectors = [{ http = { type = "HTTP", path = "/", path_operator = "STARTS_WITH" } }]
              request = [{
                policy = "oauth2-token-orchestrator"
                enabled = true
                configuration = jsonencode({
                  cacheResource = "token-cache"
                  tokenEndpoint = "http://wiremock:8080/token"
                  grantType     = "token_exchange"
                })
              }]
            }]

            resources = [{
                name = "token-cache"
                type = "cache"
                enabled = true
                configuration = jsonencode({
                  timeToIdleSeconds = 0
                  timeToLiveSeconds = 3600
                  maxEntriesLocalHeap = 1000
                })
            }]

            plans = [{
              name     = "Free Plan"
              hrid     = "free-plan"
              mode     = "STANDARD"
              security = { type = "KEY_LESS" }
              status   = "PUBLISHED"
            }]
          }
          """.formatted(mgmtBase);

        Files.writeString(terraformDir.resolve("main.tf"), tfConfig);
        runTerraform("init");
        runTerraform("apply", "-auto-approve");

        String gatewayBaseUrl = "http://" + gateway.getHost() + ":" + gateway.getMappedPort(8082) + "/e2e-test";

        // Wait for API to be available on Gateway
        Awaitility.await().atMost(Duration.ofSeconds(60)).pollInterval(Duration.ofSeconds(2)).until(() -> {
            try {
                return httpClient.send(HttpRequest.newBuilder().uri(URI.create(gatewayBaseUrl)).GET().build(), HttpResponse.BodyHandlers.discarding()).statusCode() != 404;
            } catch (Exception e) { return false; }
        });

        // Reset WireMock journal to ignore exchanges triggered by the probe
        wireMockClient.resetRequests();

        // 3. Perform Flow: User A (1), User A (2 - Hit), User B (3 - Miss/Isolation)
        
        // User A - Request 1 (Exchange)
        httpClient.send(HttpRequest.newBuilder().uri(URI.create(gatewayBaseUrl)).header("Authorization", "Bearer user-a").GET().build(), HttpResponse.BodyHandlers.discarding());
        
        // User A - Request 2 (Cache Hit)
        httpClient.send(HttpRequest.newBuilder().uri(URI.create(gatewayBaseUrl)).header("Authorization", "Bearer user-a").GET().build(), HttpResponse.BodyHandlers.discarding());
        
        // User B - Request 1 (Exchange - Isolation)
        httpClient.send(HttpRequest.newBuilder().uri(URI.create(gatewayBaseUrl)).header("Authorization", "Bearer user-b").GET().build(), HttpResponse.BodyHandlers.discarding());

        // 4. Verifications
        // Exactly 2 token exchanges (one for A, one for B)
        verify(2, postRequestedFor(urlEqualTo("/token")));
        // 3 calls to backend
        verify(3, getRequestedFor(urlEqualTo("/backend")).withHeader("Authorization", equalTo("Bearer e2e-token")));
        
        logger.info("E2E Test Passed: Native caching with User Isolation verified.");
    }

    /**
     * Forwards container stdout to SLF4J selectively, dropping the boot/infra noise that does
     * not help debug the policy under test. Forwarded lines have their leading
     * "HH:mm:ss.SSS [thread]" stripped to avoid duplicate timestamps in the consolidated log.
     *
     * Rules:
     *   - ERROR lines pass through at error level.
     *   - Anything mentioning our policy class or package passes through at info, regardless of
     *     the container-side log level (this is where the meaningful debug signal lives).
     *   - API lifecycle markers (deploy/undeploy) pass through at info to confirm sync.
     *   - Everything else (Spring/Jetty/Mongo/Gravitee bootstrap chatter, infra WARNs about
     *     unrelated plugins, etc.) is dropped.
     */
    private static final java.util.regex.Pattern LEADING_TIMESTAMP = java.util.regex.Pattern.compile(
        "^\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\s+\\[[^\\]]+\\]\\s*"
    );

    // Matches a bare JVM throwable header, e.g. "java.lang.NoSuchMethodError: io.vertx..." or
    // "Caused by: java.lang.IllegalStateException: ...". These lines have no log level, so the
    // level-based clauses below never see them.
    private static final java.util.regex.Pattern THROWABLE_HEADER = java.util.regex.Pattern.compile(
        "^(Caused by: )?(java|javax|jakarta|io|com|org)\\.[\\w.$]*(Exception|Error|Throwable)\\b"
    );

    // Known harmless ERROR-level messages emitted by Gravitee at startup. Listed explicitly
    // (not regex-broad) so we don't silently swallow real errors that look similar.
    private static final List<String> SILENCED_BOOT_ERRORS = List.of(
        "KubernetesConfig",              // Gateway/mgmt probe for K8s metadata; not running in K8s
        "EmailNotifierServiceImpl"       // Notification subsystem boot noise on empty recipient list
    );

    private static Consumer<OutputFrame> filteredLogConsumer(String prefix) {
        return frame -> {
            var line = frame.getUtf8StringWithoutLineEnding();
            if (line.isEmpty()) {
                return;
            }
            var trimmed = LEADING_TIMESTAMP.matcher(line).replaceFirst("");
            if (line.contains(" ERROR ")) {
                if (SILENCED_BOOT_ERRORS.stream().anyMatch(line::contains)) {
                    return;
                }
                logger.error("[{}] {}", prefix, trimmed);
            } else if (line.contains("OAuth2TokenOrchestratorPolicy") || line.contains("io.fluenthealth")) {
                logger.info("[{}] {}", prefix, trimmed);
            } else if (THROWABLE_HEADER.matcher(trimmed).find()) {
                // Bare exception header lines carry no log level and no package of ours, so the
                // clauses above miss them and a stack trace arrives with its cause stripped off.
                // That is exactly how a linkage error against a new Gravitee release looks.
                logger.warn("[{}] {}", prefix, trimmed);
            } else if (line.contains("ApiManagerImpl") && (line.contains("has been deployed") || line.contains("has been undeployed"))) {
                logger.info("[{}] {}", prefix, trimmed);
            }
        };
    }

    private void runTerraform(String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add("terraform");
        command.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(terraformDir.toFile());
        Path outFile = terraformDir.resolve("terraform-" + args[0] + ".log");
        pb.redirectOutput(outFile.toFile());
        pb.redirectError(outFile.toFile());
        int exitCode = pb.start().waitFor();
        if (exitCode != 0) throw new RuntimeException("Terraform " + args[0] + " failed (see " + outFile + ")");
    }
}
