package io.fluenthealth.gravitee.policy.tokenexchange.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
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

/**
 * End-to-end test that proves the policy works against a real Gravitee AM JWT
 * (Domain v2.0, opaque UUID-format {@code sub}). Pinned to AM {@value #AM_VERSION} by default;
 * see {@link #AM_VERSION} to test another line.
 *
 * <p>The test brings up AM (mgmt + gateway) alongside the existing APIM stack, bootstraps a
 * v2 domain with one user and one OIDC app, mints a JWT via the password grant, and runs
 * that JWT through the APIM gateway's token-exchange policy. WireMock plays the downstream IdP's
 * {@code /oauth2/token} endpoint and asserts the policy forwarded the AM JWT verbatim as
 * the {@code subject_token}.
 *
 * <p>It also locks in the v2 sub algorithm: {@code sub == UUID.nameUUIDFromBytes(
 * (source + ":" + externalId).getBytes(UTF_8))}. If a future AM release changes the
 * algorithm, this assertion fails fast.
 */
public class AmDomainV2GatewayIT {

    private static final Logger logger = LoggerFactory.getLogger(AmDomainV2GatewayIT.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Network network = Network.newNetwork();
    private static final String MONGO_OPTS = "serverSelectionTimeoutMS=5000&connectTimeoutMS=5000&socketTimeoutMS=5000";
    private static final String APIM_MONGO_URI = "mongodb://mongodb-apim:27017/gravitee?" + MONGO_OPTS;
    private static final String AM_MONGO_URI = "mongodb://mongodb-am:27017/gravitee?" + MONGO_OPTS;
    private static final String AM_MGMT_BASE_INTERNAL = "http://am-management:8093";
    private static final String AM_GATEWAY_BASE_INTERNAL = "http://am-gateway:8092";
    private static final String AM_ADMIN_USER = "admin";
    private static final String AM_ADMIN_PASSWORD = "adminadmin";
    private static final String DOMAIN_HRID = "fh-test";
    private static final String END_USER_USERNAME = "alice";
    private static final String END_USER_PASSWORD = "Alice#Pass1!";
    private static final String OIDC_CLIENT_ID = "fh-test-client";
    private static final String OIDC_CLIENT_SECRET = "fh-test-secret";

    /**
     * AM and APIM versions under test, both defaulting to the latest release. This plugin major
     * requires APIM >= 4.12 (Vert.x 5). CI runs the full supported range — see
     * {@code .github/workflows/integration-matrix.yml}. Override with
     * {@code -Dam.version=4.10.12 -Dapim.version=4.12.0}.
     */
    private static final String AM_VERSION = System.getProperty("am.version", "4.12.2");

    private static final String APIM_VERSION = System.getProperty("apim.version", "4.12.12");

    private static final MongoDBContainer mongoApim = new MongoDBContainer("mongo:7.0")
            .withNetwork(network)
            .withNetworkAliases("mongodb-apim");

    private static final MongoDBContainer mongoAm = new MongoDBContainer("mongo:7.0")
            .withNetwork(network)
            .withNetworkAliases("mongodb-am");

    private static final GenericContainer<?> wiremock = new GenericContainer<>("wiremock/wiremock:3.5.4")
            .withNetwork(network)
            .withNetworkAliases("wiremock")
            .withExposedPorts(8080)
            .withLogConsumer(filteredLogConsumer("wiremock"))
            .waitingFor(Wait.forHttp("/__admin").forStatusCode(200));

    private static final GenericContainer<?> amManagement = new GenericContainer<>("graviteeio/am-management-api:" + AM_VERSION)
            .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
            .withNetwork(network)
            .withNetworkAliases("am-management")
            .withExposedPorts(8093, 18093)
            // Override BOTH the management repo and the default data-plane to point at our isolated mongo.
            // `ds.mongodb.*` feeds the data-plane (gravitee.yml:467-475 in AM source).
            .withEnv("gravitee_ds_mongodb_host", "mongodb-am")
            .withEnv("gravitee_ds_mongodb_port", "27017")
            .withEnv("gravitee_ds_mongodb_dbname", "gravitee")
            .withEnv("gravitee_management_type", "mongodb")
            .withEnv("gravitee_management_mongodb_uri", AM_MONGO_URI)
            .withEnv("gravitee_oauth2_type", "mongodb")
            .withEnv("gravitee_oauth2_mongodb_uri", AM_MONGO_URI)
            .withEnv("gravitee_services_core_http_enabled", "true")
            .withEnv("gravitee_services_core_http_port", "18093")
            .withEnv("gravitee_services_core_http_host", "0.0.0.0")
            .withEnv("gravitee_services_core_http_authentication_type", "none")
            .withLogConsumer(filteredLogConsumer("am-mgmt"))
            .dependsOn(mongoAm)
            .waitingFor(Wait.forHttp("/_node/health").forPort(18093).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(300)));

    private static final GenericContainer<?> amGateway = new GenericContainer<>("graviteeio/am-gateway:" + AM_VERSION)
            .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
            .withNetwork(network)
            .withNetworkAliases("am-gateway")
            .withExposedPorts(8092, 18092)
            .withEnv("gravitee_ds_mongodb_host", "mongodb-am")
            .withEnv("gravitee_ds_mongodb_port", "27017")
            .withEnv("gravitee_ds_mongodb_dbname", "gravitee")
            .withEnv("gravitee_management_type", "mongodb")
            .withEnv("gravitee_management_mongodb_uri", AM_MONGO_URI)
            .withEnv("gravitee_oauth2_type", "mongodb")
            .withEnv("gravitee_oauth2_mongodb_uri", AM_MONGO_URI)
            .withEnv("gravitee_services_core_http_enabled", "true")
            .withEnv("gravitee_services_core_http_port", "18092")
            .withEnv("gravitee_services_core_http_host", "0.0.0.0")
            .withEnv("gravitee_services_core_http_authentication_type", "none")
            .withEnv("gravitee_services_sync_delay", "1000")
            .withEnv("gravitee_services_sync_unit", "MILLISECONDS")
            .withLogConsumer(filteredLogConsumer("am-gw"))
            .dependsOn(mongoAm, amManagement)
            .waitingFor(Wait.forHttp("/_node/health").forPort(18092).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(300)));

    private static final GenericContainer<?> apimManagement = new GenericContainer<>("graviteeio/apim-management-api:" + APIM_VERSION)
            .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
            .withNetwork(network)
            .withNetworkAliases("apim-management")
            .withExposedPorts(8083, 18083)
            .withEnv("gravitee_management_mongodb_uri", APIM_MONGO_URI)
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
            .withLogConsumer(filteredLogConsumer("apim-mgmt"))
            .dependsOn(mongoApim)
            .waitingFor(Wait.forHttp("/_node/health").forPort(18083).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(300)));

    private static final GenericContainer<?> apimGateway = new GenericContainer<>("graviteeio/apim-gateway:" + APIM_VERSION)
            .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
            .withNetwork(network)
            .withNetworkAliases("apim-gateway")
            .withExposedPorts(8082, 18082)
            .withEnv("gravitee_management_mongodb_uri", APIM_MONGO_URI)
            .withEnv("gravitee_ratelimit_mongodb_uri", APIM_MONGO_URI)
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
            .withLogConsumer(filteredLogConsumer("apim-gw"))
            .dependsOn(mongoApim, apimManagement)
            .waitingFor(Wait.forHttp("/_node/health").forPort(18082).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(300)));

    private static Path terraformDir;
    private static final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private static WireMock wireMockClient;
    private static String amMgmtBase;
    private static String amGatewayBase;
    private static String amAdminToken;
    private static String defaultIdpId;

    @BeforeAll
    static void setup() throws Exception {
        Path targetDir = Paths.get("target");
        Optional<Path> pluginZip = Files.list(targetDir).filter(p -> p.toString().endsWith(".zip")).findFirst();
        if (pluginZip.isEmpty()) throw new RuntimeException("Plugin ZIP not found in target/");

        mongoApim.start();
        mongoAm.start();
        wiremock.start();
        wireMockClient = new WireMock(wiremock.getHost(), wiremock.getMappedPort(8080));
        WireMock.configureFor(wiremock.getHost(), wiremock.getMappedPort(8080));

        amManagement.start();
        amGateway.start();

        apimManagement.withCopyFileToContainer(MountableFile.forHostPath(pluginZip.get()),
                "/opt/graviteeio-management-api/plugins-ext/" + pluginZip.get().getFileName().toString());
        apimManagement.start();

        apimGateway.withCopyFileToContainer(MountableFile.forHostPath(pluginZip.get()),
                "/opt/graviteeio-gateway/plugins-ext/" + pluginZip.get().getFileName().toString());
        apimGateway.start();

        amMgmtBase = "http://" + amManagement.getHost() + ":" + amManagement.getMappedPort(8093);
        amGatewayBase = "http://" + amGateway.getHost() + ":" + amGateway.getMappedPort(8092);

        terraformDir = Files.createDirectories(Paths.get("target/terraform-am-v2-it"));
        Files.writeString(terraformDir.resolve(".tool-versions"), "terraform 1.15.1\n");
    }

    @AfterAll
    static void tearDown() {
        Stream.of(apimGateway, apimManagement, amGateway, amManagement, wiremock, mongoApim, mongoAm)
                .filter(Objects::nonNull).forEach(GenericContainer::stop);
        network.close();
    }

    @Test
    void shouldExchangeRealAmV2Token() throws Exception {
        // ---- 1. Bootstrap AM: admin login, create domain + user + OIDC app, start domain ----
        amAdminToken = loginAsAdmin();
        String domainId = createDomain();
        defaultIdpId = getDefaultIdpId(domainId);
        String externalId = createUser(domainId, defaultIdpId);
        createOidcApplication(domainId);
        enableAndStartDomain(domainId);
        waitForGatewaySync();

        // ---- 2. Mint a real AM v2 JWT via password grant ----
        String accessToken = mintTokenViaPasswordGrant();
        JsonNode claims = decodeJwtPayload(accessToken);
        logger.info("AM-minted token claims: {}", claims);

        // ---- 3. Lock in the v2 sub algorithm ----
        String sub = claims.path("sub").asText();
        String gis = claims.path("gis").asText();
        assertThat(sub).as("v2 sub must be UUID-format").matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        assertThat(gis).as("v2 gis must be '<source>:<externalId>'").isEqualTo(defaultIdpId + ":" + externalId);
        String reproduced = UUID.nameUUIDFromBytes(gis.getBytes(StandardCharsets.UTF_8)).toString();
        assertThat(sub).as("sub == UUID.nameUUIDFromBytes(gis)").isEqualTo(reproduced);
        // Cross-check against the algorithm reproduced from primitives below.
        assertThat(reproduced).as("MD5-based name UUID parity").isEqualTo(md5NameUuid(gis));

        // ---- 4. Stub WireMock first so the Awaitility probes below succeed cleanly ----
        stubFor(post(urlEqualTo("/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"access_token\":\"downstream-token\",\"expires_in\":3600}")));
        stubFor(get(urlEqualTo("/backend")).willReturn(aResponse().withStatus(200).withBody("{\"status\":\"ok\"}")));

        String mgmtBase = "http://" + apimManagement.getHost() + ":" + apimManagement.getMappedPort(8083);
        String tf = """
          terraform {
            required_providers { apim = { source = "gravitee-io/apim", version = "~> 0.5.0" } }
          }
          provider "apim" {
            server_url = "%s/automation"
            username   = "admin"
            password   = "admin"
          }
          resource "apim_apiv4" "am_v2_api" {
            name            = "AM V2 Token Exchange E2E"
            hrid            = "am-v2-token-exchange-e2e"
            version         = "1.0.0"
            lifecycle_state = "PUBLISHED"
            type            = "PROXY"
            state           = "STARTED"
            listeners = [{
              http = {
                type = "HTTP"
                paths = [{ path = "/am-v2-e2e" }]
                entrypoints = [{ type = "http-proxy" }]
              }
            }]
            endpoint_groups = [{
              name = "default-group"
              type = "http-proxy"
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
                  grantType     = "urn:ietf:params:oauth:grant-type:token-exchange"
                  parameters = {
                    subject_token      = "{#request.headers['Authorization'][0].substring(7)}"
                    subject_token_type = "urn:ietf:params:oauth:token-type:access_token"
                  }
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
        Files.writeString(terraformDir.resolve("main.tf"), tf);
        runTerraform("init");
        runTerraform("apply", "-auto-approve");

        // ---- 5. Run the AM JWT through the APIM gateway ----
        String gatewayBaseUrl = "http://" + apimGateway.getHost() + ":" + apimGateway.getMappedPort(8082) + "/am-v2-e2e";
        // Probe with no Authorization header — anything non-404 means the gateway has picked up
        // the new API definition. The probe will trigger one harmless EL-evaluation WARN in the
        // policy log (subject_token expression can't read the missing header), then the journal
        // reset below clears it before the real assertions run. We intentionally don't probe
        // with the real JWT, since that would prime the policy cache and cause the actual
        // request below to hit-cache instead of exchanging, breaking the `verify(1, ...)` asserts.
        Awaitility.await().atMost(Duration.ofSeconds(60)).pollInterval(Duration.ofSeconds(2)).until(() -> {
            try {
                return httpClient.send(HttpRequest.newBuilder().uri(URI.create(gatewayBaseUrl)).GET().build(),
                        HttpResponse.BodyHandlers.discarding()).statusCode() != 404;
            } catch (Exception e) { return false; }
        });
        wireMockClient.resetRequests();

        HttpResponse<String> response = httpClient.send(HttpRequest.newBuilder()
                        .uri(URI.create(gatewayBaseUrl))
                        .header("Authorization", "Bearer " + accessToken)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as("gateway response").isEqualTo(200);

        // ---- 6. Verify WireMock saw the exchange and the backend got the exchanged token ----
        verify(1, postRequestedFor(urlEqualTo("/token"))
                .withRequestBody(containing("subject_token=" + java.net.URLEncoder.encode(accessToken, StandardCharsets.UTF_8))));
        verify(1, getRequestedFor(urlEqualTo("/backend"))
                .withHeader("Authorization", equalTo("Bearer downstream-token")));

        logger.info("AM v2 E2E passed: sub={}, gis={}", sub, gis);
    }

    // -------- AM bootstrap helpers --------

    private String loginAsAdmin() throws Exception {
        String basic = Base64.getEncoder().encodeToString((AM_ADMIN_USER + ":" + AM_ADMIN_PASSWORD).getBytes(StandardCharsets.UTF_8));
        HttpResponse<String> res = httpClient.send(HttpRequest.newBuilder()
                .uri(URI.create(amMgmtBase + "/management/auth/token"))
                .header("Authorization", "Basic " + basic)
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() / 100 != 2) throw new RuntimeException("AM admin login failed: " + res.statusCode() + " " + res.body());
        return MAPPER.readTree(res.body()).path("access_token").asText();
    }

    private String createDomain() throws Exception {
        String body = "{\"name\":\"" + DOMAIN_HRID + "\",\"description\":\"FH token-exchange E2E\",\"dataPlaneId\":\"default\"}";
        HttpResponse<String> res = amPost("/management/organizations/DEFAULT/environments/DEFAULT/domains", body);
        if (res.statusCode() / 100 != 2) throw new RuntimeException("createDomain failed: " + res.statusCode() + " " + res.body());
        JsonNode node = MAPPER.readTree(res.body());
        String id = node.path("id").asText();
        String hrid = node.path("hrid").asText();
        logger.info("Created domain id={} hrid={} version={}", id, hrid, node.path("version").asText());
        return id;
    }

    private String getDefaultIdpId(String domainId) throws Exception {
        HttpResponse<String> res = amGet("/management/organizations/DEFAULT/environments/DEFAULT/domains/" + domainId + "/identities");
        if (res.statusCode() / 100 != 2) throw new RuntimeException("listIdPs failed: " + res.statusCode() + " " + res.body());
        JsonNode arr = MAPPER.readTree(res.body());
        if (!arr.isArray() || arr.size() == 0) throw new RuntimeException("no IdPs found on domain");
        // The default in-memory IdP is created automatically.
        return arr.get(0).path("id").asText();
    }

    private String createUser(String domainId, String idpId) throws Exception {
        // The AM mgmt API requires an email even for IdPs that don't supply one. For this test it is
        // just a stand-in for the upstream IdP's externalId.
        String body = String.format(
                "{\"username\":\"%s\",\"password\":\"%s\",\"firstName\":\"Alice\",\"lastName\":\"Tester\","
                        + "\"email\":\"alice@example.test\",\"source\":\"%s\"}",
                END_USER_USERNAME, END_USER_PASSWORD, idpId);
        HttpResponse<String> res = amPost("/management/organizations/DEFAULT/environments/DEFAULT/domains/" + domainId + "/users", body);
        if (res.statusCode() / 100 != 2) throw new RuntimeException("createUser failed: " + res.statusCode() + " " + res.body());
        JsonNode node = MAPPER.readTree(res.body());
        String extId = node.path("externalId").asText(null);
        logger.info("Created AM user: id={} externalId={} username={} source={}",
                node.path("id").asText(), extId, node.path("username").asText(), node.path("source").asText());
        return extId;
    }

    private void createOidcApplication(String domainId) throws Exception {
        // Step 1: create with the minimal NewApplication fields — settings aren't accepted at create.
        String createBody = String.format(
                "{\"name\":\"FH Test App\",\"type\":\"WEB\",\"clientId\":\"%s\",\"clientSecret\":\"%s\","
                        + "\"redirectUris\":[\"https://app.example.test/cb\"]}",
                OIDC_CLIENT_ID, OIDC_CLIENT_SECRET);
        HttpResponse<String> createRes = amPost(
                "/management/organizations/DEFAULT/environments/DEFAULT/domains/" + domainId + "/applications", createBody);
        if (createRes.statusCode() / 100 != 2)
            throw new RuntimeException("createApp failed: " + createRes.statusCode() + " " + createRes.body());
        String appId = MAPPER.readTree(createRes.body()).path("id").asText();
        // Step 2: enable the password grant and bind the default IdP so password authentication has
        // somewhere to look up the user. Default grant types are authorization_code only.
        String patchBody = String.format(
                "{\"settings\":{\"oauth\":{\"grantTypes\":[\"password\",\"client_credentials\"]}},"
                        + "\"identityProviders\":[{\"identity\":\"%s\",\"priority\":0}]}",
                defaultIdpId);
        HttpResponse<String> patchRes = amPatch(
                "/management/organizations/DEFAULT/environments/DEFAULT/domains/" + domainId + "/applications/" + appId, patchBody);
        if (patchRes.statusCode() / 100 != 2)
            throw new RuntimeException("enable password grant failed: " + patchRes.statusCode() + " " + patchRes.body());
    }

    private void enableAndStartDomain(String domainId) throws Exception {
        HttpResponse<String> res = amPatch(
                "/management/organizations/DEFAULT/environments/DEFAULT/domains/" + domainId,
                "{\"enabled\":true}");
        if (res.statusCode() / 100 != 2) throw new RuntimeException("enableDomain failed: " + res.statusCode() + " " + res.body());
    }

    private void waitForGatewaySync() {
        Awaitility.await().atMost(Duration.ofSeconds(60)).pollInterval(Duration.ofSeconds(2)).until(() -> {
            try {
                int code = httpClient.send(HttpRequest.newBuilder()
                        .uri(URI.create(amGatewayBase + "/" + DOMAIN_HRID + "/oidc/.well-known/openid-configuration"))
                        .GET().build(), HttpResponse.BodyHandlers.discarding()).statusCode();
                return code == 200;
            } catch (Exception e) { return false; }
        });
    }

    private String mintTokenViaPasswordGrant() throws Exception {
        String basic = Base64.getEncoder().encodeToString((OIDC_CLIENT_ID + ":" + OIDC_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        // Don't request `openid` — the app's scopeSettings are empty by default and AM would reject.
        String form = "grant_type=password"
                + "&username=" + java.net.URLEncoder.encode(END_USER_USERNAME, StandardCharsets.UTF_8)
                + "&password=" + java.net.URLEncoder.encode(END_USER_PASSWORD, StandardCharsets.UTF_8);
        HttpResponse<String> res = httpClient.send(HttpRequest.newBuilder()
                .uri(URI.create(amGatewayBase + "/" + DOMAIN_HRID + "/oauth/token"))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() / 100 != 2) throw new RuntimeException("password grant failed: " + res.statusCode() + " " + res.body());
        return MAPPER.readTree(res.body()).path("access_token").asText();
    }

    // -------- generic AM HTTP helpers --------

    private HttpResponse<String> amPost(String path, String body) throws Exception {
        return httpClient.send(HttpRequest.newBuilder()
                .uri(URI.create(amMgmtBase + path))
                .header("Authorization", "Bearer " + amAdminToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> amGet(String path) throws Exception {
        return httpClient.send(HttpRequest.newBuilder()
                .uri(URI.create(amMgmtBase + path))
                .header("Authorization", "Bearer " + amAdminToken)
                .GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> amPatch(String path, String body) throws Exception {
        return httpClient.send(HttpRequest.newBuilder()
                .uri(URI.create(amMgmtBase + path))
                .header("Authorization", "Bearer " + amAdminToken)
                .header("Content-Type", "application/json")
                .method("PATCH", HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    // -------- v2 sub algorithm parity check --------

    /**
     * Reproduces {@code UUID.nameUUIDFromBytes} from primitives, to prove the documented
     * algorithm (MD5(name), set version-3 + RFC-4122 variant bits) is byte-for-byte equivalent.
     */
    private static String md5NameUuid(String name) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] h = md.digest(name.getBytes(StandardCharsets.UTF_8));
            h[6] = (byte) ((h[6] & 0x0f) | 0x30);
            h[8] = (byte) ((h[8] & 0x3f) | 0x80);
            String hex = bytesToHex(h);
            return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-"
                    + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-" + hex.substring(20);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static JsonNode decodeJwtPayload(String jwt) throws IOException {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("not a JWT: " + jwt);
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        return MAPPER.readTree(payload);
    }

    // -------- log filtering (copied / trimmed from E2EGatewayIT) --------

    private static final java.util.regex.Pattern LEADING_TIMESTAMP = java.util.regex.Pattern.compile(
            "^\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\s+\\[[^\\]]+\\]\\s*");
    private static final List<String> SILENCED_BOOT_ERRORS = List.of(
            "KubernetesConfig", "EmailNotifierServiceImpl");
    // Bare JVM throwable headers carry no log level, so the level-based clauses below miss them
    // and stack traces arrive with their cause stripped. That is what a linkage error against a
    // new Gravitee release looks like.
    private static final java.util.regex.Pattern THROWABLE_HEADER = java.util.regex.Pattern.compile(
            "^(Caused by: )?(java|javax|jakarta|io|com|org)\\.[\\w.$]*(Exception|Error|Throwable)\\b");

    private static Consumer<OutputFrame> filteredLogConsumer(String prefix) {
        return frame -> {
            var line = frame.getUtf8StringWithoutLineEnding();
            if (line.isEmpty()) return;
            var trimmed = LEADING_TIMESTAMP.matcher(line).replaceFirst("");
            // For AM mgmt container, pass through everything except boot-time metrics noise
            // — we need full stack traces to debug bootstrap failures.
            if (prefix.equals("am-mgmt")) {
                if (line.contains("services.metrics.enabled=true")) return;
                logger.info("[{}] {}", prefix, trimmed);
                return;
            }
            if (line.contains(" ERROR ")) {
                if (SILENCED_BOOT_ERRORS.stream().anyMatch(line::contains)) return;
                logger.error("[{}] {}", prefix, trimmed);
            } else if (line.contains("OAuth2TokenOrchestratorPolicy") || line.contains("io.fluenthealth")) {
                logger.info("[{}] {}", prefix, trimmed);
            } else if (THROWABLE_HEADER.matcher(trimmed).find()) {
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
