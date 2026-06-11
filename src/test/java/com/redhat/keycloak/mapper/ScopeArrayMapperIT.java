package com.redhat.keycloak.mapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.SelinuxContext;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end regression tests against a real Keycloak with the mapper
 * deployed. These cover the server-side flows that unit tests cannot:
 * token issuance through TokenManager, refresh, userinfo (which re-parses
 * the token and checks the openid scope), and introspection.
 *
 * <p>Runs via {@code mvn verify} and needs a Docker-compatible daemon.
 * For rootless podman, point Testcontainers at the user socket and keep
 * the API service alive (the socket-activated unit idle-exits after 5s,
 * which breaks pooled client connections):
 * <pre>
 *   podman system service --time=0 &amp;
 *   DOCKER_HOST=unix:///run/user/$UID/podman/podman.sock \
 *     TESTCONTAINERS_RYUK_DISABLED=true mvn verify
 * </pre>
 */
@Testcontainers
class ScopeArrayMapperIT {

    private static final String REALM_URL_PATH = "/realms/it/protocol/openid-connect";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @Container
    private static final KeycloakContainer KEYCLOAK = createContainer();

    // The provider jar and realm import are bind-mounted rather than copied
    // (withProviderClassesFrom/withRealmImportFile): Testcontainers' copy
    // preserves the host uid in the tar header, which rootless podman cannot
    // chown inside its user namespace. Bind mounts work on both Docker and
    // rootless podman; SelinuxContext.SHARED is required on SELinux hosts
    // and ignored elsewhere.
    private static KeycloakContainer createContainer() {
        KeycloakContainer keycloak = new KeycloakContainer(
                "quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version", "26.6.3"));
        keycloak.addFileSystemBind(providerJar(), "/opt/keycloak/providers/scope-array-mapper.jar",
                BindMode.READ_ONLY, SelinuxContext.SHARED);
        // Keycloak's directory import requires the file name to match the
        // realm: <realm>-realm.json.
        keycloak.addFileSystemBind(testRealmFile(), "/opt/keycloak/data/import/it-realm.json",
                BindMode.READ_ONLY, SelinuxContext.SHARED);
        return keycloak;
    }

    private static String providerJar() {
        try (Stream<Path> files = Files.list(Path.of("target"))) {
            return files.filter(p -> p.getFileName().toString().matches("scope-array-mapper-.*\\.jar"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "provider jar not found in target/ — run via 'mvn verify' so the package phase builds it"))
                    .toAbsolutePath().toString();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static String testRealmFile() {
        return Path.of("src/test/resources/it-realm.json").toAbsolutePath().toString();
    }

    @Test
    void accessTokenContainsSingleArrayScopeClaim() throws Exception {
        JsonNode tokenResponse = passwordGrant();
        String payload = jwtPayload(tokenResponse.get("access_token").asText());

        // Assert on the raw JSON text: parsing into a Map would silently
        // collapse a duplicated key, which is the exact bug being guarded.
        int occurrences = payload.split("\"scope\"", -1).length - 1;
        assertEquals(1, occurrences, "access token must contain exactly one scope claim: " + payload);

        JsonNode scope = JSON.readTree(payload).get("scope");
        assertTrue(scope.isArray(), "scope claim must be a JSON array: " + scope);
        boolean hasOpenid = false;
        for (JsonNode entry : scope) {
            if ("openid".equals(entry.asText())) hasOpenid = true;
        }
        assertTrue(hasOpenid, "scope array must contain 'openid': " + scope);
    }

    @Test
    void tokenResponseContainsScopeParameter() throws Exception {
        JsonNode tokenResponse = passwordGrant();

        JsonNode scope = tokenResponse.get("scope");
        assertNotNull(scope, "token response must keep the OAuth scope parameter");
        assertTrue(scope.asText().contains("openid"), "response scope must contain 'openid': " + scope);
    }

    @Test
    void refreshedAccessTokenKeepsSingleArrayScopeClaim() throws Exception {
        JsonNode tokenResponse = passwordGrant();
        JsonNode refreshed = postForm("/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", tokenResponse.get("refresh_token").asText(),
                "client_id", "test-client",
                "client_secret", "test-secret"), 200);

        String payload = jwtPayload(refreshed.get("access_token").asText());
        int occurrences = payload.split("\"scope\"", -1).length - 1;
        assertEquals(1, occurrences, "refreshed token must contain exactly one scope claim: " + payload);
        assertTrue(JSON.readTree(payload).get("scope").isArray());
    }

    @Test
    void userinfoAcceptsTransformedToken() throws Exception {
        // Exercises the read-back path: the endpoint re-parses the token and
        // rejects it unless TokenUtil.hasScope(token.getScope(), "openid")
        // passes, which depends on the registered array-to-string deserializer.
        JsonNode tokenResponse = passwordGrant();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(KEYCLOAK.getAuthServerUrl() + REALM_URL_PATH + "/userinfo"))
                .header("Authorization", "Bearer " + tokenResponse.get("access_token").asText())
                .GET()
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode(), "userinfo rejected the token: " + response.body());
        assertNotNull(JSON.readTree(response.body()).get("sub"));
    }

    @Test
    void introspectionReportsTokenActive() throws Exception {
        JsonNode tokenResponse = passwordGrant();
        JsonNode introspection = postForm("/token/introspect", Map.of(
                "token", tokenResponse.get("access_token").asText(),
                "client_id", "test-client",
                "client_secret", "test-secret"), 200);

        assertTrue(introspection.get("active").asBoolean(),
                "introspection must report the token active: " + introspection);
    }

    private static JsonNode passwordGrant() throws Exception {
        return postForm("/token", Map.of(
                "grant_type", "password",
                "username", "alice",
                "password", "alice-password",
                "scope", "openid",
                "client_id", "test-client",
                "client_secret", "test-secret"), 200);
    }

    private static JsonNode postForm(String path, Map<String, String> form, int expectedStatus) throws Exception {
        String body = form.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(KEYCLOAK.getAuthServerUrl() + REALM_URL_PATH + path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(expectedStatus, response.statusCode(), "unexpected status from " + path + ": " + response.body());
        return JSON.readTree(response.body());
    }

    private static String jwtPayload(String jwt) {
        String[] parts = jwt.split("\\.");
        return new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
    }
}
