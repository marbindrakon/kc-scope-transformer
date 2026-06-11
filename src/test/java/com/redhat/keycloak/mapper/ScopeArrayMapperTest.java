package com.redhat.keycloak.mapper;

import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;

import static org.junit.jupiter.api.Assertions.*;

class ScopeArrayMapperTest {

    private ScopeArrayMapper mapper;
    private ProtocolMapperModel mappingModel;

    @BeforeEach
    void setUp() {
        mapper = new ScopeArrayMapper();
        mappingModel = new ProtocolMapperModel();
    }

    @Test
    void transformsMultipleScopesToArray() {
        AccessToken token = new AccessToken();
        token.setScope("openid profile email");

        mapper.transformAccessToken(token, mappingModel, null, null, null);

        assertEquals(List.of("openid", "profile", "email"), token.getOtherClaims().get("scope"));
        assertNull(token.getScope());
    }

    @Test
    void serializedTokenContainsExactlyOneScopeClaim() throws Exception {
        AccessToken token = new AccessToken();
        token.setScope("openid profile email");

        mapper.transformAccessToken(token, mappingModel, null, null, null);

        String json = JsonSerialization.writeValueAsString(token);
        int occurrences = json.split("\"scope\"", -1).length - 1;
        assertEquals(1, occurrences, "token JSON must not contain a duplicate scope claim: " + json);
    }

    @Test
    void transformsSingleScopeToArray() {
        AccessToken token = new AccessToken();
        token.setScope("openid");

        mapper.transformAccessToken(token, mappingModel, null, null, null);

        assertEquals(List.of("openid"), token.getOtherClaims().get("scope"));
    }

    @Test
    void noOpWhenScopeIsMissing() {
        AccessToken token = new AccessToken();
        token.setOtherClaims("sub", "user123");

        mapper.transformAccessToken(token, mappingModel, null, null, null);

        assertNull(token.getOtherClaims().get("scope"));
        assertEquals("user123", token.getOtherClaims().get("sub"));
    }

    @Test
    void handlesExtraWhitespace() {
        AccessToken token = new AccessToken();
        token.setScope("  openid   profile  ");

        mapper.transformAccessToken(token, mappingModel, null, null, null);

        assertEquals(List.of("openid", "profile"), token.getOtherClaims().get("scope"));
    }

    @Test
    void deserializerRoundTripsArrayScopeBackToString() throws Exception {
        // The deserializer is registered at factory startup via init(), not on
        // first token issuance, so a replica can read an array-scope token it
        // never minted. Simulate startup here instead of relying on transform.
        mapper.init(null);

        AccessToken token = new AccessToken();
        token.setScope("openid profile");

        mapper.transformAccessToken(token, mappingModel, null, null, null);

        String json = JsonSerialization.writeValueAsString(token);
        AccessToken deserialized = JsonSerialization.readValue(json, AccessToken.class);

        assertEquals("openid profile", deserialized.getScope());
    }
}
