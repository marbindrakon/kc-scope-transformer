package com.example.keycloak.mapper;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.representations.IDToken;

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
        IDToken token = new IDToken();
        token.setOtherClaims("scope", "openid profile email");

        mapper.setClaim(token, mappingModel, null, null, null);

        assertEquals(List.of("openid", "profile", "email"), token.getOtherClaims().get("scope"));
    }

    @Test
    void transformsSingleScopeToArray() {
        IDToken token = new IDToken();
        token.setOtherClaims("scope", "openid");

        mapper.setClaim(token, mappingModel, null, null, null);

        assertEquals(List.of("openid"), token.getOtherClaims().get("scope"));
    }

    @Test
    void noOpWhenScopeClaimIsMissing() {
        IDToken token = new IDToken();
        token.setOtherClaims("sub", "user123");

        mapper.setClaim(token, mappingModel, null, null, null);

        assertNull(token.getOtherClaims().get("scope"));
        assertEquals("user123", token.getOtherClaims().get("sub"));
    }

    @Test
    void noOpWhenScopeClaimIsNotAString() {
        IDToken token = new IDToken();
        List<String> existingArray = List.of("openid", "profile");
        token.setOtherClaims("scope", existingArray);

        mapper.setClaim(token, mappingModel, null, null, null);

        assertSame(existingArray, token.getOtherClaims().get("scope"));
    }

    @Test
    void handlesExtraWhitespace() {
        IDToken token = new IDToken();
        token.setOtherClaims("scope", "  openid   profile  ");

        mapper.setClaim(token, mappingModel, null, null, null);

        assertEquals(List.of("openid", "profile"), token.getOtherClaims().get("scope"));
    }
}
