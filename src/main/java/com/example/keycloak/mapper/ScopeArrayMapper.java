package com.example.keycloak.mapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

public class ScopeArrayMapper extends AbstractOIDCProtocolMapper
        implements OIDCIDTokenMapper, OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "oidc-scope-array-mapper";
    private static final String DISPLAY_TYPE = "Scope String to Array";
    private static final String DISPLAY_CATEGORY = "Token mapper";
    private static final String HELP_TEXT = "Transforms the 'scope' claim from a space-separated string to a JSON array.";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    @Override
    public String getDisplayCategory() {
        return DISPLAY_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel,
                            UserSessionModel userSession, KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {
        Object scopeClaim = token.getOtherClaims().get("scope");
        if (!(scopeClaim instanceof String scopeString)) {
            return;
        }

        List<String> scopeArray = Arrays.asList(scopeString.trim().split("\\s+"));
        token.getOtherClaims().put("scope", scopeArray);
    }

    public static ProtocolMapperModel create(String name, boolean idToken, boolean accessToken) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol("openid-connect");
        Map<String, String> config = Map.of(
                OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, String.valueOf(idToken),
                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, String.valueOf(accessToken)
        );
        mapper.setConfig(config);
        return mapper;
    }
}
