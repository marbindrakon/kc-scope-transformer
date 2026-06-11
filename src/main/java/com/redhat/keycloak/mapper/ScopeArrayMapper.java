package com.redhat.keycloak.mapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.Config;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;

public class ScopeArrayMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper {

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

    // Runs once per factory at server startup, on every replica. Registering the
    // deserializer here (rather than lazily on first token issuance) ensures any
    // instance can deserialize an array-scope token presented to it, even if it
    // never issued one itself.
    @Override
    public void init(Config.Scope config) {
        injectAccessTokenDeserializer();
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel,
                                            KeycloakSession keycloakSession, UserSessionModel userSession,
                                            ClientSessionContext clientSessionCtx) {
        String scope = token.getScope();
        if (scope == null || scope.isBlank()) {
            return token;
        }

        List<String> scopeArray = Arrays.asList(scope.trim().split("\\s+"));
        // Clear the native field: it serializes via its own getter, so leaving it
        // set would emit a second, duplicate "scope" key alongside the array.
        token.setScope(null);
        token.getOtherClaims().put("scope", scopeArray);
        return token;
    }

    // Adapted from https://github.com/amiv1/keycloak-custom-scopes-extension (public domain)
    private static void injectAccessTokenDeserializer() {
        ObjectMapper plainMapper = new ObjectMapper();
        SimpleModule module = new SimpleModule("access-token-scope-deserializer");
        module.addDeserializer(AccessToken.class, new JsonDeserializer<>() {
            @Override
            public AccessToken deserialize(JsonParser jsonParser, DeserializationContext ctx) throws IOException {
                ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
                ObjectNode root = mapper.readTree(jsonParser);

                JsonNode scopeNode = root.get("scope");
                if (scopeNode instanceof ArrayNode arrayNode) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < arrayNode.size(); i++) {
                        if (i > 0) sb.append(' ');
                        sb.append(arrayNode.get(i).asText());
                    }
                    root.put("scope", sb.toString());
                }

                return plainMapper.treeToValue(root, AccessToken.class);
            }
        });
        JsonSerialization.mapper.registerModule(module);
    }

    public static ProtocolMapperModel create(String name) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol("openid-connect");
        Map<String, String> config = Map.of(
                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true"
        );
        mapper.setConfig(config);
        return mapper;
    }
}
