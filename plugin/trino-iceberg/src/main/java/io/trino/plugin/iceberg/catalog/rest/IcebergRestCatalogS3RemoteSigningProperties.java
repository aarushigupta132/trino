/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.iceberg.catalog.rest;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import io.airlift.json.JsonCodec;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.rest.RESTSerializers;
import org.apache.iceberg.rest.RESTUtil;
import org.apache.iceberg.rest.ResourcePaths;
import org.apache.iceberg.rest.auth.AuthProperties;
import org.apache.iceberg.rest.auth.OAuth2Properties;
import org.apache.iceberg.rest.auth.OAuth2Util;
import org.apache.iceberg.rest.responses.LoadTableResponse;
import org.apache.iceberg.rest.responses.LoadTableResponseParser;
import org.apache.iceberg.util.JsonUtil;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import static io.airlift.json.JsonCodec.mapJsonCodec;

final class IcebergRestCatalogS3RemoteSigningProperties
{
    static final String AUTHENTICATION_PROPERTY = "internal$iceberg_rest_s3_signer_authentication$";

    private static final JsonCodec<Map<String, String>> AUTHENTICATION_CODEC = mapJsonCodec(String.class, String.class);
    private static final Set<String> TABLE_AUTHENTICATION_PROPERTIES = ImmutableSet.of(
            OAuth2Properties.TOKEN,
            OAuth2Properties.CREDENTIAL,
            OAuth2Properties.TOKEN_EXPIRES_IN_MS);

    private IcebergRestCatalogS3RemoteSigningProperties() {}

    static ObjectMapper objectMapper(Map<String, String> effectiveCatalogProperties)
    {
        Map<String, String> catalogProperties = ImmutableMap.copyOf(Maps.filterKeys(effectiveCatalogProperties, key -> !key.equals(AUTHENTICATION_PROPERTY)));
        // Match Iceberg's package-private RESTObjectMapper.
        JsonFactory factory = JsonFactory.builder()
                .configure(JsonFactory.Feature.INTERN_FIELD_NAMES, false)
                .configure(JsonFactory.Feature.FAIL_ON_SYMBOL_HASH_OVERFLOW, false)
                .build();
        ObjectMapper mapper = JsonMapper.builder(factory)
                .visibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .propertyNamingStrategy(new PropertyNamingStrategies.KebabCaseStrategy())
                .build();
        RESTSerializers.registerAll(mapper);
        return mapper.registerModule(new SimpleModule()
                .addDeserializer(LoadTableResponse.class, new JsonDeserializer<>()
                {
                    @Override
                    public LoadTableResponse deserialize(JsonParser parser, DeserializationContext context)
                            throws IOException
                    {
                        JsonNode response = parser.getCodec().readTree(parser);
                        Map<String, String> tableProperties = response.hasNonNull("config")
                                ? JsonUtil.getStringMap("config", response)
                                : ImmutableMap.of();
                        // Preserve authentication before Iceberg merges table and catalog properties.
                        ((ObjectNode) response).withObject("/config")
                                .put(AUTHENTICATION_PROPERTY, encodeAuthenticationProperties(catalogProperties, tableProperties));
                        return LoadTableResponseParser.fromJson(response);
                    }
                }));
    }

    static Map<String, String> authenticationProperties(Map<String, String> catalogProperties, Map<String, String> tableProperties)
    {
        Map<String, String> properties = new HashMap<>(catalogProperties);
        properties.remove(AUTHENTICATION_PROPERTY);
        properties.putIfAbsent(AuthProperties.AUTH_TYPE, AuthProperties.AUTH_TYPE_OAUTH2);
        properties.putAll(OAuth2Util.buildOptionalParam(catalogProperties, "sign"));
        properties.put(OAuth2Properties.OAUTH2_SERVER_URI, RESTUtil.resolveEndpoint(
                catalogProperties.get(CatalogProperties.URI),
                catalogProperties.getOrDefault(OAuth2Properties.OAUTH2_SERVER_URI, ResourcePaths.tokens())));
        if (tableProperties.containsKey(OAuth2Properties.TOKEN)) {
            properties.remove(OAuth2Properties.CREDENTIAL);
            properties.remove(OAuth2Properties.TOKEN_EXPIRES_IN_MS);
        }
        if (tableProperties.containsKey(OAuth2Properties.CREDENTIAL)) {
            properties.remove(OAuth2Properties.TOKEN);
            properties.remove(OAuth2Properties.TOKEN_EXPIRES_IN_MS);
        }
        for (String property : TABLE_AUTHENTICATION_PROPERTIES) {
            String value = tableProperties.get(property);
            if (value != null) {
                properties.put(property, value);
            }
        }
        return ImmutableMap.copyOf(properties);
    }

    static String encodeAuthenticationProperties(Map<String, String> catalogProperties, Map<String, String> tableProperties)
    {
        return AUTHENTICATION_CODEC.toJson(new TreeMap<>(authenticationProperties(catalogProperties, tableProperties)));
    }

    static Map<String, String> decodeAuthenticationProperties(String properties)
    {
        return ImmutableMap.copyOf(AUTHENTICATION_CODEC.fromJson(properties));
    }
}
