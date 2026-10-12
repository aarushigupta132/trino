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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.airlift.http.server.HttpConfig;
import io.airlift.http.server.HttpServerConfig;
import io.airlift.http.server.HttpServerInfo;
import io.airlift.http.server.ServerFeature;
import io.airlift.http.server.testing.TestingHttpServer;
import io.airlift.node.NodeConfig;
import io.airlift.node.NodeInfo;
import io.trino.plugin.base.util.AutoCloseableCloser;
import io.trino.spi.security.ConnectorIdentity;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.iceberg.PartitionSpec;
import org.apache.iceberg.Schema;
import org.apache.iceberg.Table;
import org.apache.iceberg.TableMetadata;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.exceptions.ForbiddenException;
import org.apache.iceberg.io.FileIO;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.rest.HTTPClient;
import org.apache.iceberg.rest.RESTSessionCatalog;
import org.apache.iceberg.rest.RESTUtil;
import org.apache.iceberg.rest.RemoteSigningConfigParser;
import org.apache.iceberg.rest.requests.RemoteSignRequest;
import org.apache.iceberg.rest.requests.RemoteSignRequestParser;
import org.apache.iceberg.rest.responses.ConfigResponse;
import org.apache.iceberg.rest.responses.ConfigResponseParser;
import org.apache.iceberg.rest.responses.ImmutableRemoteSignResponse;
import org.apache.iceberg.rest.responses.LoadTableResponse;
import org.apache.iceberg.rest.responses.LoadTableResponseParser;
import org.apache.iceberg.rest.responses.RemoteSignResponseParser;
import org.apache.iceberg.types.Types;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static io.trino.plugin.iceberg.IcebergErrorCode.ICEBERG_CATALOG_ERROR;
import static io.trino.plugin.iceberg.catalog.rest.IcebergRestCatalogS3RemoteSignerProvider.EXTRA_CREDENTIALS_PREFIX;
import static io.trino.testing.assertions.TrinoExceptionAssert.assertTrinoExceptionThrownBy;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static software.amazon.awssdk.http.SdkHttpMethod.GET;
import static software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner.REGION_NAME;

final class TestIcebergRestCatalogS3RemoteSigningAuthentication
{
    private static final String EXPIRED_TOKEN = "eyJhbGciOiJub25lIn0.eyJleHAiOjF9.c2lnbmF0dXJl";
    private static final SignRequest<AwsCredentialsIdentity> REQUEST = SignRequest.<AwsCredentialsIdentity>builder(AnonymousCredentialsProvider.create().resolveCredentials())
            .request(SdkHttpRequest.builder().method(GET).uri(URI.create("https://storage.example/object")).build())
            .putProperty(REGION_NAME, "us-east-1")
            .build();

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testCatalogConfigControlsOAuthAuthentication(boolean overrides)
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            Map<String, String> catalogAuthentication = ImmutableMap.of(
                    "oauth2-server-uri", server.uri("/tenant-token").toString(),
                    "scope", "tenant-scope",
                    "header.x-signer-context", "tenant-catalog");
            ConfigResponse.Builder config = ConfigResponse.builder();
            ImmutableMap.Builder<String, String> localProperties = ImmutableMap.<String, String>builder()
                    .put("token-refresh-enabled", "false");
            if (overrides) {
                config.withOverrides(catalogAuthentication);
                localProperties
                        .put("oauth2-server-uri", server.uri("/bootstrap-token").toString())
                        .put("scope", "metadata-scope")
                        .put("header.x-signer-context", "bootstrap-catalog");
            }
            else {
                config.withDefaults(catalogAuthentication);
            }
            server.servlet.config = config.build();
            server.servlet.tableProperties.put("table", ImmutableMap.of(
                    "oauth2-server-uri", server.uri("/table-token").toString(),
                    "scope", "table-scope"));
            server.servlet.signingAuthorization = "Bearer tenant-token";
            server.initialize(localProperties.buildOrThrow());
            Table table = server.loadTable("table");
            server.clearRequests();

            assertThat(server.sign(table).request().firstMatchingHeader("Authorization")).contains("signed");

            assertThat(server.servlet.tokenRequests).singleElement().satisfies(request -> {
                assertThat(request.path()).isEqualTo("/tenant-token");
                assertThat(request.body()).contains("grant_type=client_credentials", "client_id=catalog-client", "scope=tenant-scope");
                assertThat(request.body()).doesNotContain("scope=metadata-scope", "scope=table-scope");
                assertThat(request.authorization()).isNull();
                assertThat(request.signerContext()).isEqualTo("tenant-catalog");
            });
            assertThat(server.servlet.signingCalls).singleElement().satisfies(call -> {
                assertThat(call.path()).isEqualTo("/catalog/v1/namespaces/test/tables/table/sign");
                assertThat(call.authorization()).isEqualTo("Bearer tenant-token");
                assertThat(call.signerContext()).isEqualTo("table");
            });
        }
    }

    @Test
    void testExplicitTableCredentialRefreshesExpiredToken()
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            server.servlet.tableProperties.put("table", ImmutableMap.of(
                    "token", EXPIRED_TOKEN,
                    "credential", "table-client:table-secret"));
            server.initialize(ImmutableMap.of(
                    "token", "catalog-token",
                    "token-expires-in-ms", "3600000"));
            Table table = server.loadTable("table");
            server.clearRequests();

            assertThat(server.sign(table).request().firstMatchingHeader("Authorization")).contains("signed");

            assertThat(server.servlet.tokenRequests).singleElement().satisfies(request -> {
                assertThat(request.path()).isEqualTo("/catalog/v1/oauth/tokens");
                assertThat(request.body()).contains("grant_type=client_credentials", "client_id=table-client", "client_secret=table-secret");
                assertThat(request.body()).doesNotContain("client_id=catalog-client");
                assertThat(request.authorization()).isNull();
            });
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer table-token");
        }
    }

    @Test
    void testTableCredentialOverridesInheritedCatalogToken()
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            server.servlet.tableProperties.put("table", ImmutableMap.of("credential", "table-client:table-secret"));
            server.initialize(ImmutableMap.of("token", "catalog-token"));
            Table table = server.loadTable("table");
            assertThat(table.io().properties()).containsEntry("token", "catalog-token");
            server.clearRequests();

            assertThat(server.sign(table).request().firstMatchingHeader("Authorization")).contains("signed");

            assertThat(server.servlet.tokenRequests).singleElement().satisfies(request -> {
                assertThat(request.path()).isEqualTo("/catalog/v1/oauth/tokens");
                assertThat(request.body()).contains("grant_type=client_credentials", "client_id=table-client", "client_secret=table-secret");
                assertThat(request.authorization()).isNull();
            });
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer table-token");
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testExpiredTableTokenCannotUseInheritedCatalogCredential(boolean overrideCatalogCredential)
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            if (overrideCatalogCredential) {
                server.servlet.config = ConfigResponse.builder()
                        .withOverride("credential", "tenant-client:tenant-secret")
                        .build();
            }
            server.servlet.tableProperties.put("table", ImmutableMap.of("token", EXPIRED_TOKEN));
            server.initialize(ImmutableMap.of());
            Table table = server.loadTable("table");
            assertThat(table.io().properties()).containsEntry("credential", overrideCatalogCredential ? "tenant-client:tenant-secret" : "catalog-client:catalog-secret");
            server.clearRequests();

            assertTrinoExceptionThrownBy(() -> server.sign(table))
                    .hasErrorCode(ICEBERG_CATALOG_ERROR)
                    .hasMessage("Failed to remotely sign S3 request")
                    .cause()
                    .isInstanceOf(ForbiddenException.class)
                    .hasMessage("Forbidden: Access denied");

            assertThat(server.servlet.tokenRequests).isEmpty();
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer " + EXPIRED_TOKEN);
        }
    }

    @Test
    void testExplicitTableCredentialCanEqualEffectiveCatalogCredential()
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            server.servlet.config = ConfigResponse.builder()
                    .withOverride("credential", "tenant-client:tenant-secret")
                    .build();
            server.servlet.tableProperties.put("table", ImmutableMap.of(
                    "token", EXPIRED_TOKEN,
                    "credential", "tenant-client:tenant-secret"));
            server.servlet.signingAuthorization = "Bearer tenant-token";
            server.initialize(ImmutableMap.of());
            Table table = server.loadTable("table");
            server.clearRequests();

            assertThat(server.sign(table).request().firstMatchingHeader("Authorization")).contains("signed");

            assertThat(server.servlet.tokenRequests).singleElement().satisfies(request -> {
                assertThat(request.path()).isEqualTo("/catalog/v1/oauth/tokens");
                assertThat(request.body()).contains("grant_type=client_credentials", "client_id=tenant-client", "client_secret=tenant-secret");
                assertThat(request.authorization()).isNull();
            });
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer tenant-token");
        }
    }

    @Test
    void testRefreshedTokenIsNotSharedWithTableWithoutCredential()
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            server.servlet.tableProperties.put("delegated", ImmutableMap.of(
                    "token", EXPIRED_TOKEN,
                    "credential", "table-client:table-secret"));
            server.servlet.tableProperties.put("token_only", ImmutableMap.of("token", EXPIRED_TOKEN));
            server.initialize(ImmutableMap.of());
            Table delegated = server.loadTable("delegated");
            server.clearRequests();

            assertThat(server.sign(delegated).request().firstMatchingHeader("Authorization")).contains("signed");
            assertThat(server.servlet.tokenRequests).singleElement().satisfies(request ->
                    assertThat(request.body()).contains("client_id=table-client"));
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer table-token");

            Table tokenOnly = server.loadTable("token_only");
            server.clearRequests();

            assertTrinoExceptionThrownBy(() -> server.sign(tokenOnly))
                    .hasErrorCode(ICEBERG_CATALOG_ERROR)
                    .hasMessage("Failed to remotely sign S3 request")
                    .cause()
                    .isInstanceOf(ForbiddenException.class)
                    .hasMessage("Forbidden: Access denied");

            assertThat(server.servlet.tokenRequests).isEmpty();
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer " + EXPIRED_TOKEN);
        }
    }

    private static final class TestServer
            implements AutoCloseable
    {
        private final AutoCloseableCloser closer = AutoCloseableCloser.create();
        private final CatalogServlet servlet = new CatalogServlet();
        private final TestingHttpServer server;
        private RESTSessionCatalog catalog;
        private IcebergRestCatalogS3RemoteSignerProvider signerProvider;

        public TestServer()
                throws Exception
        {
            NodeInfo nodeInfo = new NodeInfo(new NodeConfig()
                    .setEnvironment("test")
                    .setNodeInternalAddress("127.0.0.1"));
            HttpServerConfig config = new HttpServerConfig().setHttpEnabled(true);
            HttpServerInfo serverInfo = new HttpServerInfo(config, Optional.of(new HttpConfig().setHttpPort(0)), Optional.empty(), nodeInfo);
            server = new TestingHttpServer("remote-signing-authentication", serverInfo, nodeInfo, config, servlet, ServerFeature.builder().build());
            closer.register(server::stop);
            server.start();
        }

        public URI uri(String path)
        {
            return server.getBaseUrl().resolve(path);
        }

        public void initialize(Map<String, String> properties)
        {
            Map<String, String> catalogProperties = ImmutableMap.<String, String>builder()
                    .put("uri", uri("/catalog").toString())
                    .put("credential", "catalog-client:catalog-secret")
                    .put("rest.auth.type", SharedSessionOAuth2Manager.class.getName())
                    .put("token-refresh-enabled", "true")
                    .put("token-exchange-enabled", "false")
                    .put("rest.client.max-retries", "1")
                    .put("s3.remote-signing-enabled", "true")
                    .putAll(properties)
                    .buildKeepingLast();
            catalog = closer.register(new RESTSessionCatalog(
                    config -> HTTPClient.builder(config)
                            .uri(config.get("uri"))
                            .withHeaders(RESTUtil.configHeaders(config))
                            .withObjectMapper(IcebergRestCatalogS3RemoteSigningProperties.objectMapper(config))
                            .build(),
                    (_, config) -> new TestingFileIO(config)));
            catalog.initialize("test", catalogProperties);
            signerProvider = closer.register(new IcebergRestCatalogS3RemoteSignerProvider(catalogProperties));
        }

        public Table loadTable(String name)
        {
            return catalog.loadTable(SessionContext.createEmpty(), TableIdentifier.of("test", name));
        }

        public SignedRequest sign(Table table)
        {
            ImmutableMap.Builder<String, String> credentials = ImmutableMap.builder();
            table.io().properties().forEach((key, value) -> credentials.put(EXTRA_CREDENTIALS_PREFIX + key, value));
            ConnectorIdentity identity = ConnectorIdentity.forUser("test")
                    .withExtraCredentials(credentials.buildOrThrow())
                    .build();
            return signerProvider.getSigner(identity).orElseThrow().sign(REQUEST);
        }

        public void clearRequests()
        {
            servlet.tokenRequests.clear();
            servlet.signingCalls.clear();
        }

        @Override
        public void close()
                throws Exception
        {
            closer.close();
        }
    }

    private static final class CatalogServlet
            extends HttpServlet
    {
        private final Map<String, Map<String, String>> tableProperties = new ConcurrentHashMap<>();
        private final List<TokenRequest> tokenRequests = new CopyOnWriteArrayList<>();
        private final List<SigningCall> signingCalls = new CopyOnWriteArrayList<>();
        private volatile ConfigResponse config = ConfigResponse.builder().build();
        private volatile String signingAuthorization = "Bearer table-token";

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            response.setContentType("application/json");
            if (request.getRequestURI().equals("/catalog/v1/config")) {
                response.getWriter().write(ConfigResponseParser.toJson(config));
                return;
            }
            String tableName = request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1);
            Map<String, String> properties = tableProperties.get(tableName);
            if (properties == null) {
                response.sendError(404);
                return;
            }
            response.getWriter().write(LoadTableResponseParser.toJson(LoadTableResponse.builder()
                    .withTableMetadata(TableMetadata.newTableMetadata(
                            new Schema(Types.NestedField.optional(1, "value", Types.IntegerType.get())),
                            PartitionSpec.unpartitioned(),
                            "s3://bucket/" + tableName,
                            ImmutableMap.of()))
                    .addAllConfig(properties)
                    .withRemoteSigningConfig(RemoteSigningConfigParser.fromJson("{\"headers\":{\"X-Signer-Context\":[\"table\"]}}"))
                    .build()));
        }

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            response.setContentType("application/json");
            String path = request.getRequestURI();
            String body = new String(request.getInputStream().readAllBytes(), UTF_8);
            String authorization = request.getHeader("Authorization");
            String signerContext = request.getHeader("X-Signer-Context");
            if (ImmutableList.of("/bootstrap-token", "/tenant-token", "/catalog/v1/oauth/tokens").contains(path)) {
                tokenRequests.add(new TokenRequest(path, authorization, signerContext, body));
                String token = "catalog-token";
                if (path.equals("/tenant-token")) {
                    if (!body.contains("scope=tenant-scope") || !"tenant-catalog".equals(signerContext)) {
                        forbidden(response);
                        return;
                    }
                    token = "tenant-token";
                }
                else if (body.contains("client_id=table-client")) {
                    token = "table-token";
                }
                else if (body.contains("client_id=tenant-client")) {
                    token = "tenant-token";
                }
                response.getWriter().write("{\"access_token\":\"" + token + "\",\"token_type\":\"bearer\",\"expires_in\":3600}");
                return;
            }
            if (!path.endsWith("/sign")) {
                response.sendError(404);
                return;
            }
            RemoteSignRequest signingRequest = RemoteSignRequestParser.fromJson(body);
            signingCalls.add(new SigningCall(path, authorization, signerContext));
            if (!signingAuthorization.equals(authorization)) {
                forbidden(response);
                return;
            }
            response.getWriter().write(RemoteSignResponseParser.toJson(ImmutableRemoteSignResponse.builder()
                    .uri(signingRequest.uri())
                    .putHeaders("Authorization", ImmutableList.of("signed"))
                    .build()));
        }

        private static void forbidden(HttpServletResponse response)
                throws IOException
        {
            response.setStatus(403);
            response.getWriter().write("{\"error\":{\"message\":\"Access denied\",\"type\":\"ForbiddenException\",\"code\":403}}");
        }
    }

    private record TestingFileIO(Map<String, String> properties)
            implements FileIO
    {
        @Override
        public InputFile newInputFile(String path)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public OutputFile newOutputFile(String path)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteFile(String path)
        {
            throw new UnsupportedOperationException();
        }
    }

    private record TokenRequest(String path, String authorization, String signerContext, String body) {}

    private record SigningCall(String path, String authorization, String signerContext) {}
}
