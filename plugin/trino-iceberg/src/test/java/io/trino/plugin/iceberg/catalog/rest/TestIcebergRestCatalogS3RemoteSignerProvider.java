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
import io.airlift.node.NodeInfo;
import io.trino.spi.security.ConnectorIdentity;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.iceberg.exceptions.ForbiddenException;
import org.apache.iceberg.rest.requests.RemoteSignRequest;
import org.apache.iceberg.rest.requests.RemoteSignRequestParser;
import org.apache.iceberg.rest.responses.ImmutableRemoteSignResponse;
import org.apache.iceberg.rest.responses.RemoteSignResponseParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import static io.trino.plugin.iceberg.catalog.rest.IcebergRestCatalogS3RemoteSignerProvider.EXTRA_CREDENTIALS_PREFIX;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.iceberg.rest.RESTCatalogProperties.REMOTE_SIGNING_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static software.amazon.awssdk.auth.signer.AwsSignerExecutionAttribute.SIGNING_REGION;
import static software.amazon.awssdk.http.SdkHttpMethod.GET;
import static software.amazon.awssdk.http.SdkHttpMethod.PUT;
import static software.amazon.awssdk.regions.Region.US_EAST_1;

@SuppressWarnings("deprecation")
final class TestIcebergRestCatalogS3RemoteSignerProvider
{
    private static final String SIGNER_ENDPOINT = "v1/warehouse/namespaces/test/tables/table/sign";
    private static final URI OBJECT_URI = URI.create("https://storage.example/old/object%20%2B.txt?old=removed");
    private static final URI SIGNED_URI = URI.create("https://signed.example/new/object%20%2B.txt?signature=returned");
    private static final SdkHttpFullRequest REQUEST = SdkHttpFullRequest.builder().method(GET).uri(OBJECT_URI).build();
    private static final String EXPIRED_TOKEN = "eyJhbGciOiJub25lIn0.eyJleHAiOjF9.c2lnbmF0dXJl";

    @Test
    void testReturnedUriAndHeaders()
            throws Exception
    {
        String body = "object contents";
        SdkHttpFullRequest request = REQUEST.toBuilder()
                .method(PUT)
                .putHeader("X-Replaced", "original")
                .putHeader("X-Unsigned", "preserved")
                .contentStreamProvider(ContentStreamProvider.fromUtf8String(body))
                .build();
        try (TestServer server = new TestServer()) {
            SdkHttpFullRequest signed = server.sign(ImmutableMap.of("token", "alice"), request);

            assertThat(server.servlet.signingCalls).singleElement().satisfies(call -> {
                assertThat(call.request().provider()).isEqualTo("s3");
                assertThat(call.request().region()).isEqualTo("us-east-1");
                assertThat(call.request().method()).isEqualTo("PUT");
                assertThat(call.request().uri()).isEqualTo(OBJECT_URI);
                assertThat(call.request().headers()).containsEntry("X-Replaced", ImmutableList.of("original"));
                assertThat(call.request().body()).isNull();
            });
            assertThat(signed.getUri()).isEqualTo(SIGNED_URI);
            assertThat(signed.rawQueryParameters()).doesNotContainKey("old");
            assertThat(signed.method()).isEqualTo(PUT);
            assertThat(signed.firstMatchingHeader("Authorization")).contains("signed-alice");
            assertThat(signed.firstMatchingHeader("X-Replaced")).contains("returned");
            assertThat(signed.headers().keySet()).filteredOn(name -> name.equalsIgnoreCase("X-Replaced")).hasSize(1);
            assertThat(signed.firstMatchingHeader("X-Unsigned")).contains("preserved");
            try (InputStream input = signed.contentStreamProvider().orElseThrow().newStream()) {
                assertThat(new String(input.readAllBytes(), UTF_8)).isEqualTo(body);
            }
        }
    }

    @Test
    void testSignaturesAreNotSharedBetweenTokens()
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            assertThat(server.sign("alice").firstMatchingHeader("Authorization")).contains("signed-alice");
            assertThat(server.sign("bob").firstMatchingHeader("Authorization")).contains("signed-bob");
            assertThatThrownBy(() -> server.sign("denied"))
                    .isInstanceOf(ForbiddenException.class)
                    .hasMessage("Forbidden: Access denied");

            assertThat(server.servlet.signingCalls)
                    .extracting(SigningCall::authorization)
                    .containsExactly("Bearer alice", "Bearer bob", "Bearer denied");
            assertThat(server.servlet.signingCalls)
                    .extracting(call -> call.request().uri())
                    .containsOnly(OBJECT_URI);
        }
    }

    @Test
    void testCatalogTokenWithoutTableToken()
            throws Exception
    {
        try (TestServer server = new TestServer(ImmutableMap.of("token", "alice"))) {
            server.sign(ImmutableMap.of(), REQUEST);
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer alice");
        }
    }

    @Test
    void testExpiredTableTokenCannotRefreshWithCatalogCredential()
            throws Exception
    {
        try (TestServer server = new TestServer(ImmutableMap.of(
                "token", "catalog-token",
                "credential", "catalog-client:catalog-secret",
                "token-refresh-enabled", "true",
                "token-exchange-enabled", "false"))) {
            assertThatThrownBy(() -> server.sign(EXPIRED_TOKEN))
                    .isInstanceOf(ForbiddenException.class)
                    .hasMessage("Forbidden: Access denied");

            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer " + EXPIRED_TOKEN);
            assertThat(server.servlet.tokenRequests).isEmpty();
        }
    }

    @Test
    void testTableTokenOverridesCatalogAuthorizationHeader()
            throws Exception
    {
        try (TestServer server = new TestServer(ImmutableMap.of(
                "token", "catalog-token",
                "header.authorization", "Bearer catalog-service"))) {
            assertThat(server.sign("alice").firstMatchingHeader("Authorization")).contains("signed-alice");
            assertThatThrownBy(() -> server.sign("denied"))
                    .isInstanceOf(ForbiddenException.class)
                    .hasMessage("Forbidden: Access denied");

            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer alice", "Bearer denied");
        }
    }

    @Test
    void testConfiguredAuthorizationHeaderWithoutToken()
            throws Exception
    {
        try (TestServer server = new TestServer(ImmutableMap.of("header.authorization", "Bearer alice"))) {
            assertThat(server.sign(ImmutableMap.of(), REQUEST).firstMatchingHeader("Authorization")).contains("signed-alice");
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer alice");
        }
    }

    @Test
    void testTokenRefreshUsesCatalogScope()
            throws Exception
    {
        try (TestServer server = new TestServer(ImmutableMap.of(
                "token", EXPIRED_TOKEN,
                "credential", "catalog-client:catalog-secret",
                "scope", "catalog-scope",
                "token-refresh-enabled", "true",
                "token-exchange-enabled", "false"))) {
            server.sign(ImmutableMap.of("token", EXPIRED_TOKEN, "scope", "table-scope"), REQUEST);

            assertThat(server.servlet.tokenRequests).singleElement().satisfies(body ->
                    assertThat(body)
                            .contains("grant_type=client_credentials", "scope=catalog-scope")
                            .doesNotContain("scope=sign", "scope=table-scope"));
            assertThat(server.servlet.signingCalls).extracting(SigningCall::authorization).containsExactly("Bearer alice");
        }
    }

    @ParameterizedTest
    @CsvSource({
            "POST, delete, <Delete><Object><Key>first</Key></Object><Object><Key>second</Key></Object></Delete>, true",
            "PUT, '', object contents, false",
            "POST, uploads, '', false",
            "PUT, partNumber=1&uploadId=upload, part contents, false",
            "POST, uploadId=upload, <CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>part</ETag></Part></CompleteMultipartUpload>, false",
    })
    void testRequestBody(SdkHttpMethod method, String query, String body, boolean includeBody)
            throws Exception
    {
        URI uri = URI.create("https://storage.example/object" + (query.isEmpty() ? "" : "?" + query));
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .method(method)
                .uri(uri)
                .contentStreamProvider(ContentStreamProvider.fromUtf8String(body))
                .build();
        try (TestServer server = new TestServer()) {
            SdkHttpFullRequest signed = server.sign(ImmutableMap.of("token", "alice"), request);

            assertThat(server.servlet.signingCalls).singleElement().satisfies(call ->
                    assertThat(call.request().body()).isEqualTo(includeBody ? body : null));
            try (InputStream input = signed.contentStreamProvider().orElseThrow().newStream()) {
                assertThat(new String(input.readAllBytes(), UTF_8)).isEqualTo(body);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testSignerEndpoint(boolean absolute)
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            String endpoint = SIGNER_ENDPOINT;
            String expectedPath = "/catalog/" + SIGNER_ENDPOINT;
            if (absolute) {
                endpoint = server.server.getBaseUrl().resolve("/absolute/sign").toString();
                expectedPath = "/absolute/sign";
            }
            server.sign(ImmutableMap.of("token", "alice", REMOTE_SIGNING_ENDPOINT, endpoint), REQUEST);
            assertThat(server.servlet.signingCalls).extracting(SigningCall::path).containsExactly(expectedPath);
        }
    }

    @Test
    void testSignerRequiresEndpoint()
            throws Exception
    {
        try (TestServer server = new TestServer()) {
            assertThatThrownBy(() -> server.signerProvider.getSigner(identity(ImmutableMap.of("token", "alice"))))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage("signer endpoint is null");
            assertThat(server.servlet.signingCalls).isEmpty();
        }
    }

    private static ConnectorIdentity identity(Map<String, String> properties)
    {
        ImmutableMap.Builder<String, String> credentials = ImmutableMap.builder();
        properties.forEach((key, value) -> credentials.put(EXTRA_CREDENTIALS_PREFIX + key, value));
        return ConnectorIdentity.forUser("test").withExtraCredentials(credentials.buildOrThrow()).build();
    }

    private static final class TestServer
            implements AutoCloseable
    {
        private final SigningServlet servlet = new SigningServlet();
        private final TestingHttpServer server;
        private final IcebergRestCatalogS3RemoteSignerProvider signerProvider;

        public TestServer()
                throws Exception
        {
            this(ImmutableMap.of("token", "catalog-token"));
        }

        public TestServer(Map<String, String> properties)
                throws Exception
        {
            NodeInfo nodeInfo = new NodeInfo("test");
            HttpServerConfig config = new HttpServerConfig().setHttpEnabled(true);
            HttpServerInfo serverInfo = new HttpServerInfo(config, Optional.of(new HttpConfig().setHttpPort(0)), Optional.empty(), nodeInfo);
            server = new TestingHttpServer("remote-signing", serverInfo, nodeInfo, config, servlet, ServerFeature.builder().build());
            server.start();
            signerProvider = new IcebergRestCatalogS3RemoteSignerProvider(ImmutableMap.<String, String>builder()
                    .put("uri", server.getBaseUrl().resolve("/catalog").toString())
                    .put("rest.auth.type", "oauth2")
                    .put("token-refresh-enabled", "false")
                    .put("rest.client.max-retries", "1")
                    .putAll(properties)
                    .buildKeepingLast());
        }

        public SdkHttpFullRequest sign(String token)
        {
            return sign(ImmutableMap.of("token", token), REQUEST);
        }

        public SdkHttpFullRequest sign(Map<String, String> properties, SdkHttpFullRequest request)
        {
            Map<String, String> signerProperties = ImmutableMap.<String, String>builder()
                    .put(REMOTE_SIGNING_ENDPOINT, SIGNER_ENDPOINT)
                    .putAll(properties)
                    .buildKeepingLast();
            return signerProvider.getSigner(identity(signerProperties)).orElseThrow()
                    .sign(request, new ExecutionAttributes().putAttribute(SIGNING_REGION, US_EAST_1));
        }

        @Override
        public void close()
                throws Exception
        {
            try {
                signerProvider.close();
            }
            finally {
                server.stop();
            }
        }
    }

    private static final class SigningServlet
            extends HttpServlet
    {
        private final List<SigningCall> signingCalls = new CopyOnWriteArrayList<>();
        private final List<String> tokenRequests = new CopyOnWriteArrayList<>();

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            response.setContentType("application/json");
            if (request.getRequestURI().equals("/catalog/v1/oauth/tokens")) {
                tokenRequests.add(new String(request.getInputStream().readAllBytes(), UTF_8));
                response.getWriter().write("{\"access_token\":\"alice\",\"token_type\":\"bearer\",\"expires_in\":3600}");
                return;
            }

            RemoteSignRequest signingRequest = RemoteSignRequestParser.fromJson(new String(request.getInputStream().readAllBytes(), UTF_8));
            String authorization = request.getHeader("Authorization");
            signingCalls.add(new SigningCall(request.getRequestURI(), authorization, signingRequest));
            response.setHeader("Cache-Control", "private");
            if (!ImmutableList.of("Bearer alice", "Bearer bob").contains(authorization)) {
                response.setStatus(403);
                response.getWriter().write("{\"error\":{\"message\":\"Access denied\",\"type\":\"ForbiddenException\",\"code\":403}}");
                return;
            }
            response.getWriter().write(RemoteSignResponseParser.toJson(ImmutableRemoteSignResponse.builder()
                    .uri(SIGNED_URI)
                    .putHeaders("Authorization", ImmutableList.of("signed-" + authorization.substring("Bearer ".length())))
                    .putHeaders("x-replaced", ImmutableList.of("returned"))
                    .build()));
        }
    }

    private record SigningCall(String path, String authorization, RemoteSignRequest request) {}
}
