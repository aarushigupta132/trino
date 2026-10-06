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

import com.google.common.collect.ImmutableMap;
import io.airlift.http.server.HttpConfig;
import io.airlift.http.server.HttpServerConfig;
import io.airlift.http.server.HttpServerInfo;
import io.airlift.http.server.ServerFeature;
import io.airlift.http.server.testing.TestingHttpServer;
import io.airlift.node.NodeInfo;
import io.trino.plugin.iceberg.IcebergQueryRunner;
import io.trino.testing.AbstractTestQueryFramework;
import io.trino.testing.DistributedQueryRunner;
import io.trino.testing.QueryRunner;
import io.trino.testing.containers.Minio;
import io.trino.testing.sql.TestTable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.aws.AwsClientProperties;
import org.apache.iceberg.aws.s3.S3FileIO;
import org.apache.iceberg.aws.s3.S3FileIOProperties;
import org.apache.iceberg.catalog.Catalog;
import org.apache.iceberg.jdbc.JdbcCatalog;
import org.apache.iceberg.rest.HTTPRequest;
import org.apache.iceberg.rest.RESTCatalogAdapter;
import org.apache.iceberg.rest.RESTCatalogServlet;
import org.apache.iceberg.rest.RESTResponse;
import org.apache.iceberg.rest.requests.RemoteSignRequest;
import org.apache.iceberg.rest.requests.RemoteSignRequestParser;
import org.apache.iceberg.rest.responses.ErrorResponse;
import org.apache.iceberg.rest.responses.ImmutableRemoteSignResponse;
import org.apache.iceberg.rest.responses.LoadTableResponse;
import org.apache.iceberg.rest.responses.RemoteSignResponseParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.signer.AwsS3V4Signer;
import software.amazon.awssdk.auth.signer.params.AwsS3V4SignerParams;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static io.trino.testing.TestingNames.randomNameSuffix;
import static io.trino.testing.containers.Minio.MINIO_REGION;
import static io.trino.testing.containers.Minio.MINIO_ROOT_PASSWORD;
import static io.trino.testing.containers.Minio.MINIO_ROOT_USER;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.parallel.ExecutionMode.SAME_THREAD;

@Execution(SAME_THREAD)
final class TestIcebergS3RemoteSigningRestCatalog
        extends AbstractTestQueryFramework
{
    private static final String TABLE_TOKEN = "table-signing-token";

    private RemoteSigningServlet servlet;
    private RemoteSigningCatalogAdapter adapter;

    @Override
    protected QueryRunner createQueryRunner()
            throws Exception
    {
        Minio minio = closeAfterClass(Minio.builder().build());
        minio.start();
        String bucket = "test-iceberg-remote-signing-" + randomNameSuffix();
        minio.createBucket(bucket);

        JdbcCatalog backend = closeAfterClass(new JdbcCatalog());
        backend.initialize("backend", ImmutableMap.<String, String>builder()
                .put(CatalogProperties.URI, "jdbc:h2:mem:iceberg_remote_signing_" + randomNameSuffix() + ";DB_CLOSE_DELAY=-1")
                .put(JdbcCatalog.PROPERTY_PREFIX + "username", "user")
                .put(JdbcCatalog.PROPERTY_PREFIX + "password", "password")
                .put(JdbcCatalog.PROPERTY_PREFIX + "schema-version", "V1")
                .put(CatalogProperties.WAREHOUSE_LOCATION, "s3://" + bucket + "/warehouse")
                .put(CatalogProperties.FILE_IO_IMPL, S3FileIO.class.getName())
                .put(S3FileIOProperties.ENDPOINT, minio.getMinioAddress())
                .put(S3FileIOProperties.PATH_STYLE_ACCESS, "true")
                .put(S3FileIOProperties.ACCESS_KEY_ID, MINIO_ROOT_USER)
                .put(S3FileIOProperties.SECRET_ACCESS_KEY, MINIO_ROOT_PASSWORD)
                .put(AwsClientProperties.CLIENT_REGION, MINIO_REGION)
                .buildOrThrow());

        adapter = new RemoteSigningCatalogAdapter(backend);
        servlet = new RemoteSigningServlet(adapter);
        NodeInfo nodeInfo = new NodeInfo("test");
        HttpServerConfig serverConfig = new HttpServerConfig().setHttpEnabled(true);
        HttpServerInfo serverInfo = new HttpServerInfo(serverConfig, Optional.of(new HttpConfig().setHttpPort(0)), Optional.empty(), nodeInfo);
        TestingHttpServer server = new TestingHttpServer("rest-catalog", serverInfo, nodeInfo, serverConfig, servlet, ServerFeature.builder()
                .withLegacyUriCompliance(true)
                .build());
        server.start();
        closeAfterClass(server::stop);

        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .put("iceberg.catalog.type", "rest")
                .put("iceberg.rest-catalog.uri", server.getBaseUrl().toString())
                .put("iceberg.rest-catalog.remote-signing-enabled", "true")
                .put("iceberg.rest-catalog.security", "OAUTH2")
                .put("iceberg.rest-catalog.oauth2.token", "catalog-token")
                .put("iceberg.rest-catalog.oauth2.token-refresh-enabled", "false")
                .put("fs.s3.enabled", "true")
                .put("s3.endpoint", minio.getMinioAddress())
                .put("s3.region", MINIO_REGION)
                .put("s3.path-style-access", "true")
                .buildOrThrow();
        DistributedQueryRunner queryRunner = IcebergQueryRunner.builder()
                .setWorkerCount(1)
                .addCoordinatorProperty("node-scheduler.include-coordinator", "false")
                .setIcebergProperties(properties)
                .build();
        queryRunner.createCatalog("unsigned", "iceberg", ImmutableMap.<String, String>builder()
                .putAll(properties)
                .put("iceberg.rest-catalog.remote-signing-enabled", "false")
                .buildKeepingLast());
        return queryRunner;
    }

    @BeforeEach
    void resetSignRequests()
    {
        servlet.signRequests.clear();
        adapter.delegationRequests.set(0);
    }

    @Test
    void testCreateInsertAndRead()
    {
        try (TestTable table = newTrinoTable("test_remote_signing", "AS SELECT * FROM tpch.tiny.nation")) {
            assertThat(servlet.signRequests).anySatisfy(request -> assertThat(request.method()).isEqualTo("PUT"));
            assertThat(adapter.delegationRequests.get()).isGreaterThan(0);

            servlet.signRequests.clear();
            assertUpdate("INSERT INTO " + table.getName() + " SELECT * FROM tpch.tiny.nation", 25);
            assertThat(servlet.signRequests).anySatisfy(request -> assertThat(request.method()).isEqualTo("PUT"));

            servlet.signRequests.clear();
            assertQuery("SELECT * FROM " + table.getName(), "SELECT * FROM nation UNION ALL SELECT * FROM nation");
            assertThat(servlet.signRequests).anySatisfy(request -> {
                assertThat(request.method()).isEqualTo("GET");
                assertThat(request.uri().getPath()).endsWith(".parquet");
            });
        }
    }

    @Test
    void testRemoteSigningRequired()
    {
        try (TestTable table = newTrinoTable("test_remote_signing_required", "AS SELECT * FROM tpch.tiny.nation")) {
            servlet.signRequests.clear();
            assertQueryFails(
                    "SELECT * FROM unsigned.tpch." + table.getName(),
                    "Table requires remote signing; enable iceberg.rest-catalog.remote-signing-enabled");
            assertThat(servlet.signRequests).isEmpty();
        }
    }

    @Test
    void testStorageRejectsInvalidSignature()
    {
        try (TestTable table = newTrinoTable("test_invalid_signature", "AS SELECT * FROM tpch.tiny.nation")) {
            servlet.signRequests.clear();
            servlet.signingSecret = "incorrect-secret";
            try {
                assertThatThrownBy(() -> getQueryRunner().execute("SELECT * FROM " + table.getName()))
                        .hasStackTraceContaining("The request signature we calculated does not match");
                assertThat(servlet.signRequests).isNotEmpty();
            }
            finally {
                servlet.signingSecret = MINIO_ROOT_PASSWORD;
            }
        }
    }

    private static final class RemoteSigningCatalogAdapter
            extends RESTCatalogAdapter
    {
        private final AtomicInteger delegationRequests = new AtomicInteger();

        private RemoteSigningCatalogAdapter(Catalog delegate)
        {
            super(delegate);
        }

        @Override
        protected <T extends RESTResponse> T execute(
                HTTPRequest request,
                Class<T> responseType,
                Consumer<ErrorResponse> errorHandler,
                Consumer<Map<String, String>> responseHeaders)
        {
            T response = super.execute(request, responseType, errorHandler, responseHeaders);
            if (response instanceof LoadTableResponse table) {
                if (request.headers().entries("X-Iceberg-Access-Delegation").stream()
                        .anyMatch(header -> header.value().contains("remote-signing"))) {
                    delegationRequests.incrementAndGet();
                }
                return responseType.cast(LoadTableResponse.builder()
                        .withTableMetadata(table.tableMetadata())
                        .addAllConfig(table.config())
                        .addConfig(S3FileIOProperties.REMOTE_SIGNING_ENABLED, "true")
                        .addConfig("token", TABLE_TOKEN)
                        .build());
            }
            return response;
        }
    }

    @SuppressWarnings("deprecation")
    private static final class RemoteSigningServlet
            extends RESTCatalogServlet
    {
        private final AwsS3V4Signer signer = AwsS3V4Signer.create();
        private final List<RemoteSignRequest> signRequests = new CopyOnWriteArrayList<>();
        private volatile String signingSecret = MINIO_ROOT_PASSWORD;

        private RemoteSigningServlet(RESTCatalogAdapter adapter)
        {
            super(adapter);
        }

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            if (!request.getRequestURI().equals("/v1/aws/s3/sign")) {
                super.doPost(request, response);
                return;
            }
            if (!("Bearer " + TABLE_TOKEN).equals(request.getHeader("Authorization"))) {
                response.setStatus(403);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":{\"message\":\"Table token required\",\"type\":\"ForbiddenException\",\"code\":403}}");
                return;
            }

            RemoteSignRequest signRequest = RemoteSignRequestParser.fromJson(new String(request.getInputStream().readAllBytes(), UTF_8));
            signRequests.add(signRequest);
            SdkHttpFullRequest.Builder unsigned = SdkHttpFullRequest.builder()
                    .method(SdkHttpMethod.fromValue(signRequest.method()))
                    .uri(signRequest.uri())
                    .headers(signRequest.headers());
            if (signRequest.body() != null) {
                unsigned.contentStreamProvider(ContentStreamProvider.fromUtf8String(signRequest.body()));
            }
            SdkHttpFullRequest signed = signer.sign(unsigned.build(), AwsS3V4SignerParams.builder()
                    .awsCredentials(AwsBasicCredentials.create(MINIO_ROOT_USER, signingSecret))
                    .signingName("s3")
                    .signingRegion(Region.of(signRequest.region()))
                    .doubleUrlEncode(false)
                    .normalizePath(false)
                    .enablePayloadSigning(false)
                    .enableChunkedEncoding(false)
                    .build());
            response.setContentType("application/json");
            response.getWriter().write(RemoteSignResponseParser.toJson(ImmutableRemoteSignResponse.builder()
                    .uri(signed.getUri())
                    .headers(signed.headers())
                    .build()));
        }
    }
}
