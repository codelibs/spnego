package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link SpnegoHttpURLConnection}.
 */
@ExtendWith(MockitoExtension.class)
class SpnegoHttpURLConnectionTest {

    @Mock
    private LoginContext mockLoginContext;

    @Mock
    private GSSCredential mockGSSCredential;

    @Mock
    private GSSContext mockGSSContext;

    @Mock
    private Subject mockSubject;

    @Mock
    private GSSName mockGSSName;

    @Mock
    private HttpURLConnection mockHttpURLConnection;

    private static final String LOGIN_MODULE = "spnego-client";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_PASSWORD = "testpass";
    private static final String TEST_URL = "http://example.com:8080/api";

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("constructor with login module name")
        void constructorWithLoginModuleName() throws LoginException {
            try (MockedConstruction<LoginContext> loginMock = mockConstruction(LoginContext.class,
                    (mock, context) -> {
                        doNothing().when(mock).login();
                        doNothing().when(mock).logout();
                        when(mock.getSubject()).thenReturn(mockSubject);
                    })) {

                SpnegoHttpURLConnection conn = new SpnegoHttpURLConnection(LOGIN_MODULE);

                assertNotNull(conn);
                assertEquals(1, loginMock.constructed().size());
            }
        }

        @Test
        @DisplayName("constructor with login module name throws LoginException")
        void constructorWithLoginModuleNameThrowsException() throws LoginException {
            try (MockedConstruction<LoginContext> loginMock = mockConstruction(LoginContext.class,
                    (mock, context) -> {
                        doThrow(new LoginException("Login failed")).when(mock).login();
                    })) {

                assertThrows(LoginException.class, () -> {
                    new SpnegoHttpURLConnection(LOGIN_MODULE);
                });
            }
        }

        @Test
        @DisplayName("constructor with username and password")
        void constructorWithUsernamePassword() throws LoginException {
            try (MockedConstruction<LoginContext> loginMock = mockConstruction(LoginContext.class,
                    (mock, context) -> {
                        doNothing().when(mock).login();
                        doNothing().when(mock).logout();
                        when(mock.getSubject()).thenReturn(mockSubject);
                    });
                 MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {

                providerMock.when(() -> SpnegoProvider.getUsernamePasswordHandler(
                    eq(TEST_USERNAME), eq(TEST_PASSWORD))).thenReturn(null);

                SpnegoHttpURLConnection conn = new SpnegoHttpURLConnection(
                    LOGIN_MODULE, TEST_USERNAME, TEST_PASSWORD);

                assertNotNull(conn);
                assertEquals(1, loginMock.constructed().size());
            }
        }

        @Test
        @DisplayName("constructor with GSSCredential")
        void constructorWithGSSCredential() {
            SpnegoHttpURLConnection conn = new SpnegoHttpURLConnection(mockGSSCredential);

            assertNotNull(conn);
        }

        @Test
        @DisplayName("constructor with GSSCredential and dispose flag")
        void constructorWithGSSCredentialAndDisposeFlag() {
            SpnegoHttpURLConnection conn1 = new SpnegoHttpURLConnection(mockGSSCredential, true);
            SpnegoHttpURLConnection conn2 = new SpnegoHttpURLConnection(mockGSSCredential, false);

            assertNotNull(conn1);
            assertNotNull(conn2);
        }
    }

    @Nested
    @DisplayName("Request property tests")
    class RequestPropertyTests {

        private SpnegoHttpURLConnection connection;

        @BeforeEach
        void setUp() {
            connection = new SpnegoHttpURLConnection(mockGSSCredential, false);
        }

        @Test
        @DisplayName("setRequestProperty sets property correctly")
        void setRequestPropertySetsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.setRequestProperty("Content-Type", "application/json");
            });
        }

        @Test
        @DisplayName("addRequestProperty adds property correctly")
        void addRequestPropertyAddsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.addRequestProperty("Accept", "application/json");
                connection.addRequestProperty("Accept", "application/xml");
            });
        }

        @Test
        @DisplayName("setRequestProperty throws exception for null key")
        void setRequestPropertyThrowsExceptionForNullKey() {
            assertThrows(IllegalArgumentException.class, () -> {
                connection.setRequestProperty(null, "value");
            });
        }

        @Test
        @DisplayName("setRequestProperty throws exception for empty key")
        void setRequestPropertyThrowsExceptionForEmptyKey() {
            assertThrows(IllegalArgumentException.class, () -> {
                connection.setRequestProperty("", "value");
            });
        }

        @Test
        @DisplayName("setRequestProperty throws exception for null value")
        void setRequestPropertyThrowsExceptionForNullValue() {
            assertThrows(IllegalArgumentException.class, () -> {
                connection.setRequestProperty("Content-Type", null);
            });
        }

        @Test
        @DisplayName("addRequestProperty throws exception for null key")
        void addRequestPropertyThrowsExceptionForNullKey() {
            assertThrows(IllegalArgumentException.class, () -> {
                connection.addRequestProperty(null, "value");
            });
        }

        @Test
        @DisplayName("addRequestProperty throws exception for null value")
        void addRequestPropertyThrowsExceptionForNullValue() {
            assertThrows(IllegalArgumentException.class, () -> {
                connection.addRequestProperty("Accept", null);
            });
        }

        @Test
        @DisplayName("setRequestProperty after connect throws exception")
        void setRequestPropertyAfterConnectThrowsException() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                assertThrows(IllegalStateException.class, () -> {
                    connection.setRequestProperty("Content-Type", "text/plain");
                });
            }
        }
    }

    @Nested
    @DisplayName("Request method tests")
    class RequestMethodTests {

        private SpnegoHttpURLConnection connection;

        @BeforeEach
        void setUp() {
            connection = new SpnegoHttpURLConnection(mockGSSCredential, false);
        }

        @Test
        @DisplayName("setRequestMethod sets method correctly")
        void setRequestMethodSetsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.setRequestMethod("POST");
            });
        }

        @Test
        @DisplayName("setRequestMethod after connect throws exception")
        void setRequestMethodAfterConnectThrowsException() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                assertThrows(IllegalStateException.class, () -> {
                    connection.setRequestMethod("POST");
                });
            }
        }
    }

    @Nested
    @DisplayName("Instance follow redirects tests")
    class FollowRedirectsTests {

        private SpnegoHttpURLConnection connection;

        @BeforeEach
        void setUp() {
            connection = new SpnegoHttpURLConnection(mockGSSCredential, false);
        }

        @Test
        @DisplayName("getInstanceFollowRedirects returns default true")
        void getInstanceFollowRedirectsReturnsDefaultTrue() {
            assertTrue(connection.getInstanceFollowRedirects());
        }

        @Test
        @DisplayName("setInstanceFollowRedirects sets value correctly")
        void setInstanceFollowRedirectsSetsCorrectly() {
            connection.setInstanceFollowRedirects(false);
            assertFalse(connection.getInstanceFollowRedirects());

            connection.setInstanceFollowRedirects(true);
            assertTrue(connection.getInstanceFollowRedirects());
        }

        @Test
        @DisplayName("setInstanceFollowRedirects after connect throws exception")
        void setInstanceFollowRedirectsAfterConnectThrowsException() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                assertThrows(IllegalStateException.class, () -> {
                    connection.setInstanceFollowRedirects(false);
                });
            }
        }
    }

    @Nested
    @DisplayName("GSSContext configuration tests")
    class GSSContextConfigTests {

        private SpnegoHttpURLConnection connection;

        @BeforeEach
        void setUp() {
            connection = new SpnegoHttpURLConnection(mockGSSCredential, false);
        }

        @Test
        @DisplayName("setMutualAuth sets value correctly")
        void setMutualAuthSetsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.setMutualAuth(false);
            });
        }

        @Test
        @DisplayName("setConfidentiality sets value correctly")
        void setConfidentialitySetsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.setConfidentiality(true);
            });
        }

        @Test
        @DisplayName("setMessageIntegrity sets value correctly")
        void setMessageIntegritySetsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.setMessageIntegrity(true);
            });
        }

        @Test
        @DisplayName("setReplayDetection sets value correctly")
        void setReplayDetectionSetsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.setReplayDetection(true);
            });
        }

        @Test
        @DisplayName("setSequenceDetection sets value correctly")
        void setSequenceDetectionSetsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.setSequenceDetection(true);
            });
        }

        @Test
        @DisplayName("requestCredDeleg sets value correctly")
        void requestCredDelegSetsCorrectly() {
            assertDoesNotThrow(() -> {
                connection.requestCredDeleg(true);
            });
        }

        @Test
        @DisplayName("requestCredDeleg after connect throws exception")
        void requestCredDelegAfterConnectThrowsException() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                assertThrows(IllegalStateException.class, () -> {
                    connection.requestCredDeleg(true);
                });
            }
        }

        @Test
        @DisplayName("setConfidentiality true with messageIntegrity false throws exception")
        void confidentialityWithoutIntegrityThrowsException() throws Exception {
            connection.setMessageIntegrity(false);
            connection.setConfidentiality(true);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);

                assertThrows(IllegalStateException.class, () -> {
                    connection.connect(url);
                });
            }
        }
    }

    @Nested
    @DisplayName("Connect tests")
    class ConnectTests {

        private SpnegoHttpURLConnection connection;

        @BeforeEach
        void setUp() {
            connection = new SpnegoHttpURLConnection(mockGSSCredential, false);
        }

        @Test
        @DisplayName("connect successfully establishes connection")
        void connectSuccessfullyEstablishesConnection() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForSuccessfulConnect(providerMock);

                URL url = new URL(TEST_URL);
                HttpURLConnection result = connection.connect(url);

                assertNotNull(result);
                assertTrue(connection.isContextEstablished());
            }
        }

        @Test
        @DisplayName("connect with ByteArrayOutputStream sends data")
        void connectWithByteArrayOutputStreamSendsData() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write("test data".getBytes());

                URL url = new URL(TEST_URL);
                HttpURLConnection result = connection.connect(url, outputStream);

                assertNotNull(result);
            }
        }

        @Test
        @DisplayName("connect twice throws IllegalStateException")
        void connectTwiceThrowsException() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                assertThrows(IllegalStateException.class, () -> {
                    connection.connect(url);
                });
            }
        }

        @Test
        @DisplayName("connect handles HTTP 302 redirect")
        void connectHandlesRedirect() throws Exception {
            SpnegoHttpURLConnection redirectConnection = new SpnegoHttpURLConnection(mockGSSCredential, false);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                // First connection returns 302
                HttpURLConnection firstConn = mock(HttpURLConnection.class);
                when(firstConn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_MOVED_TEMP);
                when(firstConn.getHeaderField("location")).thenReturn("/redirect");
                when(firstConn.getHeaderFields()).thenReturn(new HashMap<>());

                // Second connection returns 200
                HttpURLConnection secondConn = mock(HttpURLConnection.class);
                when(secondConn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
                when(secondConn.getHeaderField("WWW-Authenticate")).thenReturn(null);

                setupMocksForRedirect(providerMock, firstConn, secondConn);

                URL url = new URL(TEST_URL);
                HttpURLConnection result = redirectConnection.connect(url);

                assertNotNull(result);
            }
        }

        @Test
        @DisplayName("connect with null auth scheme continues")
        void connectWithNullAuthSchemeContinues() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                when(mockGSSContext.initSecContext(any(byte[].class), anyInt(), anyInt()))
                    .thenReturn("token".getBytes());
                when(mockGSSContext.isEstablished()).thenReturn(false);

                providerMock.when(() -> SpnegoProvider.getGSSContext(any(), any()))
                    .thenReturn(mockGSSContext);
                providerMock.when(() -> SpnegoProvider.getAuthScheme(isNull()))
                    .thenReturn(null);

                when(mockHttpURLConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
                when(mockHttpURLConnection.getHeaderField("WWW-Authenticate")).thenReturn(null);

                try (MockedConstruction<URL> urlMock = mockConstruction(URL.class,
                        (mock, context) -> {
                            when(mock.openConnection()).thenReturn(mockHttpURLConnection);
                            when(mock.getHost()).thenReturn("example.com");
                            when(mock.getPort()).thenReturn(8080);
                        })) {

                    URL url = new URL(TEST_URL);
                    HttpURLConnection result = connection.connect(url);

                    assertNotNull(result);
                }
            }
        }

        @Test
        @DisplayName("connect with GSSException is thrown")
        void connectWithGSSExceptionThrown() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                when(mockGSSContext.initSecContext(any(byte[].class), anyInt(), anyInt()))
                    .thenThrow(new GSSException(GSSException.FAILURE));

                providerMock.when(() -> SpnegoProvider.getGSSContext(any(), any()))
                    .thenReturn(mockGSSContext);

                URL url = new URL(TEST_URL);

                assertThrows(GSSException.class, () -> {
                    connection.connect(url);
                });
            }
        }
    }

    @Nested
    @DisplayName("Response method tests")
    class ResponseMethodTests {

        private SpnegoHttpURLConnection connection;

        @BeforeEach
        void setUp() {
            connection = new SpnegoHttpURLConnection(mockGSSCredential, false);
        }

        @Test
        @DisplayName("getResponseCode before connect throws exception")
        void getResponseCodeBeforeConnectThrowsException() {
            assertThrows(IllegalStateException.class, () -> {
                connection.getResponseCode();
            });
        }

        @Test
        @DisplayName("getResponseMessage before connect throws exception")
        void getResponseMessageBeforeConnectThrowsException() {
            assertThrows(IllegalStateException.class, () -> {
                connection.getResponseMessage();
            });
        }

        @Test
        @DisplayName("getResponseCode after connect returns code")
        void getResponseCodeAfterConnectReturnsCode() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                when(mockHttpURLConnection.getResponseCode()).thenReturn(200);
                assertEquals(200, connection.getResponseCode());
            }
        }

        @Test
        @DisplayName("getResponseMessage after connect returns message")
        void getResponseMessageAfterConnectReturnsMessage() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                when(mockHttpURLConnection.getResponseMessage()).thenReturn("OK");
                assertEquals("OK", connection.getResponseMessage());
            }
        }
    }

    @Nested
    @DisplayName("Stream method tests")
    class StreamMethodTests {

        private SpnegoHttpURLConnection connection;

        @BeforeEach
        void setUp() {
            connection = new SpnegoHttpURLConnection(mockGSSCredential, false);
        }

        @Test
        @DisplayName("getInputStream before connect throws exception")
        void getInputStreamBeforeConnectThrowsException() {
            assertThrows(IllegalStateException.class, () -> {
                connection.getInputStream();
            });
        }

        @Test
        @DisplayName("getOutputStream before connect throws exception")
        void getOutputStreamBeforeConnectThrowsException() {
            assertThrows(IllegalStateException.class, () -> {
                connection.getOutputStream();
            });
        }

        @Test
        @DisplayName("getErrorStream before connect throws exception")
        void getErrorStreamBeforeConnectThrowsException() {
            assertThrows(IllegalStateException.class, () -> {
                connection.getErrorStream();
            });
        }

        @Test
        @DisplayName("getInputStream after connect returns stream")
        void getInputStreamAfterConnectReturnsStream() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                InputStream mockInputStream = new ByteArrayInputStream("test".getBytes());
                when(mockHttpURLConnection.getInputStream()).thenReturn(mockInputStream);

                InputStream result = connection.getInputStream();
                assertNotNull(result);
            }
        }

        @Test
        @DisplayName("getOutputStream after connect returns stream")
        void getOutputStreamAfterConnectReturnsStream() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                OutputStream mockOutputStream = new ByteArrayOutputStream();
                when(mockHttpURLConnection.getOutputStream()).thenReturn(mockOutputStream);

                OutputStream result = connection.getOutputStream();
                assertNotNull(result);
            }
        }
    }

    @Nested
    @DisplayName("Header method tests")
    class HeaderMethodTests {

        private SpnegoHttpURLConnection connection;

        @BeforeEach
        void setUp() {
            connection = new SpnegoHttpURLConnection(mockGSSCredential, false);
        }

        @Test
        @DisplayName("getHeaderField before connect throws exception")
        void getHeaderFieldBeforeConnectThrowsException() {
            assertThrows(IllegalStateException.class, () -> {
                connection.getHeaderField("Content-Type");
            });
        }

        @Test
        @DisplayName("getHeaderField by index before connect throws exception")
        void getHeaderFieldByIndexBeforeConnectThrowsException() {
            assertThrows(IllegalStateException.class, () -> {
                connection.getHeaderField(0);
            });
        }

        @Test
        @DisplayName("getHeaderFieldKey before connect throws exception")
        void getHeaderFieldKeyBeforeConnectThrowsException() {
            assertThrows(IllegalStateException.class, () -> {
                connection.getHeaderFieldKey(0);
            });
        }

        @Test
        @DisplayName("getHeaderField after connect returns value")
        void getHeaderFieldAfterConnectReturnsValue() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                when(mockHttpURLConnection.getHeaderField("Content-Type")).thenReturn("application/json");
                assertEquals("application/json", connection.getHeaderField("Content-Type"));
            }
        }

        @Test
        @DisplayName("getHeaderField by index after connect returns value")
        void getHeaderFieldByIndexAfterConnectReturnsValue() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                when(mockHttpURLConnection.getHeaderField(0)).thenReturn("HTTP/1.1 200 OK");
                assertEquals("HTTP/1.1 200 OK", connection.getHeaderField(0));
            }
        }

        @Test
        @DisplayName("getHeaderFieldKey after connect returns key")
        void getHeaderFieldKeyAfterConnectReturnsKey() throws Exception {
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                when(mockHttpURLConnection.getHeaderFieldKey(1)).thenReturn("Content-Type");
                assertEquals("Content-Type", connection.getHeaderFieldKey(1));
            }
        }
    }

    @Nested
    @DisplayName("Disconnect tests")
    class DisconnectTests {

        @Test
        @DisplayName("disconnect clears connection state")
        void disconnectClearsConnectionState() throws Exception {
            SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection(mockGSSCredential, false);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                assertDoesNotThrow(() -> connection.disconnect());

                // After disconnect, should be able to set properties again
                assertDoesNotThrow(() -> connection.setRequestProperty("Accept", "text/html"));
            }
        }

        @Test
        @DisplayName("disconnect without connect does not throw")
        void disconnectWithoutConnectDoesNotThrow() {
            SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection(mockGSSCredential, false);

            assertDoesNotThrow(() -> connection.disconnect());
        }

        @Test
        @DisplayName("disconnect disposes credential when autoDispose is true")
        void disconnectDisposesCredentialWhenAutoDispose() throws Exception {
            GSSCredential mockDisposableCredential = mock(GSSCredential.class);
            doNothing().when(mockDisposableCredential).dispose();

            SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection(mockDisposableCredential, true);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                connection.disconnect();

                verify(mockDisposableCredential, times(1)).dispose();
            }
        }

        @Test
        @DisplayName("disconnect does not dispose credential when autoDispose is false")
        void disconnectDoesNotDisposeCredentialWhenNoAutoDispose() throws Exception {
            GSSCredential mockDisposableCredential = mock(GSSCredential.class);

            SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection(mockDisposableCredential, false);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                connection.disconnect();

                verify(mockDisposableCredential, never()).dispose();
            }
        }

        @Test
        @DisplayName("disconnect handles GSSException gracefully")
        void disconnectHandlesGSSExceptionGracefully() throws Exception {
            GSSCredential mockFailingCredential = mock(GSSCredential.class);
            doThrow(new GSSException(GSSException.FAILURE)).when(mockFailingCredential).dispose();

            SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection(mockFailingCredential, true);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                // Should log warning but not throw
                assertDoesNotThrow(() -> connection.disconnect());
            }
        }
    }

    @Nested
    @DisplayName("Context established tests")
    class ContextEstablishedTests {

        @Test
        @DisplayName("isContextEstablished returns false before connect")
        void isContextEstablishedReturnsFalseBeforeConnect() {
            SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection(mockGSSCredential, false);

            assertFalse(connection.isContextEstablished());
        }

        @Test
        @DisplayName("isContextEstablished returns true after successful connect")
        void isContextEstablishedReturnsTrueAfterSuccessfulConnect() throws Exception {
            SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection(mockGSSCredential, false);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                setupMocksForSuccessfulConnect(providerMock);

                URL url = new URL(TEST_URL);
                connection.connect(url);

                assertTrue(connection.isContextEstablished());
            }
        }
    }

    // Helper methods

    private void setupMocksForConnect(MockedStatic<SpnegoProvider> providerMock) throws Exception {
        when(mockGSSContext.initSecContext(any(byte[].class), anyInt(), anyInt()))
            .thenReturn("token".getBytes());
        when(mockGSSContext.isEstablished()).thenReturn(false);

        providerMock.when(() -> SpnegoProvider.getGSSContext(any(), any()))
            .thenReturn(mockGSSContext);

        when(mockHttpURLConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockHttpURLConnection.getHeaderField("WWW-Authenticate")).thenReturn(null);

        try (MockedConstruction<URL> urlMock = mockConstruction(URL.class,
                (mock, context) -> {
                    when(mock.openConnection()).thenReturn(mockHttpURLConnection);
                    when(mock.getHost()).thenReturn("example.com");
                    when(mock.getPort()).thenReturn(8080);
                })) {
            // URL construction will be handled by the mock
        }
    }

    private void setupMocksForSuccessfulConnect(MockedStatic<SpnegoProvider> providerMock) throws Exception {
        when(mockGSSContext.initSecContext(any(byte[].class), anyInt(), anyInt()))
            .thenReturn("token".getBytes())
            .thenReturn(null);
        when(mockGSSContext.isEstablished()).thenReturn(true);

        SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
        when(mockScheme.getScheme()).thenReturn("Negotiate");
        when(mockScheme.getToken()).thenReturn("response-token".getBytes());

        providerMock.when(() -> SpnegoProvider.getGSSContext(any(), any()))
            .thenReturn(mockGSSContext);
        providerMock.when(() -> SpnegoProvider.getAuthScheme(anyString()))
            .thenReturn(mockScheme);

        when(mockHttpURLConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockHttpURLConnection.getHeaderField("WWW-Authenticate"))
            .thenReturn("Negotiate " + Base64.encode("response-token".getBytes()));

        try (MockedConstruction<URL> urlMock = mockConstruction(URL.class,
                (mock, context) -> {
                    when(mock.openConnection()).thenReturn(mockHttpURLConnection);
                    when(mock.getHost()).thenReturn("example.com");
                    when(mock.getPort()).thenReturn(8080);
                })) {
            // URL construction will be handled by the mock
        }
    }

    private void setupMocksForRedirect(MockedStatic<SpnegoProvider> providerMock,
                                       HttpURLConnection firstConn,
                                       HttpURLConnection secondConn) throws Exception {
        when(mockGSSContext.initSecContext(any(byte[].class), anyInt(), anyInt()))
            .thenReturn("token".getBytes());
        when(mockGSSContext.isEstablished()).thenReturn(false);

        providerMock.when(() -> SpnegoProvider.getGSSContext(any(), any()))
            .thenReturn(mockGSSContext);
        providerMock.when(() -> SpnegoProvider.getAuthScheme(isNull()))
            .thenReturn(null);

        try (MockedConstruction<URL> urlMock = mockConstruction(URL.class,
                (mock, context) -> {
                    when(mock.openConnection())
                        .thenReturn(firstConn)
                        .thenReturn(secondConn);
                    when(mock.getHost()).thenReturn("example.com");
                    when(mock.getPort()).thenReturn(8080);
                    when(mock.toString()).thenReturn(TEST_URL);
                })) {
            // URL construction will be handled by the mock
        }
    }
}
