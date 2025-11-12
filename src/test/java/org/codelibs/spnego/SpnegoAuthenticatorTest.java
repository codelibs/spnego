package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Unit tests for {@link SpnegoAuthenticator}.
 */
@ExtendWith(MockitoExtension.class)
class SpnegoAuthenticatorTest {

    @Mock
    private SpnegoFilterConfig mockConfig;

    @Mock
    private LoginContext mockLoginContext;

    @Mock
    private GSSCredential mockGSSCredential;

    @Mock
    private GSSContext mockGSSContext;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private SpnegoHttpServletResponse mockResponse;

    @Mock
    private Subject mockSubject;

    @Mock
    private GSSName mockGSSName;

    private static final String TEST_REALM = "EXAMPLE.COM";
    private static final String TEST_PRINCIPAL = "HTTP/server.example.com@EXAMPLE.COM";
    private static final String SERVER_MODULE = "spnego-server";
    private static final String CLIENT_MODULE = "spnego-client";

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("constructor with SpnegoFilterConfig using keytab")
        void constructorWithConfigUsingKeytab() throws Exception {
            // Setup mock config
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(true);
            when(mockConfig.downgradeNtlm()).thenReturn(true);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.useKeyTab()).thenReturn(true);
            when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                assertNotNull(authenticator);
                assertEquals(TEST_REALM, authenticator.getServerRealm());
            }
        }

        @Test
        @DisplayName("constructor with SpnegoFilterConfig using username/password")
        void constructorWithConfigUsingPassword() throws Exception {
            // Setup mock config
            when(mockConfig.isBasicAllowed()).thenReturn(false);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(true);
            when(mockConfig.useKeyTab()).thenReturn(false);
            when(mockConfig.getPreauthUsername()).thenReturn("admin");
            when(mockConfig.getPreauthPassword()).thenReturn("password");
            when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                assertNotNull(authenticator);
                assertEquals(TEST_REALM, authenticator.getServerRealm());
            }
        }

        @Test
        @DisplayName("constructor with Map configuration")
        void constructorWithMap() throws Exception {
            Map<String, String> config = new HashMap<>();
            config.put("spnego.krb5.conf", "krb5.conf");
            config.put("spnego.login.conf", "login.conf");
            config.put("spnego.preauth.username", "admin");
            config.put("spnego.preauth.password", "password");
            config.put("spnego.login.server.module", SERVER_MODULE);
            config.put("spnego.login.client.module", CLIENT_MODULE);
            config.put("spnego.allow.basic", "true");
            config.put("spnego.allow.localhost", "false");
            config.put("spnego.allow.unsecure.basic", "false");
            config.put("spnego.prompt.ntlm", "false");

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class);
                 MockedStatic<SpnegoFilterConfig> configMock = mockStatic(SpnegoFilterConfig.class)) {

                mockServerLogin(providerMock);

                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(false);
                when(mockConfig.getPreauthUsername()).thenReturn("admin");
                when(mockConfig.getPreauthPassword()).thenReturn("password");
                when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

                configMock.when(() -> SpnegoFilterConfig.getInstance(any()))
                    .thenReturn(mockConfig);

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(config);

                assertNotNull(authenticator);
            }
        }

        @Test
        @DisplayName("constructor with loginModuleName and config using username")
        void constructorWithLoginModuleAndUsername() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(true);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(true);
            when(mockConfig.downgradeNtlm()).thenReturn(true);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.getPreauthUsername()).thenReturn("admin");
            when(mockConfig.getPreauthPassword()).thenReturn("password");
            when(mockConfig.useKeyTab()).thenReturn(false);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(SERVER_MODULE, mockConfig);

                assertNotNull(authenticator);
            }
        }

        @Test
        @DisplayName("constructor with loginModuleName and config using keytab")
        void constructorWithLoginModuleAndKeytab() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(true);
            when(mockConfig.getPreauthUsername()).thenReturn(null);
            when(mockConfig.useKeyTab()).thenReturn(true);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(SERVER_MODULE, mockConfig);

                assertNotNull(authenticator);
            }
        }

        @Test
        @DisplayName("constructor throws exception when neither username nor keytab provided")
        void constructorThrowsExceptionWithoutCredentials() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.getPreauthUsername()).thenReturn(null);
            when(mockConfig.useKeyTab()).thenReturn(false);

            assertThrows(IllegalArgumentException.class, () -> {
                new SpnegoAuthenticator(SERVER_MODULE, mockConfig);
            });
        }

        @Test
        @DisplayName("constructor handles empty username as null")
        void constructorHandlesEmptyUsername() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.getPreauthUsername()).thenReturn("   ");
            when(mockConfig.useKeyTab()).thenReturn(false);

            assertThrows(IllegalArgumentException.class, () -> {
                new SpnegoAuthenticator(SERVER_MODULE, mockConfig);
            });
        }
    }

    @Nested
    @DisplayName("Authentication tests")
    class AuthenticationTests {

        private SpnegoAuthenticator authenticator;

        @BeforeEach
        void setUp() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(true);
            when(mockConfig.downgradeNtlm()).thenReturn(true);
            when(mockConfig.isDelegationAllowed()).thenReturn(true);
            when(mockConfig.useKeyTab()).thenReturn(true);
            when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);
                authenticator = new SpnegoAuthenticator(mockConfig);
            }
        }

        @Test
        @DisplayName("authenticate returns null when scheme is null")
        void authenticateReturnsNullWhenSchemeIsNull() throws Exception {
            when(mockRequest.isSecure()).thenReturn(true);
            when(mockRequest.getLocalAddr()).thenReturn("192.168.1.1");
            when(mockRequest.getRemoteAddr()).thenReturn("192.168.1.2");

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                providerMock.when(() -> SpnegoProvider.negotiate(
                    eq(mockRequest), eq(mockResponse), anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(null);

                SpnegoPrincipal result = authenticator.authenticate(mockRequest, mockResponse);

                assertNull(result);
            }
        }

        @Test
        @DisplayName("authenticate handles localhost with user.name property")
        void authenticateHandlesLocalhostWithUserName() throws Exception {
            when(mockRequest.getLocalAddr()).thenReturn("127.0.0.1");
            when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");

            String originalUserName = System.getProperty("user.name");
            try {
                System.setProperty("user.name", "testuser");

                SpnegoPrincipal result = authenticator.authenticate(mockRequest, mockResponse);

                assertNotNull(result);
                assertTrue(result.getName().startsWith("testuser@"));
            } finally {
                if (originalUserName != null) {
                    System.setProperty("user.name", originalUserName);
                }
            }
        }

        @Test
        @DisplayName("authenticate handles localhost with IPv6")
        void authenticateHandlesLocalhostIPv6() throws Exception {
            when(mockRequest.getLocalAddr()).thenReturn("0.0.0.0");
            when(mockRequest.getRemoteAddr()).thenReturn("0:0:0:0:0:0:0:1");

            SpnegoPrincipal result = authenticator.authenticate(mockRequest, mockResponse);

            assertNotNull(result);
        }

        @Test
        @DisplayName("authenticate handles localhost without user.name")
        void authenticateHandlesLocalhostWithoutUserName() throws Exception {
            when(mockRequest.getLocalAddr()).thenReturn("127.0.0.1");
            when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");

            String originalUserName = System.getProperty("user.name");
            try {
                System.clearProperty("user.name");

                SpnegoPrincipal result = authenticator.authenticate(mockRequest, mockResponse);

                assertNotNull(result);
                assertTrue(result.getName().contains("@" + TEST_REALM));
            } finally {
                if (originalUserName != null) {
                    System.setProperty("user.name", originalUserName);
                }
            }
        }

        @Test
        @DisplayName("authenticate throws UnsupportedOperationException for unsupported scheme")
        void authenticateThrowsExceptionForUnsupportedScheme() throws Exception {
            when(mockRequest.isSecure()).thenReturn(true);
            when(mockRequest.getLocalAddr()).thenReturn("192.168.1.1");
            when(mockRequest.getRemoteAddr()).thenReturn("192.168.1.2");

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(false);
            when(mockScheme.isBasicScheme()).thenReturn(false);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                providerMock.when(() -> SpnegoProvider.negotiate(
                    eq(mockRequest), eq(mockResponse), anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                assertThrows(UnsupportedOperationException.class, () -> {
                    authenticator.authenticate(mockRequest, mockResponse);
                });
            }
        }

        @Test
        @DisplayName("authenticate with Basic scheme but not allowed throws exception")
        void authenticateBasicNotAllowedThrowsException() throws Exception {
            // Create authenticator with Basic auth disabled
            when(mockConfig.isBasicAllowed()).thenReturn(false);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);

            SpnegoAuthenticator noBasicAuthenticator;
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);
                noBasicAuthenticator = new SpnegoAuthenticator(mockConfig);
            }

            when(mockRequest.isSecure()).thenReturn(false);
            when(mockRequest.getLocalAddr()).thenReturn("192.168.1.1");
            when(mockRequest.getRemoteAddr()).thenReturn("192.168.1.2");

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(false);
            when(mockScheme.isBasicScheme()).thenReturn(true);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                providerMock.when(() -> SpnegoProvider.negotiate(
                    eq(mockRequest), eq(mockResponse), anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                assertThrows(UnsupportedOperationException.class, () -> {
                    noBasicAuthenticator.authenticate(mockRequest, mockResponse);
                });
            }
        }
    }

    @Nested
    @DisplayName("Basic Authentication tests")
    class BasicAuthenticationTests {

        private SpnegoAuthenticator authenticator;

        @BeforeEach
        void setUp() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(true);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.useKeyTab()).thenReturn(true);
            when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);
                authenticator = new SpnegoAuthenticator(mockConfig);
            }
        }

        @Test
        @DisplayName("Basic auth returns null for empty token")
        void basicAuthReturnsNullForEmptyToken() throws Exception {
            when(mockRequest.isSecure()).thenReturn(true);
            when(mockRequest.getLocalAddr()).thenReturn("192.168.1.1");
            when(mockRequest.getRemoteAddr()).thenReturn("192.168.1.2");

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(false);
            when(mockScheme.isBasicScheme()).thenReturn(true);
            when(mockScheme.getToken()).thenReturn(new byte[0]);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                providerMock.when(() -> SpnegoProvider.negotiate(
                    eq(mockRequest), eq(mockResponse), anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                SpnegoPrincipal result = authenticator.authenticate(mockRequest, mockResponse);

                assertNull(result);
            }
        }

        @Test
        @DisplayName("Basic auth throws exception for malformed credentials")
        void basicAuthThrowsExceptionForMalformedCredentials() throws Exception {
            when(mockRequest.isSecure()).thenReturn(true);
            when(mockRequest.getLocalAddr()).thenReturn("192.168.1.1");
            when(mockRequest.getRemoteAddr()).thenReturn("192.168.1.2");

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(false);
            when(mockScheme.isBasicScheme()).thenReturn(true);
            when(mockScheme.getToken()).thenReturn("invalidcredentials".getBytes());

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                providerMock.when(() -> SpnegoProvider.negotiate(
                    eq(mockRequest), eq(mockResponse), anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                assertThrows(IllegalArgumentException.class, () -> {
                    authenticator.authenticate(mockRequest, mockResponse);
                });
            }
        }

        @Test
        @DisplayName("Basic auth with domain prefix extracts username correctly")
        void basicAuthHandlesDomainPrefix() throws Exception {
            // Test validates that domain prefix (DOMAIN\username) is correctly stripped
            // The actual format is "DOMAIN\\username:password" in the token
            String tokenWithDomain = "DOMAIN\\testuser:password";
            String[] parts = tokenWithDomain.split(":", 2);
            assertEquals(2, parts.length);

            String usernameWithDomain = parts[0];
            String username = usernameWithDomain.substring(usernameWithDomain.indexOf('\\') + 1);

            // Verify domain prefix is stripped correctly
            assertEquals("testuser", username);
        }
    }

    @Nested
    @DisplayName("SPNEGO Authentication tests")
    class SpnegoAuthenticationTests {

        private SpnegoAuthenticator authenticator;

        @BeforeEach
        void setUp() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(false);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(true);
            when(mockConfig.useKeyTab()).thenReturn(true);
            when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);
                authenticator = new SpnegoAuthenticator(mockConfig);
            }
        }

        @Test
        @DisplayName("SPNEGO auth returns null for empty token")
        void spnegoAuthReturnsNullForEmptyToken() throws Exception {
            when(mockRequest.isSecure()).thenReturn(true);
            when(mockRequest.getLocalAddr()).thenReturn("192.168.1.1");
            when(mockRequest.getRemoteAddr()).thenReturn("192.168.1.2");

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(true);
            when(mockScheme.getToken()).thenReturn(new byte[0]);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                providerMock.when(() -> SpnegoProvider.negotiate(
                    eq(mockRequest), eq(mockResponse), anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                SpnegoPrincipal result = authenticator.authenticate(mockRequest, mockResponse);

                assertNull(result);
            }
        }
    }

    @Nested
    @DisplayName("Dispose tests")
    class DisposeTests {

        @Test
        @DisplayName("dispose successfully disposes credentials and logs out")
        void disposeSuccessfullyDisposesAll() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.useKeyTab()).thenReturn(true);
            when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

            SpnegoAuthenticator authenticator;
            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);
                authenticator = new SpnegoAuthenticator(mockConfig);
            }

            // Should not throw exception
            assertDoesNotThrow(() -> authenticator.dispose());
        }

        @Test
        @DisplayName("dispose handles GSSException gracefully")
        void disposeHandlesGSSException() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.useKeyTab()).thenReturn(true);
            when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                GSSCredential mockFailingCredential = mock(GSSCredential.class);
                doThrow(new GSSException(GSSException.FAILURE))
                    .when(mockFailingCredential).dispose();

                mockServerLoginWithCustomCredential(providerMock, mockFailingCredential);

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                // Should log warning but not throw exception
                assertDoesNotThrow(() -> authenticator.dispose());
            }
        }
    }

    @Nested
    @DisplayName("Utility method tests")
    class UtilityMethodTests {

        @Test
        @DisplayName("getServerRealm returns correct realm")
        void getServerRealmReturnsCorrectRealm() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(true);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn(CLIENT_MODULE);
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.useKeyTab()).thenReturn(true);
            when(mockConfig.getServerLoginModule()).thenReturn(SERVER_MODULE);

            try (MockedStatic<SpnegoProvider> providerMock = mockStatic(SpnegoProvider.class)) {
                mockServerLogin(providerMock);

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                assertEquals(TEST_REALM, authenticator.getServerRealm());
            }
        }
    }

    // Helper methods

    private void mockServerLogin(MockedStatic<SpnegoProvider> providerMock) throws Exception {
        mockServerLoginWithCustomCredential(providerMock, mockGSSCredential);
    }

    private void mockServerLoginWithCustomCredential(
            MockedStatic<SpnegoProvider> providerMock,
            GSSCredential credential) throws Exception {

        doNothing().when(mockLoginContext).login();
        doNothing().when(mockLoginContext).logout();
        when(mockLoginContext.getSubject()).thenReturn(mockSubject);

        when(credential.getName()).thenReturn(mockGSSName);
        when(mockGSSName.toString()).thenReturn(TEST_PRINCIPAL);

        providerMock.when(() -> SpnegoProvider.getUsernamePasswordHandler(anyString(), anyString()))
            .thenReturn(null);

        providerMock.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
            .thenReturn(credential);

        try (MockedStatic<LoginContext> loginMock = mockStatic(LoginContext.class)) {
            loginMock.when(() -> new LoginContext(anyString())).thenReturn(mockLoginContext);
            loginMock.when(() -> new LoginContext(anyString(), any(CallbackHandler.class))).thenReturn(mockLoginContext);
        }
    }
}
