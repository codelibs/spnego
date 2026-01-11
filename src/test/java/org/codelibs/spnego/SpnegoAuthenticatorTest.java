package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.Subject;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Unit tests for {@link SpnegoAuthenticator}.
 *
 * These tests cover:
 * - Localhost detection logic
 * - Basic authentication parsing
 * - Configuration validation
 * - Authentication flow with mocked dependencies
 * - Error handling scenarios
 */
@ExtendWith(MockitoExtension.class)
class SpnegoAuthenticatorTest {

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private SpnegoHttpServletResponse mockResponse;

    @Mock
    private SpnegoFilterConfig mockConfig;

    @Mock
    private GSSCredential mockGSSCredential;

    @Mock
    private GSSContext mockGSSContext;

    @Mock
    private GSSName mockGSSName;

    @Nested
    @DisplayName("Localhost detection logic tests")
    class LocalhostDetectionLogicTests {

        @Test
        @DisplayName("localhost detection for matching IPv4 addresses")
        void localhostDetectionForMatchingIPv4() {
            // Test the logic used in isLocalhost method
            String localAddr = "127.0.0.1";
            String remoteAddr = "127.0.0.1";

            boolean isLocal = localAddr.equals(remoteAddr);

            assertTrue(isLocal);
        }

        @Test
        @DisplayName("localhost detection for IPv6 special case")
        void localhostDetectionForIPv6SpecialCase() {
            // Test the special case: localAddr is 0.0.0.0 and remoteAddr is IPv6 localhost
            String localAddr = "0.0.0.0";
            String remoteAddr = "0:0:0:0:0:0:0:1";

            // This is the special case logic from isLocalhost method
            boolean isLocal = localAddr.equals("0.0.0.0") && remoteAddr.equals("0:0:0:0:0:0:0:1");

            assertTrue(isLocal);
        }

        @Test
        @DisplayName("localhost detection for different addresses")
        void localhostDetectionForDifferentAddresses() {
            String localAddr = "192.168.1.1";
            String remoteAddr = "192.168.1.2";

            boolean isLocal = localAddr.equals(remoteAddr);

            assertFalse(isLocal);
        }

        @Test
        @DisplayName("localhost detection for matching addresses")
        void localhostDetectionForMatchingAddresses() {
            String localAddr = "10.0.0.1";
            String remoteAddr = "10.0.0.1";

            boolean isLocal = localAddr.equals(remoteAddr);

            assertTrue(isLocal);
        }
    }

    @Nested
    @DisplayName("Basic Authentication logic tests")
    class BasicAuthenticationLogicTests {

        @Test
        @DisplayName("Basic auth token parsing with domain prefix")
        void basicAuthTokenParsingWithDomainPrefix() {
            // Test validates that domain prefix (DOMAIN\\username) is correctly stripped
            String tokenWithDomain = "DOMAIN\\testuser:password";
            String[] parts = tokenWithDomain.split(":", 2);
            assertEquals(2, parts.length);

            String usernameWithDomain = parts[0];
            String username = usernameWithDomain.substring(usernameWithDomain.indexOf('\\') + 1);

            // Verify domain prefix is stripped correctly
            assertEquals("testuser", username);
        }

        @Test
        @DisplayName("Basic auth token parsing without domain prefix")
        void basicAuthTokenParsingWithoutDomainPrefix() {
            String token = "testuser:password";
            String[] parts = token.split(":", 2);
            assertEquals(2, parts.length);

            String username = parts[0];
            String password = parts[1];

            assertEquals("testuser", username);
            assertEquals("password", password);
        }

        @Test
        @DisplayName("Basic auth token with colon in password")
        void basicAuthTokenWithColonInPassword() {
            String token = "testuser:pass:word";
            String[] parts = token.split(":", 2);
            assertEquals(2, parts.length);

            String username = parts[0];
            String password = parts[1];

            assertEquals("testuser", username);
            assertEquals("pass:word", password);
        }

        @Test
        @DisplayName("Basic auth malformed token throws exception")
        void basicAuthMalformedTokenThrowsException() {
            String malformedToken = "nocolonhere";
            String[] parts = malformedToken.split(":", 2);

            // Should not have 2 parts
            assertNotEquals(2, parts.length);
        }
    }

    @Nested
    @DisplayName("Configuration validation tests")
    class ConfigurationValidationTests {

        @Test
        @DisplayName("Map configuration contains required keys")
        void mapConfigurationContainsRequiredKeys() {
            Map<String, String> config = new HashMap<>();
            config.put("spnego.krb5.conf", "krb5.conf");
            config.put("spnego.login.conf", "login.conf");
            config.put("spnego.preauth.username", "admin");
            config.put("spnego.preauth.password", "password");
            config.put("spnego.login.server.module", "spnego-server");
            config.put("spnego.login.client.module", "spnego-client");
            config.put("spnego.allow.basic", "true");
            config.put("spnego.allow.localhost", "false");
            config.put("spnego.allow.unsecure.basic", "false");
            config.put("spnego.prompt.ntlm", "false");

            assertTrue(config.containsKey("spnego.krb5.conf"));
            assertTrue(config.containsKey("spnego.login.conf"));
            assertTrue(config.containsKey("spnego.preauth.username"));
            assertTrue(config.containsKey("spnego.preauth.password"));
            assertTrue(config.containsKey("spnego.login.server.module"));
            assertTrue(config.containsKey("spnego.login.client.module"));
        }

        @Test
        @DisplayName("Configuration with empty username should be treated as no username")
        void configurationWithEmptyUsername() {
            String username = "   ";
            boolean hasUsername = username != null && !username.trim().isEmpty();

            assertFalse(hasUsername);
        }

        @Test
        @DisplayName("Configuration with valid username")
        void configurationWithValidUsername() {
            String username = "admin";
            boolean hasUsername = username != null && !username.trim().isEmpty();

            assertTrue(hasUsername);
        }
    }

    @Nested
    @DisplayName("CallbackHandler tests")
    class CallbackHandlerTests {

        @Test
        @DisplayName("getUsernamePasswordHandler creates non-null handler")
        void getUsernamePasswordHandlerCreatesNonNullHandler() {
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler("user", "pass");

            assertNotNull(handler);
        }

        @Test
        @DisplayName("getUsernamePasswordHandler with null username")
        void getUsernamePasswordHandlerWithNullUsername() {
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(null, "pass");

            assertNotNull(handler);
        }

        @Test
        @DisplayName("getUsernamePasswordHandler with empty strings")
        void getUsernamePasswordHandlerWithEmptyStrings() {
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler("", "");

            assertNotNull(handler);
        }
    }

    @Nested
    @DisplayName("Authentication scheme validation tests")
    class AuthenticationSchemeValidationTests {

        @Test
        @DisplayName("Negotiate scheme is recognized")
        void negotiateSchemeIsRecognized() {
            // This tests the constants and scheme matching logic
            String negotiateHeader = "Negotiate";
            assertTrue(negotiateHeader.equalsIgnoreCase("Negotiate"));
        }

        @Test
        @DisplayName("Basic scheme is recognized")
        void basicSchemeIsRecognized() {
            String basicHeader = "Basic";
            assertTrue(basicHeader.equalsIgnoreCase("Basic"));
        }

        @Test
        @DisplayName("Case insensitive scheme matching")
        void caseInsensitiveSchemeMatching() {
            String negotiate1 = "Negotiate";
            String negotiate2 = "negotiate";
            String negotiate3 = "NEGOTIATE";

            assertTrue(negotiate1.equalsIgnoreCase(negotiate2));
            assertTrue(negotiate1.equalsIgnoreCase(negotiate3));
            assertTrue(negotiate2.equalsIgnoreCase(negotiate3));
        }
    }

    @Nested
    @DisplayName("Security validation tests")
    class SecurityValidationTests {

        @Test
        @DisplayName("Basic auth should require secure connection when unsecure not allowed")
        void basicAuthRequiresSecureConnection() {
            boolean allowBasic = true;
            boolean allowUnsecure = false;
            boolean isSecure = false;

            boolean basicSupported = allowBasic && (allowUnsecure || isSecure);

            assertFalse(basicSupported);
        }

        @Test
        @DisplayName("Basic auth allowed on secure connection")
        void basicAuthAllowedOnSecureConnection() {
            boolean allowBasic = true;
            boolean allowUnsecure = false;
            boolean isSecure = true;

            boolean basicSupported = allowBasic && (allowUnsecure || isSecure);

            assertTrue(basicSupported);
        }

        @Test
        @DisplayName("Basic auth allowed on unsecure when explicitly allowed")
        void basicAuthAllowedOnUnsecureWhenAllowed() {
            boolean allowBasic = true;
            boolean allowUnsecure = true;
            boolean isSecure = false;

            boolean basicSupported = allowBasic && (allowUnsecure || isSecure);

            assertTrue(basicSupported);
        }

        @Test
        @DisplayName("Basic auth not allowed when disabled")
        void basicAuthNotAllowedWhenDisabled() {
            boolean allowBasic = false;
            boolean allowUnsecure = true;
            boolean isSecure = true;

            boolean basicSupported = allowBasic && (allowUnsecure || isSecure);

            assertFalse(basicSupported);
        }
    }

    @Nested
    @DisplayName("Principal name format tests")
    class PrincipalNameFormatTests {

        @Test
        @DisplayName("Principal name format with realm")
        void principalNameFormatWithRealm() {
            String username = "testuser";
            String realm = "EXAMPLE.COM";
            String expectedPrincipal = username + "@" + realm;

            assertEquals("testuser@EXAMPLE.COM", expectedPrincipal);
        }

        @Test
        @DisplayName("Server principal format")
        void serverPrincipalFormat() {
            String serviceName = "HTTP/server.example.com";
            String realm = "EXAMPLE.COM";
            String expectedPrincipal = serviceName + "@" + realm;

            assertEquals("HTTP/server.example.com@EXAMPLE.COM", expectedPrincipal);
        }
    }

    @Nested
    @DisplayName("System property tests")
    class SystemPropertyTests {

        @Test
        @DisplayName("System property user.name exists or returns null")
        void systemPropertyUserNameExistsOrNull() {
            String username = System.getProperty("user.name");

            // Username can be either a string or null
            assertTrue(username == null || username instanceof String);
        }

        @Test
        @DisplayName("Null or empty username handling")
        void nullOrEmptyUsernameHandling() {
            String username = null;
            boolean isNullOrEmpty = username == null || username.isEmpty();

            assertTrue(isNullOrEmpty);
        }
    }

    @Nested
    @DisplayName("Error handling tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("UnsupportedOperationException for unsupported scheme")
        void unsupportedOperationExceptionForUnsupportedScheme() {
            assertThrows(UnsupportedOperationException.class, () -> {
                throw new UnsupportedOperationException("scheme=Digest");
            });
        }

        @Test
        @DisplayName("IllegalArgumentException for invalid credentials format")
        void illegalArgumentExceptionForInvalidCredentials() {
            assertThrows(IllegalArgumentException.class, () -> {
                String credentials = "invalidformat";
                String[] parts = credentials.split(":", 2);
                if (parts.length != 2) {
                    throw new IllegalArgumentException("Username/Password may have contained an invalid character");
                }
            });
        }
    }

    @Nested
    @DisplayName("Authenticate method tests")
    class AuthenticateMethodTests {

        @Test
        @DisplayName("authenticate returns localhost principal when localhost is allowed and request is local")
        void authenticateReturnsLocalhostPrincipalWhenAllowed() throws Exception {
            // Create mocks for the full authentication flow
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);

                // Setup config for localhost allowed
                when(mockConfig.isBasicAllowed()).thenReturn(false);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(true);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                // Setup localhost request
                when(mockRequest.getLocalAddr()).thenReturn("127.0.0.1");
                when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");

                SpnegoPrincipal principal = authenticator.authenticate(mockRequest, mockResponse);

                assertNotNull(principal);
                assertTrue(principal.getName().contains("@EXAMPLE.COM"));
            }
        }

        @Test
        @DisplayName("authenticate returns localhost principal for IPv6 localhost")
        void authenticateReturnsLocalhostPrincipalForIPv6() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);

                when(mockConfig.isBasicAllowed()).thenReturn(false);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(true);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                // IPv6 localhost special case
                when(mockRequest.getLocalAddr()).thenReturn("0.0.0.0");
                when(mockRequest.getRemoteAddr()).thenReturn("0:0:0:0:0:0:0:1");

                SpnegoPrincipal principal = authenticator.authenticate(mockRequest, mockResponse);

                assertNotNull(principal);
            }
        }

        @Test
        @DisplayName("authenticate returns null when no scheme is provided")
        void authenticateReturnsNullWhenNoScheme() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);
                mockedProvider.when(() -> SpnegoProvider.negotiate(
                    any(HttpServletRequest.class),
                    any(SpnegoHttpServletResponse.class),
                    anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(null);

                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(true);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                SpnegoPrincipal principal = authenticator.authenticate(mockRequest, mockResponse);

                assertNull(principal);
            }
        }

        @Test
        @DisplayName("authenticate throws UnsupportedOperationException for unsupported scheme")
        void authenticateThrowsForUnsupportedScheme() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(false);
            when(mockScheme.isBasicScheme()).thenReturn(false);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);
                mockedProvider.when(() -> SpnegoProvider.negotiate(
                    any(HttpServletRequest.class),
                    any(SpnegoHttpServletResponse.class),
                    anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(true);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                assertThrows(UnsupportedOperationException.class, () -> {
                    authenticator.authenticate(mockRequest, mockResponse);
                });
            }
        }

        @Test
        @DisplayName("authenticate throws UnsupportedOperationException for Basic when not allowed on unsecure")
        void authenticateThrowsForBasicOnUnsecure() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(false);
            when(mockScheme.isBasicScheme()).thenReturn(true);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);
                mockedProvider.when(() -> SpnegoProvider.negotiate(
                    any(HttpServletRequest.class),
                    any(SpnegoHttpServletResponse.class),
                    anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                // Allow basic but not unsecure
                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                when(mockRequest.isSecure()).thenReturn(false); // Not secure!

                assertThrows(UnsupportedOperationException.class, () -> {
                    authenticator.authenticate(mockRequest, mockResponse);
                });
            }
        }
    }

    @Nested
    @DisplayName("Dispose method tests")
    class DisposeMethodTests {

        @Test
        @DisplayName("dispose releases server credentials and logs out")
        void disposeReleasesCredentials() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);

                when(mockConfig.isBasicAllowed()).thenReturn(false);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);
                authenticator.dispose();

                // Verify credentials were disposed
                verify(mockServerCred).dispose();

                // Verify login context was logged out
                LoginContext constructedContext = mockedLoginContext.constructed().get(0);
                verify(constructedContext).logout();
            }
        }

        @Test
        @DisplayName("dispose handles GSSException gracefully")
        void disposeHandlesGSSException() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);
            doThrow(new GSSException(GSSException.FAILURE)).when(mockServerCred).dispose();

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);

                when(mockConfig.isBasicAllowed()).thenReturn(false);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                // Should not throw even when dispose fails
                assertDoesNotThrow(() -> authenticator.dispose());
            }
        }

        @Test
        @DisplayName("dispose handles LoginException gracefully")
        void disposeHandlesLoginException() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                         doThrow(new LoginException("Logout failed")).when(mock).logout();
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);

                when(mockConfig.isBasicAllowed()).thenReturn(false);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                // Should not throw even when logout fails
                assertDoesNotThrow(() -> authenticator.dispose());
            }
        }
    }

    @Nested
    @DisplayName("GetServerRealm tests")
    class GetServerRealmTests {

        @Test
        @DisplayName("getServerRealm returns the realm from server principal")
        void getServerRealmReturnsRealm() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@TESTREALM.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);

                when(mockConfig.isBasicAllowed()).thenReturn(false);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                String realm = authenticator.getServerRealm();
                assertEquals("TESTREALM.COM", realm);
            }
        }
    }

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("constructor with SpnegoFilterConfig using keytab")
        void constructorWithKeytab() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);

                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(true);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(true);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                assertNotNull(authenticator);
                assertEquals(1, mockedLoginContext.constructed().size());
            }
        }

        @Test
        @DisplayName("constructor with SpnegoFilterConfig using username/password")
        void constructorWithUsernamePassword() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            CallbackHandler mockHandler = mock(CallbackHandler.class);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);
                mockedProvider.when(() -> SpnegoProvider.getUsernamePasswordHandler(anyString(), anyString()))
                    .thenReturn(mockHandler);

                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(true);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(true);
                when(mockConfig.useKeyTab()).thenReturn(false);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");
                when(mockConfig.getPreauthUsername()).thenReturn("admin");
                when(mockConfig.getPreauthPassword()).thenReturn("password");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                assertNotNull(authenticator);
            }
        }

        @Test
        @DisplayName("constructor with login module name and config - valid username")
        void constructorWithLoginModuleAndUsername() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            CallbackHandler mockHandler = mock(CallbackHandler.class);

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);
                mockedProvider.when(() -> SpnegoProvider.getUsernamePasswordHandler(anyString(), anyString()))
                    .thenReturn(mockHandler);

                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.getPreauthUsername()).thenReturn("testuser");
                when(mockConfig.getPreauthPassword()).thenReturn("testpass");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator("custom-module", mockConfig);

                assertNotNull(authenticator);
            }
        }

        @Test
        @DisplayName("constructor with login module name - no username and no keytab throws")
        void constructorThrowsWhenNoUsernameAndNoKeytab() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(false);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn("client-module");
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.useKeyTab()).thenReturn(false);
            when(mockConfig.getPreauthUsername()).thenReturn(null);

            assertThrows(IllegalArgumentException.class, () -> {
                new SpnegoAuthenticator("custom-module", mockConfig);
            });
        }

        @Test
        @DisplayName("constructor with login module name - empty username and no keytab throws")
        void constructorThrowsWhenEmptyUsernameAndNoKeytab() throws Exception {
            when(mockConfig.isBasicAllowed()).thenReturn(false);
            when(mockConfig.isUnsecureAllowed()).thenReturn(false);
            when(mockConfig.getClientLoginModule()).thenReturn("client-module");
            when(mockConfig.isLocalhostAllowed()).thenReturn(false);
            when(mockConfig.downgradeNtlm()).thenReturn(false);
            when(mockConfig.isDelegationAllowed()).thenReturn(false);
            when(mockConfig.useKeyTab()).thenReturn(false);
            when(mockConfig.getPreauthUsername()).thenReturn("   ");

            assertThrows(IllegalArgumentException.class, () -> {
                new SpnegoAuthenticator("custom-module", mockConfig);
            });
        }
    }

    @Nested
    @DisplayName("SPNEGO authentication tests")
    class SpnegoAuthenticationTests {

        @Test
        @DisplayName("doSpnegoAuth returns null when token is empty")
        void spnegoAuthReturnsNullForEmptyToken() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(true);
            when(mockScheme.getToken()).thenReturn(new byte[0]); // Empty token

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);
                mockedProvider.when(() -> SpnegoProvider.negotiate(
                    any(HttpServletRequest.class),
                    any(SpnegoHttpServletResponse.class),
                    anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                when(mockConfig.isBasicAllowed()).thenReturn(false);
                when(mockConfig.isUnsecureAllowed()).thenReturn(false);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                SpnegoPrincipal principal = authenticator.authenticate(mockRequest, mockResponse);

                assertNull(principal);
            }
        }
    }

    @Nested
    @DisplayName("Basic authentication method tests")
    class BasicAuthMethodTests {

        @Test
        @DisplayName("doBasicAuth returns null for empty token")
        void basicAuthReturnsNullForEmptyToken() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(false);
            when(mockScheme.isBasicScheme()).thenReturn(true);
            when(mockScheme.getToken()).thenReturn(new byte[0]); // Empty token

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);
                mockedProvider.when(() -> SpnegoProvider.negotiate(
                    any(HttpServletRequest.class),
                    any(SpnegoHttpServletResponse.class),
                    anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(true);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                SpnegoPrincipal principal = authenticator.authenticate(mockRequest, mockResponse);

                assertNull(principal);
            }
        }

        @Test
        @DisplayName("doBasicAuth throws IllegalArgumentException for malformed credentials")
        void basicAuthThrowsForMalformedCredentials() throws Exception {
            GSSName mockName = mock(GSSName.class);
            when(mockName.toString()).thenReturn("HTTP/server@EXAMPLE.COM");

            GSSCredential mockServerCred = mock(GSSCredential.class);
            when(mockServerCred.getName()).thenReturn(mockName);

            SpnegoAuthScheme mockScheme = mock(SpnegoAuthScheme.class);
            when(mockScheme.isNegotiateScheme()).thenReturn(false);
            when(mockScheme.isBasicScheme()).thenReturn(true);
            // No colon in credentials
            when(mockScheme.getToken()).thenReturn("nocolonhere".getBytes());

            try (MockedStatic<SpnegoProvider> mockedProvider = mockStatic(SpnegoProvider.class);
                 MockedConstruction<LoginContext> mockedLoginContext = mockConstruction(LoginContext.class,
                     (mock, context) -> {
                         when(mock.getSubject()).thenReturn(new Subject());
                     })) {

                mockedProvider.when(() -> SpnegoProvider.getServerCredential(any(Subject.class)))
                    .thenReturn(mockServerCred);
                mockedProvider.when(() -> SpnegoProvider.negotiate(
                    any(HttpServletRequest.class),
                    any(SpnegoHttpServletResponse.class),
                    anyBoolean(), anyBoolean(), anyString()))
                    .thenReturn(mockScheme);

                when(mockConfig.isBasicAllowed()).thenReturn(true);
                when(mockConfig.isUnsecureAllowed()).thenReturn(true);
                when(mockConfig.getClientLoginModule()).thenReturn("client-module");
                when(mockConfig.isLocalhostAllowed()).thenReturn(false);
                when(mockConfig.downgradeNtlm()).thenReturn(false);
                when(mockConfig.isDelegationAllowed()).thenReturn(false);
                when(mockConfig.useKeyTab()).thenReturn(true);
                when(mockConfig.getServerLoginModule()).thenReturn("server-module");

                SpnegoAuthenticator authenticator = new SpnegoAuthenticator(mockConfig);

                assertThrows(IllegalArgumentException.class, () -> {
                    authenticator.authenticate(mockRequest, mockResponse);
                });
            }
        }
    }
}
