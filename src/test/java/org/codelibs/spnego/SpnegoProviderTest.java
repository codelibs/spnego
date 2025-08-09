package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SpnegoProvider} utility class.
 */
class SpnegoProviderTest {

    @Nested
    @DisplayName("getAuthScheme() tests")
    class GetAuthSchemeTests {
        
        @Test
        @DisplayName("null header returns null")
        void nullHeaderReturnsNull() {
            SpnegoAuthScheme result = SpnegoProvider.getAuthScheme(null);
            assertNull(result);
        }
        
        @Test
        @DisplayName("empty header returns null")
        void emptyHeaderReturnsNull() {
            SpnegoAuthScheme result = SpnegoProvider.getAuthScheme("");
            assertNull(result);
        }
        
        @Test
        @DisplayName("valid Negotiate header")
        void validNegotiateHeader() {
            SpnegoAuthScheme result = SpnegoProvider.getAuthScheme("Negotiate YWJjZGU=");
            
            assertNotNull(result);
            assertEquals("Negotiate", result.getScheme());
            assertTrue(result.isNegotiateScheme());
            assertFalse(result.isBasicScheme());
            assertArrayEquals("abcde".getBytes(), result.getToken());
        }
        
        @Test
        @DisplayName("valid Basic header")
        void validBasicHeader() {
            SpnegoAuthScheme result = SpnegoProvider.getAuthScheme("Basic dXNlcjpwYXNz");
            
            assertNotNull(result);
            assertEquals("Basic", result.getScheme());
            assertFalse(result.isNegotiateScheme());
            assertTrue(result.isBasicScheme());
            assertArrayEquals("user:pass".getBytes(), result.getToken());
        }
        
        @Test
        @DisplayName("case insensitive scheme names")
        void caseInsensitiveSchemes() {
            SpnegoAuthScheme negotiate = SpnegoProvider.getAuthScheme("negotiate dGVzdA==");
            SpnegoAuthScheme basic = SpnegoProvider.getAuthScheme("BASIC dXNlcjpwYXNz");
            
            assertNotNull(negotiate);
            assertTrue(negotiate.isNegotiateScheme());
            
            assertNotNull(basic);
            assertTrue(basic.isBasicScheme());
        }
        
        @Test
        @DisplayName("header with extra whitespace")
        void headerWithWhitespace() {
            SpnegoAuthScheme result = SpnegoProvider.getAuthScheme("Negotiate   dGVzdA==   ");
            
            assertNotNull(result);
            assertEquals("Negotiate", result.getScheme());
            assertArrayEquals("test".getBytes(), result.getToken());
        }
        
        @Test
        @DisplayName("scheme without token throws exception")
        void schemeWithoutToken() {
            // Based on implementation, if scheme is recognized but has no token, it throws exception
            assertThrows(UnsupportedOperationException.class, () -> {
                SpnegoProvider.getAuthScheme("Negotiate");
            });
            
            assertThrows(UnsupportedOperationException.class, () -> {
                SpnegoProvider.getAuthScheme("Basic");
            });
        }
        
        @Test
        @DisplayName("scheme with empty token throws exception")
        void schemeWithEmptyToken() {
            // Based on implementation, empty tokens also throw exception
            assertThrows(UnsupportedOperationException.class, () -> {
                SpnegoProvider.getAuthScheme("Negotiate   ");
            });
            
            assertThrows(UnsupportedOperationException.class, () -> {
                SpnegoProvider.getAuthScheme("Basic   ");
            });
        }
        
        @Test
        @DisplayName("unsupported scheme throws exception")
        void unsupportedSchemeThrowsException() {
            assertThrows(UnsupportedOperationException.class, () -> {
                SpnegoProvider.getAuthScheme("Digest realm=test");
            });
        }
        
        @Test
        @DisplayName("malformed header throws exception")
        void malformedHeaderThrowsException() {
            assertThrows(UnsupportedOperationException.class, () -> {
                SpnegoProvider.getAuthScheme("SomeUnknownScheme dGVzdA==");
            });
        }
    }

    @Nested
    @DisplayName("getUsernamePasswordHandler() tests")
    class GetUsernamePasswordHandlerTests {
        
        @Test
        @DisplayName("handler processes NameCallback correctly")
        void handlerProcessesNameCallback() throws Exception {
            String username = "testuser";
            String password = "testpass";
            
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(username, password);
            
            NameCallback nameCallback = new NameCallback("Username:");
            Callback[] callbacks = {nameCallback};
            
            handler.handle(callbacks);
            
            assertEquals(username, nameCallback.getName());
        }
        
        @Test
        @DisplayName("handler processes PasswordCallback correctly")
        void handlerProcessesPasswordCallback() throws Exception {
            String username = "testuser";
            String password = "testpass";
            
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(username, password);
            
            PasswordCallback passwordCallback = new PasswordCallback("Password:", false);
            Callback[] callbacks = {passwordCallback};
            
            handler.handle(callbacks);
            
            assertArrayEquals(password.toCharArray(), passwordCallback.getPassword());
        }
        
        @Test
        @DisplayName("handler processes both name and password callbacks")
        void handlerProcessesBothCallbacks() throws Exception {
            String username = "testuser";
            String password = "testpass";
            
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(username, password);
            
            NameCallback nameCallback = new NameCallback("Username:");
            PasswordCallback passwordCallback = new PasswordCallback("Password:", false);
            Callback[] callbacks = {nameCallback, passwordCallback};
            
            handler.handle(callbacks);
            
            assertEquals(username, nameCallback.getName());
            assertArrayEquals(password.toCharArray(), passwordCallback.getPassword());
        }
        
        @Test
        @DisplayName("handler ignores unsupported callbacks")
        void handlerIgnoresUnsupportedCallbacks() throws Exception {
            String username = "testuser";
            String password = "testpass";
            
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(username, password);
            
            NameCallback nameCallback = new NameCallback("Username:");
            Callback unsupportedCallback = mock(Callback.class);
            Callback[] callbacks = {nameCallback, unsupportedCallback};
            
            // Should not throw exception, just log warning
            assertDoesNotThrow(() -> handler.handle(callbacks));
            
            assertEquals(username, nameCallback.getName());
        }
        
        @Test
        @DisplayName("handler with null username")
        void handlerWithNullUsername() throws Exception {
            String password = "testpass";
            
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(null, password);
            
            NameCallback nameCallback = new NameCallback("Username:");
            Callback[] callbacks = {nameCallback};
            
            handler.handle(callbacks);
            
            assertNull(nameCallback.getName());
        }
        
        @Test
        @DisplayName("handler with null password")
        void handlerWithNullPassword() throws Exception {
            String username = "testuser";
            
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(username, null);
            
            PasswordCallback passwordCallback = new PasswordCallback("Password:", false);
            Callback[] callbacks = {passwordCallback};
            
            // Should throw NullPointerException when trying to convert null to char array
            assertThrows(NullPointerException.class, () -> {
                handler.handle(callbacks);
            });
        }
        
        @Test
        @DisplayName("handler with empty username and password")
        void handlerWithEmptyCredentials() throws Exception {
            String username = "";
            String password = "";
            
            CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(username, password);
            
            NameCallback nameCallback = new NameCallback("Username:");
            PasswordCallback passwordCallback = new PasswordCallback("Password:", false);
            Callback[] callbacks = {nameCallback, passwordCallback};
            
            handler.handle(callbacks);
            
            assertEquals("", nameCallback.getName());
            assertArrayEquals(new char[0], passwordCallback.getPassword());
        }
    }

    @Nested
    @DisplayName("Edge cases and validation tests")
    class EdgeCasesTests {
        
        @Test
        @DisplayName("header parsing with special characters")
        void headerParsingWithSpecialChars() {
            // Test with various valid Base64 characters including padding
            SpnegoAuthScheme result = SpnegoProvider.getAuthScheme("Negotiate QUJDREVGRw==");
            
            assertNotNull(result);
            assertEquals("Negotiate", result.getScheme());
            assertTrue(result.isNegotiateScheme());
        }
        
        @Test
        @DisplayName("extremely long header")
        void extremelyLongHeader() {
            StringBuilder longToken = new StringBuilder();
            for (int i = 0; i < 1000; i++) {
                longToken.append("A");
            }
            String header = "Negotiate " + longToken.toString();
            
            SpnegoAuthScheme result = SpnegoProvider.getAuthScheme(header);
            
            assertNotNull(result);
            assertEquals("Negotiate", result.getScheme());
        }
        
        @Test
        @DisplayName("header with tabs and other whitespace")
        void headerWithTabs() {
            SpnegoAuthScheme result = SpnegoProvider.getAuthScheme("Basic\t\tdGVzdA==");
            
            assertNotNull(result);
            assertEquals("Basic", result.getScheme());
            assertTrue(result.isBasicScheme());
        }
        
        @Test
        @DisplayName("partial scheme match should not work")
        void partialSchemeMatch() {
            // "Neg" is a prefix of "Negotiate" but should not match
            assertThrows(UnsupportedOperationException.class, () -> {
                SpnegoProvider.getAuthScheme("Neg dGVzdA==");
            });
        }
    }
}