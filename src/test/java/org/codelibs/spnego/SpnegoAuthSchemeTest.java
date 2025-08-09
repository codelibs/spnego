package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SpnegoAuthScheme} class.
 */
class SpnegoAuthSchemeTest {

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {
        
        @Test
        @DisplayName("negotiate scheme with valid token")
        void negotiateSchemeWithToken() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "dGVzdA==");
            assertEquals("Negotiate", scheme.getScheme());
            assertTrue(scheme.isNegotiateScheme());
            assertFalse(scheme.isBasicScheme());
            assertFalse(scheme.isNtlmToken());
            assertArrayEquals("test".getBytes(), scheme.getToken());
        }
        
        @Test
        @DisplayName("basic scheme with credentials")
        void basicSchemeWithCredentials() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Basic", "dXNlcjpwYXNz");
            assertEquals("Basic", scheme.getScheme());
            assertFalse(scheme.isNegotiateScheme());
            assertTrue(scheme.isBasicScheme());
            assertFalse(scheme.isNtlmToken());
            assertArrayEquals("user:pass".getBytes(), scheme.getToken());
        }
        
        @Test
        @DisplayName("negotiate scheme with NTLM token")
        void negotiateSchemeWithNtlmToken() {
            // NTLM_PROLOG is "TlRMTVNT"
            String ntlmToken = "TlRMTVNTAAAAAAA="; // Starts with NTLM prolog
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", ntlmToken);
            
            assertEquals("Negotiate", scheme.getScheme());
            assertTrue(scheme.isNegotiateScheme());
            assertFalse(scheme.isBasicScheme());
            assertTrue(scheme.isNtlmToken());
        }
        
        @Test
        @DisplayName("case insensitive scheme names")
        void caseInsensitiveSchemes() {
            SpnegoAuthScheme negotiate1 = new SpnegoAuthScheme("negotiate", "dGVzdA==");
            SpnegoAuthScheme negotiate2 = new SpnegoAuthScheme("NEGOTIATE", "dGVzdA==");
            SpnegoAuthScheme basic1 = new SpnegoAuthScheme("basic", "dXNlcjpwYXNz");
            SpnegoAuthScheme basic2 = new SpnegoAuthScheme("BASIC", "dXNlcjpwYXNz");
            
            assertTrue(negotiate1.isNegotiateScheme());
            assertTrue(negotiate2.isNegotiateScheme());
            assertTrue(basic1.isBasicScheme());
            assertTrue(basic2.isBasicScheme());
        }
        
        @Test
        @DisplayName("null token handling")
        void nullToken() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", null);
            
            assertEquals("Negotiate", scheme.getScheme());
            assertTrue(scheme.isNegotiateScheme());
            assertFalse(scheme.isBasicScheme());
            assertFalse(scheme.isNtlmToken());
            assertArrayEquals(new byte[0], scheme.getToken());
        }
        
        @Test
        @DisplayName("empty token handling")
        void emptyToken() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "");
            
            assertEquals("Negotiate", scheme.getScheme());
            assertTrue(scheme.isNegotiateScheme());
            assertFalse(scheme.isBasicScheme());
            assertFalse(scheme.isNtlmToken());
            assertArrayEquals(new byte[0], scheme.getToken());
        }
        
        @Test
        @DisplayName("unknown scheme type")
        void unknownSchemeType() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Unknown", "dGVzdA==");
            
            assertEquals("Unknown", scheme.getScheme());
            assertFalse(scheme.isNegotiateScheme());
            assertFalse(scheme.isBasicScheme());
            assertFalse(scheme.isNtlmToken());
            assertArrayEquals("test".getBytes(), scheme.getToken());
        }
    }

    @Nested
    @DisplayName("NTLM detection tests")
    class NtlmDetectionTests {
        
        @Test
        @DisplayName("NTLM token detection - exact prolog")
        void ntlmTokenExactProlog() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "TlRMTVNT");
            assertTrue(scheme.isNtlmToken());
        }
        
        @Test
        @DisplayName("NTLM token detection - prolog with additional data")
        void ntlmTokenWithAdditionalData() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "TlRMTVNTAAAAAABBBBBB");
            assertTrue(scheme.isNtlmToken());
        }
        
        @Test
        @DisplayName("Non-NTLM token - similar but different")
        void nonNtlmSimilarToken() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "TlRMTVNU"); // Different ending
            assertFalse(scheme.isNtlmToken());
        }
        
        @Test
        @DisplayName("Non-NTLM token - completely different")
        void nonNtlmDifferentToken() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "U29tZVRva2Vu");
            assertFalse(scheme.isNtlmToken());
        }
        
        @Test
        @DisplayName("NTLM detection with basic scheme")
        void ntlmDetectionWithBasicScheme() {
            // Even if token looks like NTLM, it shouldn't matter for Basic scheme in this context
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Basic", "TlRMTVNT");
            assertTrue(scheme.isNtlmToken()); // The detection is independent of scheme type
            assertTrue(scheme.isBasicScheme());
        }
    }

    @Nested
    @DisplayName("Token handling tests")
    class TokenHandlingTests {
        
        @Test
        @DisplayName("valid base64 token decoding")
        void validBase64Decoding() {
            String token = "SGVsbG8gV29ybGQ="; // "Hello World" in base64
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", token);
            
            byte[] decoded = scheme.getToken();
            assertEquals("Hello World", new String(decoded));
        }
        
        @Test
        @DisplayName("token returns copy not reference")
        void tokenReturnsCopy() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "dGVzdA==");
            
            byte[] token1 = scheme.getToken();
            byte[] token2 = scheme.getToken();
            
            assertArrayEquals(token1, token2);
            assertNotSame(token1, token2); // Should be different instances
        }
        
        @Test
        @DisplayName("modifying returned token doesn't affect original")
        void modifyingReturnedTokenSafe() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "dGVzdA==");
            
            byte[] token = scheme.getToken();
            byte[] originalToken = scheme.getToken();
            
            // Modify the returned token
            if (token.length > 0) {
                token[0] = (byte) 'X';
            }
            
            // Original should be unchanged
            byte[] newToken = scheme.getToken();
            assertArrayEquals(originalToken, newToken);
        }
    }

    @Nested
    @DisplayName("toString tests")
    class ToStringTests {
        
        @Test
        @DisplayName("toString contains all relevant information")
        void toStringContainsAllInfo() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "dGVzdA==");
            String result = scheme.toString();
            
            assertTrue(result.contains("scheme=Negotiate"));
            assertTrue(result.contains("token=dGVzdA=="));
            assertTrue(result.contains("basicScheme=false"));
            assertTrue(result.contains("negotiateScheme=true"));
            assertTrue(result.contains("ntlm=false"));
        }
        
        @Test
        @DisplayName("toString with NTLM token")
        void toStringWithNtlm() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Negotiate", "TlRMTVNTAAA=");
            String result = scheme.toString();
            
            assertTrue(result.contains("ntlm=true"));
        }
        
        @Test
        @DisplayName("toString with null token")
        void toStringWithNullToken() {
            SpnegoAuthScheme scheme = new SpnegoAuthScheme("Basic", null);
            String result = scheme.toString();
            
            assertTrue(result.contains("token=null"));
            assertTrue(result.contains("ntlm=false"));
        }
    }
}