package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.ietf.jgss.GSSCredential;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link DelegateServletRequest}. The class under test is an
 * interface, therefore the tests use Mockito to create a mock instance and
 * verify its contract.
 */
@ExtendWith(MockitoExtension.class)
class DelegateServletRequestTest {

    @Mock
    private DelegateServletRequest delegateRequest;

    @Mock
    private GSSCredential credential;

    @Nested
    @DisplayName("Happy path")
    class HappyPath {
        @Test
        @DisplayName("getDelegatedCredential returns the credential supplied by the mock")
        void returnsCredential() {
            // Arrange: mock returns a non‑null credential
            when(delegateRequest.getDelegatedCredential()).thenReturn(credential);

            // Act
            GSSCredential result = delegateRequest.getDelegatedCredential();

            // Assert
            assertSame(credential, result, "The delegated credential should be returned unchanged");
            verify(delegateRequest, times(1)).getDelegatedCredential();
        }
    }

    @Nested
    @DisplayName("Invalid / null inputs")
    class InvalidInputs {
        @Test
        @DisplayName("getDelegatedCredential returns null when no credential is present")
        void returnsNull() {
            // Arrange: mock returns null
            when(delegateRequest.getDelegatedCredential()).thenReturn(null);

            // Act
            GSSCredential result = delegateRequest.getDelegatedCredential();

            // Assert
            assertNull(result, "A null delegated credential should be propagated");
            verify(delegateRequest, times(1)).getDelegatedCredential();
        }
    }

    @Nested
    @DisplayName("Edge scenarios")
    class EdgeScenarios {
        @Test
        @DisplayName("Repeated calls consistently return the same mock value")
        void repeatedCalls() {
            when(delegateRequest.getDelegatedCredential()).thenReturn(credential);

            // First call
            assertSame(credential, delegateRequest.getDelegatedCredential());
            // Second call – should still return the same credential
            assertSame(credential, delegateRequest.getDelegatedCredential());

            // Verify exactly two invocations
            verify(delegateRequest, times(2)).getDelegatedCredential();
        }
    }
}

