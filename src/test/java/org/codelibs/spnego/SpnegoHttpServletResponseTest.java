package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.HttpServletResponse;

/**
 * Unit tests for {@link SpnegoHttpServletResponse} class.
 */
@ExtendWith(MockitoExtension.class)
class SpnegoHttpServletResponseTest {

    @Mock
    private HttpServletResponse mockResponse;
    
    private SpnegoHttpServletResponse spnegoResponse;
    
    @BeforeEach
    void setup() {
        spnegoResponse = new SpnegoHttpServletResponse(mockResponse);
    }

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {
        
        @Test
        @DisplayName("constructor creates response wrapper")
        void constructorCreatesWrapper() {
            SpnegoHttpServletResponse response = new SpnegoHttpServletResponse(mockResponse);
            
            assertNotNull(response);
            assertFalse(response.isStatusSet());
        }
    }

    @Nested
    @DisplayName("Status tracking tests")
    class StatusTrackingTests {
        
        @Test
        @DisplayName("initial status is not set")
        void initialStatusNotSet() {
            assertFalse(spnegoResponse.isStatusSet());
        }
        
        @Test
        @DisplayName("status set after calling setStatus")
        void statusSetAfterSetStatus() {
            spnegoResponse.setStatus(HttpServletResponse.SC_OK);
            
            assertTrue(spnegoResponse.isStatusSet());
            verify(mockResponse).setStatus(HttpServletResponse.SC_OK);
        }
        
        @Test
        @DisplayName("status tracking for different status codes")
        void statusTrackingDifferentCodes() {
            // Test with various HTTP status codes
            int[] statusCodes = {
                HttpServletResponse.SC_OK,
                HttpServletResponse.SC_UNAUTHORIZED,
                HttpServletResponse.SC_FORBIDDEN,
                HttpServletResponse.SC_NOT_FOUND,
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR
            };
            
            for (int statusCode : statusCodes) {
                SpnegoHttpServletResponse response = new SpnegoHttpServletResponse(mockResponse);
                
                assertFalse(response.isStatusSet());
                response.setStatus(statusCode);
                assertTrue(response.isStatusSet());
                
                verify(mockResponse).setStatus(statusCode);
            }
        }
        
        @Test
        @DisplayName("multiple setStatus calls maintain status set")
        void multipleSetStatusCallsMaintainStatusSet() {
            spnegoResponse.setStatus(HttpServletResponse.SC_OK);
            assertTrue(spnegoResponse.isStatusSet());
            
            spnegoResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            assertTrue(spnegoResponse.isStatusSet());
            
            verify(mockResponse).setStatus(HttpServletResponse.SC_OK);
            verify(mockResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("Immediate response tests")
    class ImmediateResponseTests {
        
        @Test
        @DisplayName("setStatus with immediate false")
        void setStatusImmediateFalse() throws IOException {
            spnegoResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED, false);
            
            assertTrue(spnegoResponse.isStatusSet());
            verify(mockResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            verify(mockResponse, never()).setContentLength(anyInt());
            verify(mockResponse, never()).flushBuffer();
        }
        
        @Test
        @DisplayName("setStatus with immediate true")
        void setStatusImmediateTrue() throws IOException {
            spnegoResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED, true);
            
            assertTrue(spnegoResponse.isStatusSet());
            verify(mockResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            verify(mockResponse).setContentLength(0);
            verify(mockResponse).flushBuffer();
        }
        
        @Test
        @DisplayName("immediate response with different status codes")
        void immediateResponseDifferentStatusCodes() throws IOException {
            int[] statusCodes = {
                HttpServletResponse.SC_OK,
                HttpServletResponse.SC_UNAUTHORIZED,
                HttpServletResponse.SC_FORBIDDEN
            };
            
            for (int statusCode : statusCodes) {
                HttpServletResponse mockResp = mock(HttpServletResponse.class);
                SpnegoHttpServletResponse response = new SpnegoHttpServletResponse(mockResp);
                
                response.setStatus(statusCode, true);
                
                assertTrue(response.isStatusSet());
                verify(mockResp).setStatus(statusCode);
                verify(mockResp).setContentLength(0);
                verify(mockResp).flushBuffer();
            }
        }
        
        @Test
        @DisplayName("IOException from flushBuffer is propagated")
        void ioExceptionFromFlushBufferPropagated() throws IOException {
            doThrow(new IOException("Test exception")).when(mockResponse).flushBuffer();
            
            assertThrows(IOException.class, () -> {
                spnegoResponse.setStatus(HttpServletResponse.SC_OK, true);
            });
            
            // Status should still be set even if flush fails
            assertTrue(spnegoResponse.isStatusSet());
            verify(mockResponse).setStatus(HttpServletResponse.SC_OK);
            verify(mockResponse).setContentLength(0);
        }
    }

    @Nested
    @DisplayName("Edge cases and error handling")
    class EdgeCasesTests {
        
        @Test
        @DisplayName("negative status code")
        void negativeStatusCode() {
            spnegoResponse.setStatus(-1);
            
            assertTrue(spnegoResponse.isStatusSet());
            verify(mockResponse).setStatus(-1);
        }
        
        @Test
        @DisplayName("zero status code")
        void zeroStatusCode() {
            spnegoResponse.setStatus(0);
            
            assertTrue(spnegoResponse.isStatusSet());
            verify(mockResponse).setStatus(0);
        }
        
        @Test
        @DisplayName("very large status code")
        void veryLargeStatusCode() {
            int largeStatus = 999999;
            spnegoResponse.setStatus(largeStatus);
            
            assertTrue(spnegoResponse.isStatusSet());
            verify(mockResponse).setStatus(largeStatus);
        }
        
        @Test
        @DisplayName("status tracking persists across method calls")
        void statusTrackingPersistsAcrossCalls() throws IOException {
            // Initial state
            assertFalse(spnegoResponse.isStatusSet());
            
            // Set status
            spnegoResponse.setStatus(HttpServletResponse.SC_OK);
            assertTrue(spnegoResponse.isStatusSet());
            
            // Call other methods that shouldn't affect status tracking
            spnegoResponse.setContentType("text/html");
            assertTrue(spnegoResponse.isStatusSet());
            
            // Set status with immediate flag
            spnegoResponse.setStatus(HttpServletResponse.SC_ACCEPTED, false);
            assertTrue(spnegoResponse.isStatusSet());
        }
        
        @Test
        @DisplayName("immediate response order of operations")
        void immediateResponseOrderOfOperations() throws IOException {
            spnegoResponse.setStatus(HttpServletResponse.SC_NO_CONTENT, true);
            
            // Verify the order: setStatus, setContentLength, flushBuffer
            var inOrder = inOrder(mockResponse);
            inOrder.verify(mockResponse).setStatus(HttpServletResponse.SC_NO_CONTENT);
            inOrder.verify(mockResponse).setContentLength(0);
            inOrder.verify(mockResponse).flushBuffer();
            
            assertTrue(spnegoResponse.isStatusSet());
        }
    }
}