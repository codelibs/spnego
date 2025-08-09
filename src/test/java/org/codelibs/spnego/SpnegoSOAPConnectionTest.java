package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.PrivilegedActionException;

import javax.security.auth.login.LoginException;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.MimeHeaders;
import jakarta.xml.soap.SOAPBody;
import jakarta.xml.soap.SOAPConnection;
import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Unit tests for {@link SpnegoSOAPConnection} covering constructors,
 * SOAP message handling, and connection management.
 */
@ExtendWith(MockitoExtension.class)
class SpnegoSOAPConnectionTest {

    @Mock
    private GSSCredential mockCredential;
    
    @Mock
    private SOAPMessage mockRequest;
    
    @Mock
    private SOAPMessage mockResponse;
    
    @Mock
    private MimeHeaders mockMimeHeaders;
    
    @Mock
    private SOAPBody mockSOAPBody;
    
    @Mock
    private Document mockDocument;
    
    @Mock
    private Element mockElement;
    
    @Mock
    private NodeList mockNodeList;
    
    @Mock
    private Node mockNode;
    
    private URL testEndpoint;
    
    @BeforeEach
    void setUp() throws Exception {
        testEndpoint = new URL("http://example.com/soap");
    }
    
    /**
     * Test constructor with login module name
     */
    @Test
    void testConstructorWithLoginModuleName() {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            assertDoesNotThrow(() -> {
                SpnegoSOAPConnection connection = new SpnegoSOAPConnection("test-module");
                assertNotNull(connection);
            });
            
            assertEquals(1, mockedConstruction.constructed().size());
        }
    }
    
    /**
     * Test that we can create connection with MessageFactory mocked
     */
    @Test
    void testConstructorWithMessageFactoryMocked() throws LoginException {
        try (MockedStatic<MessageFactory> mockedMessageFactory = mockStatic(MessageFactory.class)) {
            // Mock MessageFactory to avoid real initialization
            MessageFactory mockFactory = mock(MessageFactory.class);
            mockedMessageFactory.when(MessageFactory::newInstance).thenReturn(mockFactory);
            
            try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                    mockConstruction(SpnegoHttpURLConnection.class)) {
                
                SpnegoSOAPConnection connection = new SpnegoSOAPConnection("test-module");
                assertNotNull(connection);
                assertEquals(1, mockedConstruction.constructed().size());
            }
        }
    }
    
    /**
     * Test constructor with GSSCredential
     */
    @Test
    void testConstructorWithCredential() {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            assertNotNull(connection);
            
            assertEquals(1, mockedConstruction.constructed().size());
        }
    }
    
    /**
     * Test constructor with GSSCredential and dispose flag
     */
    @Test
    void testConstructorWithCredentialAndDispose() {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential, false);
            assertNotNull(connection);
            
            assertEquals(1, mockedConstruction.constructed().size());
        }
    }
    
    /**
     * Test constructor with GSSCredential, dispose flag, and security options
     */
    @Test
    void testConstructorWithFullParameters() {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    // Verify setConfidentiality and setMessageIntegrity are called
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(
                mockCredential, true, true, true);
            assertNotNull(connection);
            
            assertEquals(1, mockedConstruction.constructed().size());
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).setConfidentiality(true);
            verify(constructedConn).setMessageIntegrity(true);
        }
    }
    
    /**
     * Test constructor with username and password
     */
    @Test
    void testConstructorWithUsernamePassword() {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            assertDoesNotThrow(() -> {
                SpnegoSOAPConnection connection = new SpnegoSOAPConnection(
                    "test-module", "username", "password");
                assertNotNull(connection);
            });
            
            assertEquals(1, mockedConstruction.constructed().size());
        }
    }
    
    /**
     * Test call method with successful SOAP message exchange
     */
    @Test
    void testCallSuccessful() throws Exception {
        String soapResponse = "<?xml version=\"1.0\"?>" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
            "<soap:Body>" +
            "<m:GetPriceResponse xmlns:m=\"http://example.com\">" +
            "<m:Price>100</m:Price>" +
            "</m:GetPriceResponse>" +
            "</soap:Body>" +
            "</soap:Envelope>";
        
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenReturn(
                        new ByteArrayInputStream(soapResponse.getBytes()));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            ByteArrayOutputStream capturedOutput = new ByteArrayOutputStream();
            doAnswer(invocation -> {
                ByteArrayOutputStream bos = invocation.getArgument(0);
                bos.write("<test/>".getBytes());
                return null;
            }).when(mockRequest).writeTo(any(ByteArrayOutputStream.class));
            
            SOAPMessage result = connection.call(mockRequest, testEndpoint);
            assertNotNull(result);
            
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).setRequestMethod("POST");
            verify(constructedConn).connect(eq(testEndpoint), any(ByteArrayOutputStream.class));
            verify(constructedConn).disconnect();
        }
    }
    
    /**
     * Test call method with Content-Type header specified
     */
    @Test
    void testCallWithContentTypeHeader() throws Exception {
        String soapResponse = "<?xml version=\"1.0\"?>" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
            "<soap:Body><test/></soap:Body></soap:Envelope>";
        
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenReturn(
                        new ByteArrayInputStream(soapResponse.getBytes()));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type"))
                .thenReturn(new String[]{"text/xml; charset=UTF-8"});
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            SOAPMessage result = connection.call(mockRequest, testEndpoint);
            assertNotNull(result);
            
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).addRequestProperty("Content-Type", "text/xml; charset=UTF-8");
        }
    }
    
    /**
     * Test call method with SOAPAction header
     */
    @Test
    void testCallWithSOAPActionHeader() throws Exception {
        String soapResponse = "<?xml version=\"1.0\"?>" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
            "<soap:Body><test/></soap:Body></soap:Envelope>";
        
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenReturn(
                        new ByteArrayInputStream(soapResponse.getBytes()));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction"))
                .thenReturn(new String[]{"\"http://example.com/GetPrice\""});
            
            SOAPMessage result = connection.call(mockRequest, testEndpoint);
            assertNotNull(result);
            
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).addRequestProperty("Content-Type", "text/xml; charset=UTF-8;");
            verify(constructedConn).addRequestProperty("SOAPAction", "\"http://example.com/GetPrice\"");
        }
    }
    
    /**
     * Test call method with multiple Content-Type headers throws exception
     */
    @Test
    void testCallWithMultipleContentTypeHeaders() throws Exception {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type"))
                .thenReturn(new String[]{"text/xml", "application/soap+xml"});
            
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                connection.call(mockRequest, testEndpoint);
            });
            
            assertEquals("Content-Type defined more than once.", 
                exception.getMessage());
        }
    }
    
    /**
     * Test call method with multiple SOAPAction headers throws exception
     */
    @Test
    void testCallWithMultipleSOAPActionHeaders() throws Exception {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction"))
                .thenReturn(new String[]{"action1", "action2"});
            
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                connection.call(mockRequest, testEndpoint);
            });
            
            assertEquals("SOAPAction defined more than once.", 
                exception.getMessage());
        }
    }
    
    /**
     * Test call method with IOException
     */
    @Test
    void testCallWithIOException() throws Exception {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenThrow(new IOException("Test IO exception"));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            SOAPException exception = assertThrows(SOAPException.class, () -> {
                connection.call(mockRequest, testEndpoint);
            });
            
            assertTrue(exception.getCause() instanceof IOException);
            
            // Verify disconnect is still called
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).disconnect();
        }
    }
    
    /**
     * Test call method with GSSException
     */
    @Test
    void testCallWithGSSException() throws Exception {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    doThrow(new GSSException(GSSException.FAILURE))
                        .when(mock).connect(any(URL.class), any(ByteArrayOutputStream.class));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            SOAPException exception = assertThrows(SOAPException.class, () -> {
                connection.call(mockRequest, testEndpoint);
            });
            
            assertTrue(exception.getCause() instanceof GSSException);
            
            // Verify disconnect is still called
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).disconnect();
        }
    }
    
    /**
     * Test call method with PrivilegedActionException
     */
    @Test
    void testCallWithPrivilegedActionException() throws Exception {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    doThrow(new PrivilegedActionException(new Exception("Test exception")))
                        .when(mock).connect(any(URL.class), any(ByteArrayOutputStream.class));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            SOAPException exception = assertThrows(SOAPException.class, () -> {
                connection.call(mockRequest, testEndpoint);
            });
            
            assertTrue(exception.getCause() instanceof PrivilegedActionException);
            
            // Verify disconnect is still called
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).disconnect();
        }
    }
    
    /**
     * Test call method with invalid SOAP response (no Envelope)
     */
    @Test
    void testCallWithInvalidResponseNoEnvelope() throws Exception {
        String invalidResponse = "<?xml version=\"1.0\"?>" +
            "<NotAnEnvelope><test/></NotAnEnvelope>";
        
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenReturn(
                        new ByteArrayInputStream(invalidResponse.getBytes()));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                connection.call(mockRequest, testEndpoint);
            });
            
            assertEquals("Response did not contain a SOAP 'Envelope'.", 
                exception.getMessage());
        }
    }
    
    /**
     * Test call method with invalid SOAP response (no Body)
     */
    @Test
    void testCallWithInvalidResponseNoBody() throws Exception {
        String invalidResponse = "<?xml version=\"1.0\"?>" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
            "<soap:Header/>" +
            "</soap:Envelope>";
        
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenReturn(
                        new ByteArrayInputStream(invalidResponse.getBytes()));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                connection.call(mockRequest, testEndpoint);
            });
            
            assertEquals("Response did not contain a SOAP 'Body'.", 
                exception.getMessage());
        }
    }
    
    /**
     * Test call method with empty Body
     */
    @Test
    void testCallWithEmptyBody() throws Exception {
        String response = "<?xml version=\"1.0\"?>" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
            "<soap:Body/>" +
            "</soap:Envelope>";
        
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenReturn(
                        new ByteArrayInputStream(response.getBytes()));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            SOAPMessage result = connection.call(mockRequest, testEndpoint);
            assertNotNull(result);
            assertNotNull(result.getSOAPBody());
        }
    }
    
    /**
     * Test call method with complex SOAP Body containing multiple children
     */
    @Test
    void testCallWithMultipleBodyChildren() throws Exception {
        String response = "<?xml version=\"1.0\"?>" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
            "<soap:Body>" +
            "<child1>Value1</child1>" +
            "<child2>Value2</child2>" +
            "<child3>Value3</child3>" +
            "</soap:Body>" +
            "</soap:Envelope>";
        
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenReturn(
                        new ByteArrayInputStream(response.getBytes()));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            SOAPMessage result = connection.call(mockRequest, testEndpoint);
            assertNotNull(result);
            assertNotNull(result.getSOAPBody());
        }
    }
    
    /**
     * Test close method
     */
    @Test
    void testClose() {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            connection.close();
            
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).disconnect();
        }
    }
    
    /**
     * Test close method called multiple times
     */
    @Test
    void testCloseMultipleTimes() {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            connection.close();
            connection.close();
            connection.close();
            
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn, times(3)).disconnect();
        }
    }
    
    /**
     * Test that SpnegoSOAPConnection extends SOAPConnection
     */
    @Test
    void testExtendsSOAPConnection() {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            assertTrue(connection instanceof SOAPConnection);
        }
    }
    
    /**
     * Test constructor when MessageFactory.newInstance() throws SOAPException
     */
    @Test
    void testConstructorWithMessageFactoryException() {
        try (MockedStatic<MessageFactory> mockedFactory = mockStatic(MessageFactory.class)) {
            mockedFactory.when(MessageFactory::newInstance)
                .thenThrow(new SOAPException("Test factory exception"));
            
            try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                    mockConstruction(SpnegoHttpURLConnection.class)) {
                
                assertThrows(IllegalStateException.class, () -> {
                    new SpnegoSOAPConnection(mockCredential);
                });
            }
        }
    }
    
    /**
     * Test call method with Content-Type header for SOAP 1.2 (no SOAPAction)
     */
    @Test
    void testCallWithSOAP12ContentType() throws Exception {
        String soapResponse = "<?xml version=\"1.0\"?>" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
            "<soap:Body><test/></soap:Body></soap:Envelope>";
        
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class, (mock, context) -> {
                    when(mock.getInputStream()).thenReturn(
                        new ByteArrayInputStream(soapResponse.getBytes()));
                })) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            
            SOAPMessage result = connection.call(mockRequest, testEndpoint);
            assertNotNull(result);
            
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).addRequestProperty("Content-Type", 
                "application/soap+xml; charset=UTF-8;");
        }
    }
    
    /**
     * Test call method ensures close is called even when writeTo throws exception
     */
    @Test
    void testCallEnsuresCloseOnWriteToException() throws Exception {
        try (MockedConstruction<SpnegoHttpURLConnection> mockedConstruction = 
                mockConstruction(SpnegoHttpURLConnection.class)) {
            
            SpnegoSOAPConnection connection = new SpnegoSOAPConnection(mockCredential);
            
            when(mockRequest.getMimeHeaders()).thenReturn(mockMimeHeaders);
            when(mockMimeHeaders.getHeader("Content-Type")).thenReturn(null);
            when(mockMimeHeaders.getHeader("SOAPAction")).thenReturn(null);
            doThrow(new IOException("Write failed"))
                .when(mockRequest).writeTo(any(ByteArrayOutputStream.class));
            
            assertThrows(SOAPException.class, () -> {
                connection.call(mockRequest, testEndpoint);
            });
            
            // Verify disconnect is still called
            SpnegoHttpURLConnection constructedConn = mockedConstruction.constructed().get(0);
            verify(constructedConn).disconnect();
        }
    }
}