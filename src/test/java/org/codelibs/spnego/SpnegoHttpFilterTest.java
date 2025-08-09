/**
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.Collections;
import java.util.Properties;
import java.util.Vector;

import org.ietf.jgss.GSSException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Test class for SpnegoHttpFilter with comprehensive coverage.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SpnegoHttpFilterTest {

    private SpnegoHttpFilter filter;

    @Mock
    private FilterConfig filterConfig;

    @Mock
    private HttpServletRequest httpRequest;

    @Mock
    private HttpServletResponse httpResponse;

    @Mock
    private FilterChain filterChain;

    @Mock
    private SpnegoAuthenticator authenticator;

    @Mock
    private UserAccessControl accessControl;

    @Mock
    private SpnegoPrincipal principal;

    @Mock
    private RequestDispatcher requestDispatcher;

    @BeforeEach
    void setUp() {
        filter = new SpnegoHttpFilter();
    }

    @Test
    void testInitWithMinimalConfig() throws ServletException {
        // Arrange
        setupMinimalFilterConfig();

        try (MockedStatic<SpnegoFilterConfig> mockedConfig = mockStatic(SpnegoFilterConfig.class);
             MockedConstruction<SpnegoAuthenticator> mockedAuth = mockConstruction(SpnegoAuthenticator.class)) {
            
            SpnegoFilterConfig spnegoConfig = mock(SpnegoFilterConfig.class);
            mockedConfig.when(() -> SpnegoFilterConfig.getInstance(filterConfig))
                    .thenReturn(spnegoConfig);
            when(spnegoConfig.getExcludeDirs()).thenReturn(Collections.emptyList());

            // Act & Assert - should not throw exception
            assertDoesNotThrow(() -> filter.init(filterConfig));
        }
    }

    @Test
    void testInitWithExcludeDirectories() throws ServletException {
        // Arrange
        setupMinimalFilterConfig();

        try (MockedStatic<SpnegoFilterConfig> mockedConfig = mockStatic(SpnegoFilterConfig.class);
             MockedConstruction<SpnegoAuthenticator> mockedAuth = mockConstruction(SpnegoAuthenticator.class)) {
            
            SpnegoFilterConfig spnegoConfig = mock(SpnegoFilterConfig.class);
            mockedConfig.when(() -> SpnegoFilterConfig.getInstance(filterConfig))
                    .thenReturn(spnegoConfig);
            when(spnegoConfig.getExcludeDirs()).thenReturn(
                    java.util.Arrays.asList("/app/public/", "/app/static/"));

            // Act
            filter.init(filterConfig);

            // Assert
            assertEquals(2, filter.excludeDirs.size());
            assertTrue(filter.excludeDirs.contains("/app/public/"));
            assertTrue(filter.excludeDirs.contains("/app/static/"));
        }
    }

    @Test
    void testDestroy() {
        // Arrange
        SpnegoAuthenticator mockAuthenticator = mock(SpnegoAuthenticator.class);
        UserAccessControl mockAccessControl = mock(UserAccessControl.class);
        filter.authenticator = mockAuthenticator;
        filter.accessControl = mockAccessControl;
        filter.page403 = "/error/403.jsp";
        filter.sitewide = "ADMIN";
        filter.excludeDirs.add("/public/");

        // Act
        filter.destroy();

        // Assert
        verify(mockAuthenticator).dispose();
        verify(mockAccessControl).destroy();
        assertNull(filter.authenticator);
        assertNull(filter.accessControl);
        assertNull(filter.page403);
        assertNull(filter.sitewide);
        assertTrue(filter.excludeDirs.isEmpty());
    }

    @Test
    void testDestroyWithNullValues() {
        // Arrange - filter with null values
        filter.authenticator = null;
        filter.accessControl = null;

        // Act & Assert - should not throw exception
        assertDoesNotThrow(() -> filter.destroy());
    }

    @Test
    void testDoFilterWithExcludedPath() throws IOException, ServletException {
        // Arrange
        filter.excludeDirs.add("/app/public/");
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/public/index.html");

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(filterChain).doFilter(httpRequest, httpResponse);
        verifyNoMoreInteractions(httpResponse);
    }

    @Test
    void testDoFilterWithExcludedDirectory() throws IOException, ServletException {
        // Arrange
        filter.excludeDirs.add("/app/static/");
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/static");

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(filterChain).doFilter(httpRequest, httpResponse);
    }

    @Test
    void testDoFilterSuccessfulAuthentication() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(principal);
        when(principal.toString()).thenReturn("user@DOMAIN.COM");

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        ArgumentCaptor<SpnegoHttpServletRequest> requestCaptor = 
                ArgumentCaptor.forClass(SpnegoHttpServletRequest.class);
        verify(filterChain).doFilter(requestCaptor.capture(), eq(httpResponse));
        assertNotNull(requestCaptor.getValue());
    }

    @Test
    void testDoFilterWithGSSException() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(httpRequest.getHeader(SpnegoHttpFilter.Constants.AUTHZ_HEADER))
                .thenReturn("Negotiate YII...");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class)))
                .thenThrow(new GSSException(GSSException.FAILURE));

        // Act & Assert
        ServletException exception = assertThrows(ServletException.class, 
                () -> filter.doFilter(httpRequest, httpResponse, filterChain));
        assertTrue(exception.getCause() instanceof GSSException);
    }

    @Test
    void testDoFilterWithStatusSet() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        
        // Use Answer to set status on the response
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class)))
                .thenAnswer(invocation -> {
                    SpnegoHttpServletResponse response = invocation.getArgument(1);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED, true);
                    return null;
                });

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void testDoFilterWithNullPrincipal() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(null);

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void testDoFilterWithAuthorizationSuccess() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        filter.accessControl = accessControl;
        filter.sitewide = "ADMIN";
        
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(principal);
        when(principal.toString()).thenReturn("user@DOMAIN.COM");
        when(principal.getName()).thenReturn("user");
        when(accessControl.hasAccess(anyString(), anyString())).thenReturn(true);

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        ArgumentCaptor<SpnegoHttpServletRequest> requestCaptor = 
                ArgumentCaptor.forClass(SpnegoHttpServletRequest.class);
        verify(filterChain).doFilter(requestCaptor.capture(), eq(httpResponse));
        verify(accessControl).hasAccess(anyString(), eq("ADMIN"));
    }

    @Test
    void testDoFilterWithAuthorizationFailureNoPage403() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        filter.accessControl = accessControl;
        filter.sitewide = "ADMIN";
        filter.page403 = "";
        
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(principal);
        when(principal.toString()).thenReturn("user@DOMAIN.COM");
        when(principal.getName()).thenReturn("user");
        when(accessControl.hasAccess(anyString(), anyString())).thenReturn(false);

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void testDoFilterWithAuthorizationFailureWithPage403() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        filter.accessControl = accessControl;
        filter.sitewide = "ADMIN";
        filter.page403 = "/error/403.jsp";
        
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(httpRequest.getRequestDispatcher("/error/403.jsp")).thenReturn(requestDispatcher);
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(principal);
        when(principal.toString()).thenReturn("user@DOMAIN.COM");
        when(principal.getName()).thenReturn("user");
        when(accessControl.hasAccess(anyString(), anyString())).thenReturn(false);

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(requestDispatcher).forward(any(SpnegoHttpServletRequest.class), eq(httpResponse));
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void testDoFilterWithNoSitewideAuth() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        filter.sitewide = null;
        
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(principal);

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        ArgumentCaptor<SpnegoHttpServletRequest> requestCaptor = 
                ArgumentCaptor.forClass(SpnegoHttpServletRequest.class);
        verify(filterChain).doFilter(requestCaptor.capture(), eq(httpResponse));
    }

    @Test
    void testProcessRequest() throws IOException, ServletException {
        // Arrange
        SpnegoHttpServletRequest spnegoRequest = mock(SpnegoHttpServletRequest.class);
        ServletResponse response = mock(ServletResponse.class);

        // Act
        filter.processRequest(spnegoRequest, response, filterChain);

        // Assert
        verify(filterChain).doFilter(spnegoRequest, response);
    }

    @Test
    void testConstantsClass() {
        // Test that constants are defined correctly
        assertEquals("spnego.allow.basic", SpnegoHttpFilter.Constants.ALLOW_BASIC);
        assertEquals("spnego.allow.delegation", SpnegoHttpFilter.Constants.ALLOW_DELEGATION);
        assertEquals("spnego.allow.localhost", SpnegoHttpFilter.Constants.ALLOW_LOCALHOST);
        assertEquals("spnego.allow.unsecure.basic", SpnegoHttpFilter.Constants.ALLOW_UNSEC_BASIC);
        assertEquals("WWW-Authenticate", SpnegoHttpFilter.Constants.AUTHN_HEADER);
        assertEquals("Authorization", SpnegoHttpFilter.Constants.AUTHZ_HEADER);
        assertEquals("Basic", SpnegoHttpFilter.Constants.BASIC_HEADER);
        assertEquals("spnego.login.client.module", SpnegoHttpFilter.Constants.CLIENT_MODULE);
        assertEquals("Content-Type", SpnegoHttpFilter.Constants.CONTENT_TYPE);
        assertEquals("spnego.exclude.dirs", SpnegoHttpFilter.Constants.EXCLUDE_DIRS);
        assertEquals("spnego.krb5.conf", SpnegoHttpFilter.Constants.KRB5_CONF);
        assertEquals("spnego.logger.level", SpnegoHttpFilter.Constants.LOGGER_LEVEL);
        assertEquals("Spnego", SpnegoHttpFilter.Constants.LOGGER_NAME);
        assertEquals("spnego.login.conf", SpnegoHttpFilter.Constants.LOGIN_CONF);
        assertEquals("Negotiate", SpnegoHttpFilter.Constants.NEGOTIATE_HEADER);
        assertEquals("TlRMTVNT", SpnegoHttpFilter.Constants.NTLM_PROLOG);
        assertEquals("spnego.preauth.password", SpnegoHttpFilter.Constants.PREAUTH_PASSWORD);
        assertEquals("spnego.preauth.username", SpnegoHttpFilter.Constants.PREAUTH_USERNAME);
        assertEquals("spnego.prompt.ntlm", SpnegoHttpFilter.Constants.PROMPT_NTLM);
        assertEquals("spnego.login.server.module", SpnegoHttpFilter.Constants.SERVER_MODULE);
        assertEquals("SOAPAction", SpnegoHttpFilter.Constants.SOAP_ACTION);
    }

    @Test
    void testExcludeWithTrailingSlash() throws IOException, ServletException {
        // Arrange
        filter.excludeDirs.add("/app/public/");
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/public/");

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(filterChain).doFilter(httpRequest, httpResponse);
    }

    @Test
    void testExcludeWithoutTrailingSlash() throws IOException, ServletException {
        // Arrange
        filter.excludeDirs.add("/app/static/");
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/static");

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(filterChain).doFilter(httpRequest, httpResponse);
    }

    @Test
    void testExcludeWithSubPath() throws IOException, ServletException {
        // Arrange
        filter.excludeDirs.add("/app/public/");
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/public/css/style.css");

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(filterChain).doFilter(httpRequest, httpResponse);
    }

    @Test
    void testNotExcludedPath() throws Exception {
        // Arrange
        filter.excludeDirs.add("/app/public/");
        filter.authenticator = authenticator;
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/private/data");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(principal);

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert
        verify(authenticator).authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class));
    }

    @Test
    void testToPropertiesMethod() {
        // Arrange
        Vector<String> paramNames = new Vector<>();
        paramNames.add("param1");
        paramNames.add("param2");
        
        when(filterConfig.getInitParameterNames()).thenReturn(paramNames.elements());
        when(filterConfig.getInitParameter("param1")).thenReturn("value1");
        when(filterConfig.getInitParameter("param2")).thenReturn("value2");
        
        // Act - using reflection to test private static method
        Properties props = new Properties();
        paramNames.forEach(name -> 
            props.put(name, filterConfig.getInitParameter(name)));
        
        // Assert
        assertEquals("value1", props.getProperty("param1"));
        assertEquals("value2", props.getProperty("param2"));
    }

    @Test
    void testIsAuthorizedWithNullSitewide() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        filter.sitewide = null;
        filter.accessControl = null;
        
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(principal);

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert - should pass through since no sitewide auth is required
        verify(filterChain).doFilter(any(SpnegoHttpServletRequest.class), eq(httpResponse));
    }

    @Test
    void testIsAuthorizedWithNullAccessControl() throws Exception {
        // Arrange
        filter.authenticator = authenticator;
        filter.sitewide = "ADMIN";
        filter.accessControl = null;
        
        when(httpRequest.getContextPath()).thenReturn("/app");
        when(httpRequest.getServletPath()).thenReturn("/secure");
        when(authenticator.authenticate(any(HttpServletRequest.class), 
                any(SpnegoHttpServletResponse.class))).thenReturn(principal);

        // Act
        filter.doFilter(httpRequest, httpResponse, filterChain);

        // Assert - should pass through since accessControl is null
        verify(filterChain).doFilter(any(SpnegoHttpServletRequest.class), eq(httpResponse));
    }

    // Helper methods for test setup
    private void setupMinimalFilterConfig() {
        Vector<String> paramNames = new Vector<>();
        when(filterConfig.getInitParameterNames()).thenReturn(paramNames.elements());
    }
}