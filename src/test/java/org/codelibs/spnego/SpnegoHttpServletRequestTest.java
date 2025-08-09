package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.Principal;

import org.ietf.jgss.GSSCredential;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Unit tests for {@link SpnegoHttpServletRequest} class.
 */
@ExtendWith(MockitoExtension.class)
class SpnegoHttpServletRequestTest {

    @Mock
    private HttpServletRequest mockRequest;
    
    @Mock
    private SpnegoPrincipal mockPrincipal;
    
    @Mock
    private UserAccessControl mockAccessControl;
    
    @Mock
    private GSSCredential mockCredential;

    @Nested
    @DisplayName("Constructor and basic functionality tests")
    class ConstructorTests {
        
        @Test
        @DisplayName("constructor with principal only")
        void constructorWithPrincipalOnly() {
            SpnegoHttpServletRequest request = new SpnegoHttpServletRequest(mockRequest, mockPrincipal);
            
            assertNotNull(request);
            assertEquals(mockPrincipal, request.getUserPrincipal());
        }
        
        @Test
        @DisplayName("constructor with principal and access control")
        void constructorWithPrincipalAndAccessControl() {
            SpnegoHttpServletRequest request = new SpnegoHttpServletRequest(mockRequest, mockPrincipal, mockAccessControl);
            
            assertNotNull(request);
            assertEquals(mockPrincipal, request.getUserPrincipal());
        }
        
        @Test
        @DisplayName("constructor with null principal")
        void constructorWithNullPrincipal() {
            SpnegoHttpServletRequest request = new SpnegoHttpServletRequest(mockRequest, null);
            
            assertNotNull(request);
            assertNull(request.getUserPrincipal());
        }
    }

    @Nested
    @DisplayName("Authentication type tests")
    class AuthTypeTests {
        
        private SpnegoHttpServletRequest spnegoRequest;
        
        @BeforeEach
        void setup() {
            spnegoRequest = new SpnegoHttpServletRequest(mockRequest, mockPrincipal);
        }
        
        @Test
        @DisplayName("negotiate auth type from Authorization header")
        void negotiateAuthType() {
            when(mockRequest.getHeader("Authorization")).thenReturn("Negotiate dGVzdA==");
            
            String authType = spnegoRequest.getAuthType();
            
            assertEquals("Negotiate", authType);
        }
        
        @Test
        @DisplayName("basic auth type from Authorization header")
        void basicAuthType() {
            when(mockRequest.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");
            
            String authType = spnegoRequest.getAuthType();
            
            assertEquals("Basic", authType);
        }
        
        @Test
        @DisplayName("default auth type when no Authorization header")
        void defaultAuthTypeNoHeader() {
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.getAuthType()).thenReturn("FORM");
            
            String authType = spnegoRequest.getAuthType();
            
            assertEquals("FORM", authType);
        }
        
        @Test
        @DisplayName("default auth type for unknown authorization scheme")
        void defaultAuthTypeUnknownScheme() {
            when(mockRequest.getHeader("Authorization")).thenReturn("Digest realm=test");
            when(mockRequest.getAuthType()).thenReturn("DIGEST");
            
            String authType = spnegoRequest.getAuthType();
            
            assertEquals("DIGEST", authType);
        }
    }

    @Nested
    @DisplayName("Remote user tests")
    class RemoteUserTests {
        
        @Test
        @DisplayName("remote user from principal name")
        void remoteUserFromPrincipal() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            
            SpnegoHttpServletRequest request = new SpnegoHttpServletRequest(mockRequest, mockPrincipal);
            
            assertEquals("testuser", request.getRemoteUser());
        }
        
        @Test
        @DisplayName("remote user without realm")
        void remoteUserWithoutRealm() {
            when(mockPrincipal.getName()).thenReturn("simpleuser");
            
            SpnegoHttpServletRequest request = new SpnegoHttpServletRequest(mockRequest, mockPrincipal);
            
            assertEquals("simpleuser", request.getRemoteUser());
        }
        
        @Test
        @DisplayName("default remote user when principal is null")
        void defaultRemoteUserNullPrincipal() {
            when(mockRequest.getRemoteUser()).thenReturn("defaultuser");
            
            SpnegoHttpServletRequest request = new SpnegoHttpServletRequest(mockRequest, null);
            
            assertEquals("defaultuser", request.getRemoteUser());
        }
    }

    @Nested
    @DisplayName("Delegated credential tests")
    class DelegatedCredentialTests {
        
        @Test
        @DisplayName("get delegated credential from principal")
        void getDelegatedCredential() {
            when(mockPrincipal.getDelegatedCredential()).thenReturn(mockCredential);
            
            SpnegoHttpServletRequest request = new SpnegoHttpServletRequest(mockRequest, mockPrincipal);
            
            assertSame(mockCredential, request.getDelegatedCredential());
        }
        
        @Test
        @DisplayName("null delegated credential")
        void nullDelegatedCredential() {
            when(mockPrincipal.getDelegatedCredential()).thenReturn(null);
            
            SpnegoHttpServletRequest request = new SpnegoHttpServletRequest(mockRequest, mockPrincipal);
            
            assertNull(request.getDelegatedCredential());
        }
    }

    @Nested
    @DisplayName("Access control tests")
    class AccessControlTests {
        
        private SpnegoHttpServletRequest requestWithAccessControl;
        private SpnegoHttpServletRequest requestWithoutAccessControl;
        
        @BeforeEach
        void setup() {
            requestWithAccessControl = new SpnegoHttpServletRequest(mockRequest, mockPrincipal, mockAccessControl);
            requestWithoutAccessControl = new SpnegoHttpServletRequest(mockRequest, mockPrincipal);
        }
        
        @Test
        @DisplayName("hasRole with access control")
        void hasRoleWithAccessControl() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.hasRole("testuser", "admin")).thenReturn(true);
            
            assertTrue(requestWithAccessControl.hasRole("admin"));
            verify(mockAccessControl).hasRole("testuser", "admin");
        }
        
        @Test
        @DisplayName("hasRole without access control throws exception")
        void hasRoleWithoutAccessControl() {
            assertThrows(UnsupportedOperationException.class, () -> {
                requestWithoutAccessControl.hasRole("admin");
            });
        }
        
        @Test
        @DisplayName("anyRole with access control")
        void anyRoleWithAccessControl() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.anyRole("testuser", "admin", "user")).thenReturn(true);
            
            assertTrue(requestWithAccessControl.anyRole("admin", "user"));
            verify(mockAccessControl).anyRole("testuser", "admin", "user");
        }
        
        @Test
        @DisplayName("anyRole without access control throws exception")
        void anyRoleWithoutAccessControl() {
            assertThrows(UnsupportedOperationException.class, () -> {
                requestWithoutAccessControl.anyRole("admin", "user");
            });
        }
        
        @Test
        @DisplayName("hasAccess with access control")
        void hasAccessWithAccessControl() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.hasAccess("testuser", "/admin")).thenReturn(true);
            
            assertTrue(requestWithAccessControl.hasAccess("/admin"));
            verify(mockAccessControl).hasAccess("testuser", "/admin");
        }
        
        @Test
        @DisplayName("hasAccess without access control throws exception")
        void hasAccessWithoutAccessControl() {
            assertThrows(UnsupportedOperationException.class, () -> {
                requestWithoutAccessControl.hasAccess("/admin");
            });
        }
        
        @Test
        @DisplayName("anyAccess with access control")
        void anyAccessWithAccessControl() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.anyAccess("testuser", "/admin", "/user")).thenReturn(false);
            
            assertFalse(requestWithAccessControl.anyAccess("/admin", "/user"));
            verify(mockAccessControl).anyAccess("testuser", "/admin", "/user");
        }
        
        @Test
        @DisplayName("anyAccess without access control throws exception")
        void anyAccessWithoutAccessControl() {
            assertThrows(UnsupportedOperationException.class, () -> {
                requestWithoutAccessControl.anyAccess("/admin", "/user");
            });
        }
        
        @Test
        @DisplayName("hasRole with features")
        void hasRoleWithFeatures() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.hasRole("testuser", "featureX", "featureY", "featureZ")).thenReturn(true);
            
            assertTrue(requestWithAccessControl.hasRole("featureX", "featureY", "featureZ"));
            verify(mockAccessControl).hasRole("testuser", "featureX", "featureY", "featureZ");
        }
        
        @Test
        @DisplayName("hasAccess with multiple resources")
        void hasAccessWithMultipleResources() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.hasAccess("testuser", "resourceX", "resourceY")).thenReturn(false);
            
            assertFalse(requestWithAccessControl.hasAccess("resourceX", "resourceY"));
            verify(mockAccessControl).hasAccess("testuser", "resourceX", "resourceY");
        }
        
        @Test
        @DisplayName("isUserInRole delegates to hasRole")
        void isUserInRoleDelegatesToHasRole() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.hasRole("testuser", "manager")).thenReturn(true);
            
            assertTrue(requestWithAccessControl.isUserInRole("manager"));
            verify(mockAccessControl).hasRole("testuser", "manager");
        }
    }

    @Nested
    @DisplayName("User info tests")
    class UserInfoTests {
        
        @Mock
        private UserInfo mockUserInfo;
        
        private SpnegoHttpServletRequest requestWithAccessControl;
        private SpnegoHttpServletRequest requestWithoutAccessControl;
        
        @BeforeEach
        void setup() {
            requestWithAccessControl = new SpnegoHttpServletRequest(mockRequest, mockPrincipal, mockAccessControl);
            requestWithoutAccessControl = new SpnegoHttpServletRequest(mockRequest, mockPrincipal);
        }
        
        @Test
        @DisplayName("getUserInfo with access control")
        void getUserInfoWithAccessControl() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.getUserInfo("testuser")).thenReturn(mockUserInfo);
            
            assertSame(mockUserInfo, requestWithAccessControl.getUserInfo());
            verify(mockAccessControl).getUserInfo("testuser");
        }
        
        @Test
        @DisplayName("getUserInfo without access control throws exception")
        void getUserInfoWithoutAccessControl() {
            assertThrows(UnsupportedOperationException.class, () -> {
                requestWithoutAccessControl.getUserInfo();
            });
        }
        
        @Test
        @DisplayName("getUserInfo returns null throws exception")
        void getUserInfoReturnsNull() {
            when(mockPrincipal.getName()).thenReturn("testuser@EXAMPLE.COM");
            when(mockAccessControl.getUserInfo("testuser")).thenReturn(null);
            
            assertThrows(UnsupportedOperationException.class, () -> {
                requestWithAccessControl.getUserInfo();
            });
        }
    }
}