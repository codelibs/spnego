package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

/**
 * Test class for LdapAccessControl
 */
class LdapAccessControlTest {

    private LdapAccessControl ldapAccessControl;
    private Properties testProps;
    
    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() {
        ldapAccessControl = new LdapAccessControl();
        testProps = createTestProperties();
    }

    @AfterEach
    void tearDown() {
        if (ldapAccessControl != null) {
            try {
                ldapAccessControl.destroy();
            } catch (Exception e) {
                // Ignore cleanup errors
            }
        }
    }

    private Properties createTestProperties() {
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.url", "ldap://test.local:389");
        props.setProperty("spnego.authz.ldap.username", "testuser");
        props.setProperty("spnego.authz.ldap.password", "testpass");
        props.setProperty("spnego.server.realm", "TEST.LOCAL");
        props.setProperty("spnego.authz.ldap.filter.1", "(&(sAMAccountName=%1$s)(memberOf=CN=%2$s,DC=test,DC=local))");
        props.setProperty("spnego.authz.resource.name.1", "admin-resource");
        props.setProperty("spnego.authz.resource.access.1", "Admin,Manager");
        props.setProperty("spnego.authz.resource.type.1", "has");
        props.setProperty("spnego.authz.ttl", "10");
        props.setProperty("spnego.authz.unique", "true");
        return props;
    }

    // Test initialization and configuration
    
    @Test
    void testInitWithValidProperties() {
        assertDoesNotThrow(() -> ldapAccessControl.init(testProps));
    }

    @Test
    void testInitWithMissingLdapUrl() {
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.username", "testuser");
        props.setProperty("spnego.authz.ldap.password", "testpass");
        props.setProperty("spnego.server.realm", "TEST.LOCAL");
        props.setProperty("spnego.authz.ldap.filter.1", "(&(sAMAccountName=%1$s))");
        
        assertThrows(IllegalStateException.class, () -> ldapAccessControl.init(props));
    }

    @Test
    void testInitWithMissingUsername() {
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.url", "ldap://test.local:389");
        props.setProperty("spnego.authz.ldap.password", "testpass");
        props.setProperty("spnego.server.realm", "TEST.LOCAL");
        props.setProperty("spnego.authz.ldap.filter.1", "(&(sAMAccountName=%1$s))");
        
        assertThrows(IllegalArgumentException.class, () -> ldapAccessControl.init(props));
    }

    @Test
    void testInitWithMissingPassword() {
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.url", "ldap://test.local:389");
        props.setProperty("spnego.authz.ldap.username", "testuser");
        props.setProperty("spnego.server.realm", "TEST.LOCAL");
        props.setProperty("spnego.authz.ldap.filter.1", "(&(sAMAccountName=%1$s))");
        
        assertThrows(IllegalArgumentException.class, () -> ldapAccessControl.init(props));
    }

    @Test
    void testInitWithMissingFilter() {
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.url", "ldap://test.local:389");
        props.setProperty("spnego.authz.ldap.username", "testuser");
        props.setProperty("spnego.authz.ldap.password", "testpass");
        props.setProperty("spnego.server.realm", "TEST.LOCAL");
        
        assertThrows(IllegalStateException.class, () -> ldapAccessControl.init(props));
    }

    @Test
    void testInitWithPolicyFile() throws IOException {
        File policyFile = new File(tempDir, "test.policy");
        try (FileWriter writer = new FileWriter(policyFile)) {
            writer.write("spnego.authz.ldap.filter.1=(&(sAMAccountName=%1$s))\n");
            writer.write("spnego.authz.resource.name.1=test-resource\n");
            writer.write("spnego.authz.resource.access.1=TestRole\n");
            writer.write("spnego.authz.resource.type.1=any\n");
        }
        
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.url", "ldap://test.local:389");
        props.setProperty("spnego.authz.ldap.username", "testuser");
        props.setProperty("spnego.authz.ldap.password", "testpass");
        props.setProperty("spnego.authz.policy.file", policyFile.getAbsolutePath());
        props.setProperty("spnego.server.realm", "TEST.LOCAL");
        
        assertDoesNotThrow(() -> ldapAccessControl.init(props));
    }

    @Test
    void testInitWithInvalidPolicyFile() {
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.url", "ldap://test.local:389");
        props.setProperty("spnego.authz.ldap.username", "testuser");
        props.setProperty("spnego.authz.ldap.password", "testpass");
        props.setProperty("spnego.authz.policy.file", "/nonexistent/file.policy");
        props.setProperty("spnego.server.realm", "TEST.LOCAL");
        
        assertThrows(IllegalArgumentException.class, () -> ldapAccessControl.init(props));
    }

    @Test
    void testDoubleInit() {
        ldapAccessControl.init(testProps);
        assertThrows(IllegalStateException.class, () -> ldapAccessControl.init(testProps));
    }

    @Test
    void testDestroy() {
        ldapAccessControl.init(testProps);
        assertDoesNotThrow(() -> ldapAccessControl.destroy());
    }

    // Test role-based access control

    @Test
    void testHasRole() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.hasRole("testuser", "Admin");
            assertTrue(result);
        }
    }

    @Test
    void testHasRoleNotFound() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(false);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.hasRole("testuser", "NonExistentRole");
            assertFalse(result);
        }
    }

    @Test
    void testHasRoleWithCache() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            // First call - should query LDAP
            boolean result1 = ldapAccessControl.hasRole("testuser", "Admin");
            assertTrue(result1);
            
            // Second call - should use cache
            boolean result2 = ldapAccessControl.hasRole("testuser", "Admin");
            assertTrue(result2);
            
            // Verify LDAP was only queried once
            assertEquals(1, mockedContext.constructed().size());
        }
    }

    @Test
    void testHasRoleWithNamingException() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    when(mock.search(anyString(), anyString(), any(SearchControls.class)))
                        .thenThrow(new NamingException("LDAP error"));
                })) {
            
            assertThrows(IllegalStateException.class, () -> ldapAccessControl.hasRole("testuser", "Admin"));
        }
    }

    @Test
    void testHasRoleWithMultipleAttributes() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.hasRole("testuser", "Admin", "Manager", "User");
            assertTrue(result);
        }
    }

    @Test
    void testHasRoleWithEmptyAttributeArray() {
        ldapAccessControl.init(testProps);
        String[] emptyArray = new String[0];
        assertThrows(IllegalArgumentException.class, 
            () -> ldapAccessControl.hasRole("testuser", "Admin", emptyArray));
    }

    @Test
    void testAnyRole() throws NamingException {
        ldapAccessControl.init(testProps);
        
        int[] callCount = {0};
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    // First context call returns false (NonExistent role), second returns true (Admin role)
                    if (callCount[0]++ == 0) {
                        when(results.hasMoreElements()).thenReturn(false);
                    } else {
                        when(results.hasMoreElements()).thenReturn(true);
                    }
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.anyRole("testuser", "NonExistent", "Admin");
            assertTrue(result);
        }
    }

    @Test
    void testAnyRoleAllFalse() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(false);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.anyRole("testuser", "Role1", "Role2", "Role3");
            assertFalse(result);
        }
    }

    // Test resource-based access control

    @Test
    void testHasAccess() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.hasAccess("testuser", "admin-resource");
            assertTrue(result);
        }
    }

    @Test
    void testHasAccessResourceNotFound() {
        ldapAccessControl.init(testProps);
        assertThrows(IllegalArgumentException.class, 
            () -> ldapAccessControl.hasAccess("testuser", "nonexistent-resource"));
    }

    @Test
    void testHasAccessWithAnyType() throws NamingException {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.resource.type.1", "any");
        ldapAccessControl.init(props);
        
        int[] callCount = {0};
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    // First context call returns false (Admin role), second returns true (Manager role)
                    if (callCount[0]++ == 0) {
                        when(results.hasMoreElements()).thenReturn(false);
                    } else {
                        when(results.hasMoreElements()).thenReturn(true);
                    }
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.hasAccess("testuser", "admin-resource");
            assertTrue(result);
        }
    }

    @Test
    void testHasAccessWithCache() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            // First call - should query LDAP
            boolean result1 = ldapAccessControl.hasAccess("testuser", "admin-resource");
            assertTrue(result1);
            
            // Second call - should use cache
            boolean result2 = ldapAccessControl.hasAccess("testuser", "admin-resource");
            assertTrue(result2);
        }
    }

    @Test
    void testHasAccessWithMultipleResources() throws NamingException {
        ldapAccessControl.init(testProps);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            // Add second resource for testing
            Properties props = createTestProperties();
            props.setProperty("spnego.authz.resource.name.2", "user-resource");
            props.setProperty("spnego.authz.resource.access.2", "User");
            props.setProperty("spnego.authz.resource.type.2", "has");
            ldapAccessControl.destroy();
            ldapAccessControl.init(props);
            
            boolean result = ldapAccessControl.hasAccess("testuser", "admin-resource", "user-resource");
            assertTrue(result);
        }
    }

    @Test
    void testHasAccessWithEmptyResourceArray() {
        ldapAccessControl.init(testProps);
        String[] emptyArray = new String[0];
        assertThrows(IllegalArgumentException.class, 
            () -> ldapAccessControl.hasAccess("testuser", "admin-resource", emptyArray));
    }

    @Test
    void testAnyAccess() throws NamingException {
        // Create a simpler scenario where first resource fails but second succeeds
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.resource.type.1", "any"); // Change to "any" type so it tries multiple roles
        props.setProperty("spnego.authz.resource.name.2", "user-resource");
        props.setProperty("spnego.authz.resource.access.2", "User");
        props.setProperty("spnego.authz.resource.type.2", "has");
        ldapAccessControl.init(props);
        
        int[] callCount = {0};
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    // First two contexts fail (Admin, Manager for admin-resource "any" check)
                    // Third context succeeds (User for user-resource)
                    when(results.hasMoreElements()).thenReturn(callCount[0]++ == 2);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.anyAccess("testuser", "admin-resource", "user-resource");
            assertTrue(result);
        }
    }

    // Test getUserInfo functionality

    @Test
    void testGetUserInfo() throws NamingException {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.user.info", "mail,department,displayName");
        props.setProperty("spnego.authz.ldap.user.filter", "(&(sAMAccountName=%1$s))");
        ldapAccessControl.init(props);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    // Mock search results
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    SearchResult searchResult = mock(SearchResult.class);
                    Attributes attributes = mock(Attributes.class);
                    NamingEnumeration attrEnum = mock(NamingEnumeration.class);
                    
                    // Setup mail attribute
                    Attribute mailAttr = mock(Attribute.class);
                    when(mailAttr.getID()).thenReturn("mail");
                    NamingEnumeration mailValues = mock(NamingEnumeration.class);
                    when(mailValues.hasMore()).thenReturn(true, false);
                    when(mailValues.next()).thenReturn("user@test.com");
                    when(mailAttr.getAll()).thenReturn(mailValues);
                    
                    // Setup department attribute
                    Attribute deptAttr = mock(Attribute.class);
                    when(deptAttr.getID()).thenReturn("department");
                    NamingEnumeration deptValues = mock(NamingEnumeration.class);
                    when(deptValues.hasMore()).thenReturn(true, false);
                    when(deptValues.next()).thenReturn("IT");
                    when(deptAttr.getAll()).thenReturn(deptValues);
                    
                    // Wire up the mocks
                    when(results.hasMoreElements()).thenReturn(true, false);
                    when(results.nextElement()).thenReturn(searchResult);
                    when(searchResult.getAttributes()).thenReturn(attributes);
                    when(attributes.getAll()).thenReturn(attrEnum);
                    when(attrEnum.hasMore()).thenReturn(true, true, false);
                    when(attrEnum.next()).thenReturn(mailAttr, deptAttr);
                    
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            UserInfo userInfo = ldapAccessControl.getUserInfo("testuser");
            assertNotNull(userInfo);
            assertTrue(userInfo.hasInfo("mail"));
            assertTrue(userInfo.hasInfo("department"));
            assertEquals("user@test.com", userInfo.getInfo("mail").get(0));
            assertEquals("IT", userInfo.getInfo("department").get(0));
        }
    }

    @Test
    void testGetUserInfoNotFound() throws NamingException {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.user.info", "mail");
        props.setProperty("spnego.authz.ldap.user.filter", "(&(sAMAccountName=%1$s))");
        ldapAccessControl.init(props);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(false);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            assertThrows(IllegalArgumentException.class, () -> ldapAccessControl.getUserInfo("testuser"));
        }
    }

    @Test
    void testGetUserInfoWithNamingException() throws NamingException {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.user.info", "mail");
        props.setProperty("spnego.authz.ldap.user.filter", "(&(sAMAccountName=%1$s))");
        ldapAccessControl.init(props);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    when(mock.search(anyString(), anyString(), any(SearchControls.class)))
                        .thenThrow(new NamingException("LDAP error"));
                })) {
            
            assertThrows(IllegalStateException.class, () -> ldapAccessControl.getUserInfo("testuser"));
        }
    }

    @Test
    void testGetUserInfoNoFilter() {
        ldapAccessControl.init(testProps);
        UserInfo userInfo = ldapAccessControl.getUserInfo("testuser");
        assertNull(userInfo);
    }

    // Test edge cases and error conditions

    @Test
    void testUniquePropertyViolation() throws NamingException {
        // Add a second filter to test uniqueness across multiple filters
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.ldap.filter.2", "(&(sAMAccountName=%1$s)(memberOf=CN=%2$s,DC=test2,DC=local))");
        ldapAccessControl.init(props);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    // Both filters return true for the same role - violates uniqueness
                    NamingEnumeration<SearchResult> results1 = mock(NamingEnumeration.class);
                    NamingEnumeration<SearchResult> results2 = mock(NamingEnumeration.class);
                    when(results1.hasMoreElements()).thenReturn(true);
                    when(results2.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class)))
                        .thenReturn(results1)
                        .thenReturn(results2);
                })) {
            
            assertThrows(IllegalArgumentException.class, () -> ldapAccessControl.hasRole("testuser", "DuplicateRole"));
        }
    }

    @Test
    void testNonUniqueMode() throws NamingException {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.unique", "false");
        ldapAccessControl.init(props);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.hasRole("testuser", "Admin");
            assertTrue(result);
        }
    }

    @Test
    void testInvalidResourceType() {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.resource.type.1", "invalid");
        ldapAccessControl.init(props);
        
        assertThrows(UnsupportedOperationException.class, 
            () -> ldapAccessControl.hasAccess("testuser", "admin-resource"));
    }

    @Test
    void testEmptyResourceAccess() {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.resource.access.1", "");
        ldapAccessControl.init(props);
        
        assertThrows(IllegalStateException.class, 
            () -> ldapAccessControl.hasAccess("testuser", "admin-resource"));
    }

    @Test
    void testMaxFiltersExceeded() {
        Properties props = createTestProperties();
        // Add more than 200 filters
        for (int i = 1; i <= 201; i++) {
            props.setProperty("spnego.authz.ldap.filter." + i, "(&(sAMAccountName=%1$s))");
        }
        
        assertThrows(IllegalArgumentException.class, () -> ldapAccessControl.init(props));
    }

    @Test
    void testMaxResourcesExceeded() {
        Properties props = createTestProperties();
        // Add more than 200 resources
        for (int i = 1; i <= 201; i++) {
            props.setProperty("spnego.authz.resource.name." + i, "resource" + i);
            props.setProperty("spnego.authz.resource.access." + i, "Role" + i);
            props.setProperty("spnego.authz.resource.type." + i, "has");
        }
        
        assertThrows(IllegalArgumentException.class, () -> ldapAccessControl.init(props));
    }

    @Test
    void testTTLConfiguration() {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.ttl", "5");
        assertDoesNotThrow(() -> ldapAccessControl.init(props));
    }

    @Test
    void testNegativeTTL() {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.ttl", "-1");
        assertDoesNotThrow(() -> ldapAccessControl.init(props));
        // Should use default TTL
    }

    @Test
    void testLdapPoolConfiguration() {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.ldap.pool", "false");
        assertDoesNotThrow(() -> ldapAccessControl.init(props));
    }

    @Test
    void testCustomLdapFactory() {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.ldap.factory", "custom.ldap.Factory");
        assertDoesNotThrow(() -> ldapAccessControl.init(props));
    }

    @Test
    void testAuthenticationMethod() {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.ldap.authn", "DIGEST-MD5");
        assertDoesNotThrow(() -> ldapAccessControl.init(props));
    }

    @Test
    void testKrb5Credentials() {
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.url", "ldap://test.local:389");
        props.setProperty("spnego.preauth.username", "krbuser");
        props.setProperty("spnego.preauth.password", "krbpass");
        props.setProperty("spnego.server.realm", "TEST.LOCAL");
        props.setProperty("spnego.authz.ldap.filter.1", "(&(sAMAccountName=%1$s))");
        
        assertDoesNotThrow(() -> ldapAccessControl.init(props));
    }

    @Test
    void testMissingDeeceeWithoutRealm() {
        Properties props = new Properties();
        props.setProperty("spnego.authz.ldap.url", "ldap://test.local:389");
        props.setProperty("spnego.authz.ldap.username", "testuser");
        props.setProperty("spnego.authz.ldap.password", "testpass");
        props.setProperty("spnego.authz.ldap.filter.1", "(&(sAMAccountName=%1$s))");
        
        assertThrows(IllegalArgumentException.class, () -> ldapAccessControl.init(props));
    }

    @Test
    void testCustomDeecee() {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.ldap.deecee", "DC=custom,DC=domain");
        assertDoesNotThrow(() -> ldapAccessControl.init(props));
    }

    @Test
    void testMultipleFilters() throws NamingException {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.ldap.filter.2", "(&(sAMAccountName=%1$s)(department=%2$s))");
        ldapAccessControl.init(props);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(false, true); // First filter fails, second succeeds
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.hasRole("testuser", "Admin");
            assertTrue(result);
        }
    }

    @Test
    void testResourceWithMultipleRoles() throws NamingException {
        Properties props = createTestProperties();
        props.setProperty("spnego.authz.resource.access.1", "Role1,Role2,Role3");
        ldapAccessControl.init(props);
        
        try (MockedConstruction<InitialLdapContext> mockedContext = mockConstruction(InitialLdapContext.class,
                (mock, context) -> {
                    NamingEnumeration<SearchResult> results = mock(NamingEnumeration.class);
                    when(results.hasMoreElements()).thenReturn(true);
                    when(mock.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            
            boolean result = ldapAccessControl.hasAccess("testuser", "admin-resource");
            assertTrue(result);
        }
    }
}