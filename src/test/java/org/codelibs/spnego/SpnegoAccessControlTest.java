package org.codelibs.spnego;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test class for SpnegoAccessControl interface.
 * Tests all interface methods with various scenarios and edge cases.
 */
class SpnegoAccessControlTest {

    @Mock
    private UserInfo mockUserInfo;

    private SpnegoAccessControl accessControl;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        
        // Create a test implementation of SpnegoAccessControl
        accessControl = new TestSpnegoAccessControl(mockUserInfo);
    }

    @Nested
    @DisplayName("anyRole method tests")
    class AnyRoleTests {

        @Test
        @DisplayName("Should return true when user has at least one matching attribute")
        void testAnyRole_WithMatchingAttribute() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer", "IT"));
            
            // When
            boolean result = accessControl.anyRole("Developer", "Manager", "Analyst");
            
            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should return false when user has no matching attributes")
        void testAnyRole_WithNoMatchingAttribute() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer", "IT"));
            
            // When
            boolean result = accessControl.anyRole("Manager", "Analyst", "HR");
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should return false with empty attributes array")
        void testAnyRole_WithEmptyArray() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer"));
            
            // When
            boolean result = accessControl.anyRole();
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle null attributes gracefully")
        void testAnyRole_WithNullAttribute() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer"));
            
            // When
            boolean result = accessControl.anyRole((String[]) null);
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should return true when user has multiple matching attributes")
        void testAnyRole_WithMultipleMatches() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer", "Manager", "IT"));
            
            // When
            boolean result = accessControl.anyRole("Developer", "Manager", "Analyst");
            
            // Then
            assertTrue(result);
        }
    }

    @Nested
    @DisplayName("hasRole(String) method tests")
    class HasRoleSingleTests {

        @Test
        @DisplayName("Should return true when user has the specified attribute")
        void testHasRole_WithMatchingAttribute() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer", "IT"));
            
            // When
            boolean result = accessControl.hasRole("Developer");
            
            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should return false when user does not have the specified attribute")
        void testHasRole_WithNoMatchingAttribute() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer", "IT"));
            
            // When
            boolean result = accessControl.hasRole("Manager");
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle null attribute gracefully")
        void testHasRole_WithNullAttribute() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer"));
            
            // When
            boolean result = accessControl.hasRole(null);
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle empty string attribute")
        void testHasRole_WithEmptyAttribute() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Developer", ""));
            
            // When
            boolean result = accessControl.hasRole("");
            
            // Then
            assertTrue(result);
        }
    }

    @Nested
    @DisplayName("hasRole(String, String...) method tests")
    class HasRoleMultipleTests {

        @Test
        @DisplayName("Should return true when user has X and at least one Y attribute")
        void testHasRole_WithXAndY() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Los Angeles", "Developer", "IT"));
            
            // When
            boolean result = accessControl.hasRole("Los Angeles", "Developer", "Manager");
            
            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should return false when user has X but none of Y attributes")
        void testHasRole_WithXButNoY() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Los Angeles", "Analyst"));
            
            // When
            boolean result = accessControl.hasRole("Los Angeles", "Developer", "Manager");
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should return false when user does not have X attribute")
        void testHasRole_WithoutX() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("New York", "Developer"));
            
            // When
            boolean result = accessControl.hasRole("Los Angeles", "Developer", "Manager");
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle empty Y attributes array")
        void testHasRole_WithEmptyYArray() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Los Angeles"));
            
            // When - calling with empty varargs
            boolean result = accessControl.hasRole("Los Angeles", new String[0]);
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle null Y attributes")
        void testHasRole_WithNullYAttributes() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserRoles(Arrays.asList("Los Angeles"));
            
            // When
            boolean result = accessControl.hasRole("Los Angeles", (String[]) null);
            
            // Then
            assertFalse(result);
        }
    }

    @Nested
    @DisplayName("anyAccess method tests")
    class AnyAccessTests {

        @Test
        @DisplayName("Should return true when user has access to at least one resource")
        void testAnyAccess_WithMatchingResource() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("admin-links", "finance-buttons"));
            
            // When
            boolean result = accessControl.anyAccess("admin-links", "ops-buttons");
            
            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should return false when user has no access to any resource")
        void testAnyAccess_WithNoMatchingResource() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("user-links"));
            
            // When
            boolean result = accessControl.anyAccess("admin-links", "ops-buttons");
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle empty resources array")
        void testAnyAccess_WithEmptyArray() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("admin-links"));
            
            // When
            boolean result = accessControl.anyAccess();
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle null resources")
        void testAnyAccess_WithNullResources() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("admin-links"));
            
            // When
            boolean result = accessControl.anyAccess((String[]) null);
            
            // Then
            assertFalse(result);
        }
    }

    @Nested
    @DisplayName("hasAccess(String) method tests")
    class HasAccessSingleTests {

        @Test
        @DisplayName("Should return true when user has access to the resource")
        void testHasAccess_WithMatchingResource() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("finance-links", "admin-buttons"));
            
            // When
            boolean result = accessControl.hasAccess("finance-links");
            
            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should return false when user does not have access to the resource")
        void testHasAccess_WithNoMatchingResource() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("user-links"));
            
            // When
            boolean result = accessControl.hasAccess("admin-links");
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle null resource")
        void testHasAccess_WithNullResource() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("admin-links"));
            
            // When
            boolean result = accessControl.hasAccess(null);
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle empty string resource")
        void testHasAccess_WithEmptyResource() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("admin-links", ""));
            
            // When
            boolean result = accessControl.hasAccess("");
            
            // Then
            assertTrue(result);
        }
    }

    @Nested
    @DisplayName("hasAccess(String, String...) method tests")
    class HasAccessMultipleTests {

        @Test
        @DisplayName("Should return true when user has X and at least one Y resource")
        void testHasAccess_WithXAndY() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("finance-links", "admin-links"));
            
            // When
            boolean result = accessControl.hasAccess("finance-links", "admin-links", "accounting-buttons");
            
            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should return false when user has X but none of Y resources")
        void testHasAccess_WithXButNoY() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("finance-links", "user-buttons"));
            
            // When
            boolean result = accessControl.hasAccess("finance-links", "admin-links", "accounting-buttons");
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should return false when user does not have X resource")
        void testHasAccess_WithoutX() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("user-links", "admin-links"));
            
            // When
            boolean result = accessControl.hasAccess("finance-links", "admin-links", "accounting-buttons");
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle empty Y resources array")
        void testHasAccess_WithEmptyYArray() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("finance-links"));
            
            // When - calling with empty varargs
            boolean result = accessControl.hasAccess("finance-links", new String[0]);
            
            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle null Y resources")
        void testHasAccess_WithNullYResources() {
            // Given
            TestSpnegoAccessControl testControl = (TestSpnegoAccessControl) accessControl;
            testControl.setUserResources(Arrays.asList("finance-links"));
            
            // When
            boolean result = accessControl.hasAccess("finance-links", (String[]) null);
            
            // Then
            assertFalse(result);
        }
    }

    @Nested
    @DisplayName("getUserInfo method tests")
    class GetUserInfoTests {

        @Test
        @DisplayName("Should return the UserInfo object")
        void testGetUserInfo() {
            // When
            UserInfo result = accessControl.getUserInfo();
            
            // Then
            assertNotNull(result);
            assertEquals(mockUserInfo, result);
        }

        @Test
        @DisplayName("Should return null when UserInfo is not set")
        void testGetUserInfo_WhenNull() {
            // Given
            SpnegoAccessControl nullUserInfoControl = new TestSpnegoAccessControl(null);
            
            // When
            UserInfo result = nullUserInfoControl.getUserInfo();
            
            // Then
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("Integration tests with UserInfo")
    class IntegrationTests {

        @Test
        @DisplayName("Should integrate with UserInfo to check attributes")
        void testIntegrationWithUserInfo() {
            // Given
            when(mockUserInfo.hasInfo("memberOf")).thenReturn(true);
            when(mockUserInfo.getInfo("memberOf")).thenReturn(
                Arrays.asList("CN=Developers,DC=example,DC=com", "CN=IT,DC=example,DC=com")
            );
            when(mockUserInfo.getLabels()).thenReturn(Arrays.asList("memberOf", "mail", "displayName"));
            
            // When
            UserInfo userInfo = accessControl.getUserInfo();
            
            // Then
            assertTrue(userInfo.hasInfo("memberOf"));
            assertEquals(2, userInfo.getInfo("memberOf").size());
            assertEquals(3, userInfo.getLabels().size());
            
            // Verify mock interactions
            verify(mockUserInfo).hasInfo("memberOf");
            verify(mockUserInfo).getInfo("memberOf");
            verify(mockUserInfo).getLabels();
        }

        @Test
        @DisplayName("Should handle empty UserInfo labels")
        void testIntegrationWithEmptyUserInfo() {
            // Given
            when(mockUserInfo.hasInfo(anyString())).thenReturn(false);
            when(mockUserInfo.getInfo(anyString())).thenReturn(Collections.emptyList());
            when(mockUserInfo.getLabels()).thenReturn(Collections.emptyList());
            
            // When
            UserInfo userInfo = accessControl.getUserInfo();
            
            // Then
            assertFalse(userInfo.hasInfo("anyLabel"));
            assertTrue(userInfo.getInfo("anyLabel").isEmpty());
            assertTrue(userInfo.getLabels().isEmpty());
        }
    }

    /**
     * Test implementation of SpnegoAccessControl interface for testing purposes.
     * This implementation allows setting user roles and resources for testing various scenarios.
     */
    private static class TestSpnegoAccessControl implements SpnegoAccessControl {
        
        private final UserInfo userInfo;
        private List<String> userRoles = Collections.emptyList();
        private List<String> userResources = Collections.emptyList();
        
        public TestSpnegoAccessControl(UserInfo userInfo) {
            this.userInfo = userInfo;
        }
        
        public void setUserRoles(List<String> roles) {
            this.userRoles = roles != null ? roles : Collections.emptyList();
        }
        
        public void setUserResources(List<String> resources) {
            this.userResources = resources != null ? resources : Collections.emptyList();
        }
        
        @Override
        public boolean anyRole(String... attributes) {
            if (attributes == null || attributes.length == 0) {
                return false;
            }
            for (String attribute : attributes) {
                if (attribute != null && userRoles.contains(attribute)) {
                    return true;
                }
            }
            return false;
        }
        
        @Override
        public boolean hasRole(String attribute) {
            return attribute != null && userRoles.contains(attribute);
        }
        
        @Override
        public boolean hasRole(String attributeX, String... attributeYs) {
            if (!hasRole(attributeX)) {
                return false;
            }
            if (attributeYs == null || attributeYs.length == 0) {
                return false;
            }
            for (String attributeY : attributeYs) {
                if (hasRole(attributeY)) {
                    return true;
                }
            }
            return false;
        }
        
        @Override
        public boolean anyAccess(String... resources) {
            if (resources == null || resources.length == 0) {
                return false;
            }
            for (String resource : resources) {
                if (resource != null && userResources.contains(resource)) {
                    return true;
                }
            }
            return false;
        }
        
        @Override
        public boolean hasAccess(String resource) {
            return resource != null && userResources.contains(resource);
        }
        
        @Override
        public boolean hasAccess(String resourceX, String... resourceYs) {
            if (!hasAccess(resourceX)) {
                return false;
            }
            if (resourceYs == null || resourceYs.length == 0) {
                return false;
            }
            for (String resourceY : resourceYs) {
                if (hasAccess(resourceY)) {
                    return true;
                }
            }
            return false;
        }
        
        @Override
        public UserInfo getUserInfo() {
            return userInfo;
        }
    }
}