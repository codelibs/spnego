package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link UserInfo} using Mockito.
 *
 * The interface itself contains no logic, so the tests focus on the contract
 * expected by consumers: correct handling of valid, invalid and edge inputs
 * and verification of interactions with the mock.
 */
@ExtendWith(MockitoExtension.class)
class UserInfoTest {

    @Mock
    private UserInfo userInfo;

    private static final String VALID_LABEL = "mail";
    private static final String INVALID_LABEL = "nonexistent";
    private static final List<String> MAIL_VALUES = List.of("user@example.com");
    private static final List<String> LABELS = List.of("mail", "displayName");

    @BeforeEach
    void setUp() {
        lenient().when(userInfo.getInfo(VALID_LABEL)).thenReturn(MAIL_VALUES);
        lenient().when(userInfo.getInfo(INVALID_LABEL)).thenReturn(Collections.emptyList());
        lenient().when(userInfo.getInfo("")).thenReturn(Collections.emptyList());
        lenient().when(userInfo.getInfo(null)).thenThrow(NullPointerException.class);

        lenient().when(userInfo.getLabels()).thenReturn(LABELS);

        lenient().when(userInfo.hasInfo(VALID_LABEL)).thenReturn(true);
        lenient().when(userInfo.hasInfo(INVALID_LABEL)).thenReturn(false);
        lenient().when(userInfo.hasInfo("")).thenReturn(false);
        lenient().when(userInfo.hasInfo(null)).thenThrow(NullPointerException.class);
    }

    @Nested
    @DisplayName("getInfo(..) tests")
    class GetInfoTests {

        @Test
        @DisplayName("valid label returns configured list")
        void validLabel() {
            List<String> info = userInfo.getInfo(VALID_LABEL);
            assertEquals(MAIL_VALUES, info);
            verify(userInfo, times(1)).getInfo(VALID_LABEL);
        }

        @Test
        @DisplayName("invalid label returns empty list")
        void invalidLabel() {
            List<String> info = userInfo.getInfo(INVALID_LABEL);
            assertTrue(info.isEmpty());
            verify(userInfo).getInfo(INVALID_LABEL);
        }

        @Test
        @DisplayName("empty label treated as unknown")
        void emptyLabel() {
            List<String> info = userInfo.getInfo("");
            assertTrue(info.isEmpty());
        }

        @Test
        @DisplayName("null label throws NullPointerException")
        void nullLabel() {
            assertThrows(NullPointerException.class, () -> userInfo.getInfo(null));
        }
    }

    @Nested
    @DisplayName("getLabels() tests")
    class GetLabelsTests {
        @Test
        @DisplayName("returns configured label list")
        void returnsLabels() {
            List<String> labels = userInfo.getLabels();
            assertEquals(LABELS, labels);
            verify(userInfo).getLabels();
        }
    }

    @Nested
    @DisplayName("hasInfo(..) tests")
    class HasInfoTests {
        @Test
        @DisplayName("true when info exists for label")
        void trueWhenExists() {
            assertTrue(userInfo.hasInfo(VALID_LABEL));
            verify(userInfo).hasInfo(VALID_LABEL);
        }

        @Test
        @DisplayName("false when info absent for label")
        void falseWhenAbsent() {
            assertFalse(userInfo.hasInfo(INVALID_LABEL));
        }

        @Test
        @DisplayName("false for empty label")
        void falseForEmpty() {
            assertFalse(userInfo.hasInfo(""));
        }

        @Test
        @DisplayName("null label throws NullPointerException")
        void nullLabel() {
            assertThrows(NullPointerException.class, () -> userInfo.hasInfo(null));
        }
    }
}

