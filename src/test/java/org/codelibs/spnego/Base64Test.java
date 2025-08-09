package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link Base64} utility class.
 */
class Base64Test {

    @Nested
    @DisplayName("encode() tests")
    class EncodeTests {
        
        @Test
        @DisplayName("empty byte array returns empty string")
        void emptyByteArray() {
            byte[] input = new byte[0];
            String result = Base64.encode(input);
            assertEquals("", result);
        }
        
        @Test
        @DisplayName("single byte encoding")
        void singleByte() {
            byte[] input = {65}; // 'A'
            String result = Base64.encode(input);
            assertEquals("QQ==", result);
        }
        
        @Test
        @DisplayName("two bytes encoding")
        void twoBytes() {
            byte[] input = {65, 66}; // 'AB'
            String result = Base64.encode(input);
            assertEquals("QUI=", result);
        }
        
        @Test
        @DisplayName("three bytes encoding (no padding)")
        void threeBytes() {
            byte[] input = {65, 66, 67}; // 'ABC'
            String result = Base64.encode(input);
            assertEquals("QUJD", result);
        }
        
        @Test
        @DisplayName("simple text encoding")
        void simpleText() {
            byte[] input = "Hello World".getBytes(StandardCharsets.UTF_8);
            String result = Base64.encode(input);
            assertEquals("SGVsbG8gV29ybGQ=", result);
        }
        
        @Test
        @DisplayName("longer text encoding")
        void longerText() {
            byte[] input = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
            String result = Base64.encode(input);
            assertEquals("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==", result);
        }
        
        @Test
        @DisplayName("binary data encoding")
        void binaryData() {
            byte[] input = {-1, -2, -3, 0, 1, 2, 3};
            String result = Base64.encode(input);
            String decoded = new String(Base64.decode(result), StandardCharsets.ISO_8859_1);
            // Verify round-trip works
            assertArrayEquals(input, Base64.decode(result));
        }
    }

    @Nested
    @DisplayName("decode() tests")
    class DecodeTests {
        
        @Test
        @DisplayName("empty string returns empty byte array")
        void emptyString() {
            byte[] result = Base64.decode("");
            assertEquals(0, result.length);
        }
        
        @Test
        @DisplayName("single byte decoding with padding")
        void singleByteWithPadding() {
            byte[] result = Base64.decode("QQ==");
            assertArrayEquals(new byte[]{65}, result);
        }
        
        @Test
        @DisplayName("two bytes decoding with padding")
        void twoBytesWithPadding() {
            byte[] result = Base64.decode("QUI=");
            assertArrayEquals(new byte[]{65, 66}, result);
        }
        
        @Test
        @DisplayName("three bytes decoding without padding")
        void threeBytesNoPadding() {
            byte[] result = Base64.decode("QUJD");
            assertArrayEquals(new byte[]{65, 66, 67}, result);
        }
        
        @Test
        @DisplayName("simple text decoding")
        void simpleTextDecoding() {
            byte[] result = Base64.decode("SGVsbG8gV29ybGQ=");
            String decoded = new String(result, StandardCharsets.UTF_8);
            assertEquals("Hello World", decoded);
        }
        
        @Test
        @DisplayName("longer text decoding")
        void longerTextDecoding() {
            byte[] result = Base64.decode("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");
            String decoded = new String(result, StandardCharsets.UTF_8);
            assertEquals("The quick brown fox jumps over the lazy dog", decoded);
        }
    }

    @Nested
    @DisplayName("round-trip tests")
    class RoundTripTests {
        
        @Test
        @DisplayName("encode then decode returns original")
        void encodeDecodeRoundTrip() {
            byte[] original = "Test message for round-trip verification".getBytes(StandardCharsets.UTF_8);
            String encoded = Base64.encode(original);
            byte[] decoded = Base64.decode(encoded);
            assertArrayEquals(original, decoded);
        }
        
        @Test
        @DisplayName("various byte values round-trip")
        void variousBytes() {
            byte[] original = new byte[256];
            for (int i = 0; i < 256; i++) {
                original[i] = (byte) (i - 128);
            }
            String encoded = Base64.encode(original);
            byte[] decoded = Base64.decode(encoded);
            assertArrayEquals(original, decoded);
        }
        
        @Test
        @DisplayName("edge case lengths round-trip")
        void edgeCaseLengths() {
            // Test various lengths that result in different padding scenarios
            for (int length = 1; length <= 10; length++) {
                byte[] original = new byte[length];
                for (int i = 0; i < length; i++) {
                    original[i] = (byte) (i + 65);
                }
                String encoded = Base64.encode(original);
                byte[] decoded = Base64.decode(encoded);
                assertArrayEquals(original, decoded, "Failed for length " + length);
            }
        }
    }
}