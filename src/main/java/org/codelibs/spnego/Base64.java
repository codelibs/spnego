/* Encodes and decodes to and from Base64 notation.
 * Copyright (C) 2003 "Eric Glass" <jcifs at samba dot org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.codelibs.spnego;

/**
 * Encodes and decodes data to and from Base64 notation.
 *
 * <p>
 * This class delegates to the JDK {@link java.util.Base64} implementation.
 * Encoding uses the standard (RFC 4648) alphabet without line wrapping and
 * decoding uses the strict basic decoder, which rejects malformed input by
 * throwing {@link IllegalArgumentException}.
 * </p>
 */
public final class Base64 {

    private Base64() {
        // default private
    }

    /**
     * Base-64 encodes the supplied block of data.  Line wrapping is not
     * applied on output.
     *
     * @param bytes The block of data that is to be Base-64 encoded.
     * @return A <code>String</code> containing the encoded data. An empty
     *     input yields an empty <code>String</code>.
     * @throws NullPointerException if <code>bytes</code> is <code>null</code>
     */
    public static String encode(final byte[] bytes) {
        return java.util.Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Decodes the supplied Base-64 encoded string.
     *
     * @param string The Base-64 encoded string that is to be decoded.
     * @return A <code>byte[]</code> containing the decoded data block. An empty
     *     input yields a zero length array.
     * @throws NullPointerException if <code>string</code> is <code>null</code>
     * @throws IllegalArgumentException if <code>string</code> is not in valid
     *     Base-64 notation
     */
    public static byte[] decode(final String string) {
        return java.util.Base64.getDecoder().decode(string);
    }
}
