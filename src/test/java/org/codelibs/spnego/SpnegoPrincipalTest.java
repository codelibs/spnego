package org.codelibs.spnego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import javax.security.auth.kerberos.KerberosPrincipal;
import org.ietf.jgss.GSSCredential;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Unit tests for {@link SpnegoPrincipal} covering happy paths, edge cases and
 * interaction with the delegated {@link GSSCredential} using Mockito.
 */
class SpnegoPrincipalTest {

    @Test
    void happyPath_nameOnly() {
        String name = "user@EXAMPLE.COM";
        SpnegoPrincipal sp = new SpnegoPrincipal(name);
        KerberosPrincipal kp = new KerberosPrincipal(name);
        assertEquals(kp.getName(), sp.getName());
        assertEquals(kp.getNameType(), sp.getNameType());
        assertEquals(kp.getRealm(), sp.getRealm());
        assertNull(sp.getDelegatedCredential());
    }

    @Test
    void invalidInput_emptyName() {
        Executable ctor = () -> new SpnegoPrincipal("");
        assertThrows(IllegalArgumentException.class, ctor);
    }

    @Test
    void invalidInput_nullName() {
        Executable ctor = () -> new SpnegoPrincipal(null);
        assertThrows(IllegalArgumentException.class, ctor);
    }

    @Test
    void hashCode_withoutDelegatedCredential() {
        String name = "user@EXAMPLE.COM";
        SpnegoPrincipal sp = new SpnegoPrincipal(name);
        int hashCode = sp.hashCode();
        assertTrue(hashCode != 0);
    }

    @Test
    void happyPath_withDelegatedCredential() {
        String name = "alice@EXAMPLE.COM";
        int nameType = KerberosPrincipal.KRB_NT_PRINCIPAL;
        GSSCredential mockCred = mock(GSSCredential.class);
        SpnegoPrincipal sp = new SpnegoPrincipal(name, nameType, mockCred);
        assertEquals(name, sp.getName());
        assertEquals(nameType, sp.getNameType());
        assertSame(mockCred, sp.getDelegatedCredential());
    }

    @Test
    void equalsAndHashCode_sameDelegatedCredential() {
        String name = "charlie@EXAMPLE.COM";
        int nameType = KerberosPrincipal.KRB_NT_PRINCIPAL;
        GSSCredential mockCred = mock(GSSCredential.class);
        SpnegoPrincipal a = new SpnegoPrincipal(name, nameType, mockCred);
        SpnegoPrincipal b = new SpnegoPrincipal(name, nameType, mockCred);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void equalsAndHashCode_bothNullCredentials() {
        String name = "charlie@EXAMPLE.COM";
        SpnegoPrincipal a = new SpnegoPrincipal(name);
        SpnegoPrincipal b = new SpnegoPrincipal(name);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void notEqual_differentDelegatedCredential() {
        String name = "dave@EXAMPLE.COM";
        int nameType = KerberosPrincipal.KRB_NT_PRINCIPAL;
        GSSCredential cred1 = mock(GSSCredential.class);
        GSSCredential cred2 = mock(GSSCredential.class);
        SpnegoPrincipal a = new SpnegoPrincipal(name, nameType, cred1);
        SpnegoPrincipal b = new SpnegoPrincipal(name, nameType, cred2);
        assertNotEquals(a, b);
    }

    @Test
    void toString_delegates() {
        String name = "eve@EXAMPLE.COM";
        SpnegoPrincipal sp = new SpnegoPrincipal(name);
        assertEquals(new KerberosPrincipal(name).toString(), sp.toString());
    }
}

