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

import java.security.Principal;

import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSCredential;

/**
 * This class encapsulates a KerberosPrincipal.
 * 
 * <p>This class also has a reference to the client's/requester's 
 * delegated credential (if any). See the {@link DelegateServletRequest} 
 * documentation for more details.</p>
 * 
 * <p>Also, see the delegation examples at 
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 * 
 * @author Darwin V. Felix
 *
 */
public final class SpnegoPrincipal implements Principal {

    private final KerberosPrincipal kerberosPrincipal;
    
    private final GSSCredential delegatedCred;
    
    /**
     * Constructs a SpnegoPrincipal from the provided String input.
     * 
     * @param name the principal name
     */
    public SpnegoPrincipal(final String name) {
        this.kerberosPrincipal = new KerberosPrincipal(name);
        this.delegatedCred = null;
    }
    
    /**
     * Constructs a SpnegoPrincipal from the provided String input 
     * and name type input.
     * 
     * @param name the principal name
     * @param nameType the name type of the principal
     */
    public SpnegoPrincipal(final String name, final int nameType) {
        this.kerberosPrincipal = new KerberosPrincipal(name, nameType);
        this.delegatedCred = null;
    }

    /**
     * Constructs a SpnegoPrincipal from the provided String input 
     * and name type input.
     * 
     * @param name the principal name
     * @param nameType the name type of the principal
     * @param delegCred this principal's delegated credential (if any)
     */
    public SpnegoPrincipal(final String name, final int nameType
        , final GSSCredential delegCred) {
        
        this.kerberosPrincipal = new KerberosPrincipal(name, nameType);
        this.delegatedCred = delegCred;
    }
    
    /**
     * Returns this Principal's delegated credential or null.
     * 
     * @return Principal's delegated credential or null.
     */
    public GSSCredential getDelegatedCredential() {
        return this.delegatedCred;
    }
    
    @Override
    public String getName() {
        return this.kerberosPrincipal.getName();
    }
    
    /**
     * Returns the name type of the KerberosPrincipal.
     * 
     * @return name type of the KerberosPrincipal
     */
    public int getNameType() {
        return this.kerberosPrincipal.getNameType();
    }
    
    /**
     * Returns the realm component of this Kerberos principal.
     * 
     * @return realm component of this Kerberos principal
     */
    public String getRealm() {
        return this.kerberosPrincipal.getRealm();
    }
    
    @Override
    public int hashCode() {
        int result = 31;
        result = 31 * result + this.kerberosPrincipal.hashCode();
        result = 31 * result + (this.delegatedCred != null ? this.delegatedCred.hashCode() : 0);
        
        return result;
    }
    
    @Override
    public boolean equals(final Object object) {
        if (object == this) {
            return true;
        }
        
        if (!(object instanceof SpnegoPrincipal)) {
            return false;
        }
        
        final SpnegoPrincipal obj = (SpnegoPrincipal) object;
        if (!this.kerberosPrincipal.equals(obj.kerberosPrincipal)) {
            return false;
        }
        
        if (this.delegatedCred == null) {
            if (obj.delegatedCred != null) {
                return false;
            }
        } else if (!this.delegatedCred.equals(obj.delegatedCred)) {
            return false;
        }
        
        return this.hashCode() == obj.hashCode();
    }
    
    @Override
    public String toString() {
        return this.kerberosPrincipal.toString();
    }
}
