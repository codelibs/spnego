/** 
 * Copyright (C) 2009 "Darwin V. Felix" <dfelix@users.sourceforge.net>
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

package net.sourceforge.spnego;

import java.security.Principal;

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import net.sourceforge.spnego.SpnegoHttpFilter.Constants;

/**
 * Wrap ServletRequest so we can do our own handling of the 
 * principal and auth types.
 * 
 * @author Darwin V. Felix
 *
 */
final class SpnegoHttpServletRequest extends HttpServletRequestWrapper {
    
    /** Client Principal. */
    private final transient KerberosPrincipal principal;
    
    /**
     * Creates Servlet Request specifying KerberosPrincipal of user.
     * 
     * @param request
     * @param kerberosPrincipal
     */
    SpnegoHttpServletRequest(final HttpServletRequest request
        , final KerberosPrincipal kerberosPrincipal) {
        
        super(request);
        
        this.principal = kerberosPrincipal;
    }
    
    /**
     * Returns "Negotiate" or "Basic" else default auth type.
     * 
     * @see javax.servlet.http.HttpServletRequest#getAuthType()
     */
    @Override
    public String getAuthType() {
        
        final String authType;
        final String header = this.getHeader(Constants.AUTHZ_HEADER);
        
        if (header.startsWith(Constants.NEGOTIATE_HEADER)) {
            authType = Constants.NEGOTIATE_HEADER;
            
        } else if (header.startsWith(Constants.BASIC_HEADER)) {
            authType = Constants.BASIC_HEADER;
            
        } else {
            authType = super.getAuthType();
        }
        
        return authType;
    }
    
    /**
     * Returns authenticated username (sans domain/realm) else default username.
     * 
     * @see javax.servlet.http.HttpServletRequest#getRemoteUser()
     */
    @Override
    public String getRemoteUser() {
        
        if (null == this.principal) {
            return super.getRemoteUser();
            
        } else {
            final String[] username = this.principal.getName().split("@", 2);
            return username[0];
        }
    }
    
    /**
     * Returns KerberosPrincipal of user.
     * 
     * @see javax.servlet.http.HttpServletRequest#getUserPrincipal()
     */
    @Override
    public Principal getUserPrincipal() {
        return this.principal;
    }
}
