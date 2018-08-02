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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ietf.jgss.GSSException;

/**
 * Http Servlet Filter that provides <a
 * href="http://en.wikipedia.org/wiki/SPNEGO" target="_blank">SPNEGO</a> authentication.
 * It allows servlet containers like Tomcat and JBoss to transparently/silently
 * authenticate HTTP clients like Microsoft Internet Explorer (MSIE).
 * 
 * <p>
 * This feature in MSIE is sometimes referred to as single sign-on and/or 
 * Integrated Windows Authentication. In general, there are at least two 
 * authentication mechanisms that allow an HTTP server and an HTTP client 
 * to achieve single sign-on: <b>NTLM</b> and <b>Kerberos/SPNEGO</b>.
 * </p>
 * 
 * <p>
 * <b>NTLM</b><br>
 * MSIE has the ability to negotiate NTLM password hashes over an HTTP session 
 * using Base 64 encoded NTLMSSP messages. This is a staple feature of Microsoft's 
 * Internet Information Server (IIS). Open source libraries exists (ie. jCIFS) that 
 * provide NTLM-based authentication capabilities to Servlet Containers. jCIFS uses 
 * NTLM and Microsoft's Active Directory (AD) to authenticate MSIE clients.
 * </p>
 * 
 * <p>
 * <b>{@code SpnegoHttpFilter} does NOT support NTLM (tokens).</b>
 * </p>
 * 
 * <p>
 * <b>Kerberos/SPNEGO</b><br>
 * Kerberos is an authentication protocol that is implemented in AD. The protocol 
 * does not negotiate passwords between a client and a server but rather uses tokens 
 * to securely prove/authenticate to one another over an un-secure network.
 * </p>
 * 
 * <p>
 * <b><code>SpnegoHttpFilter</code> does support Kerberos but through the 
 * pseudo-mechanism <code>SPNEGO</code></b>.
 * </p>
 * <ul>
 * <li><a href="http://en.wikipedia.org/wiki/SPNEGO" target="_blank">Wikipedia: SPNEGO</a></li>
 * <li><a href="http://www.ietf.org/rfc/rfc4178.txt" target="_blank">IETF RFC: 4178</a></li>
 * </ul>
 * 
 * <p>
 * <b>Localhost Support</b><br>
 * The Kerberos protocol requires that a service must have a Principal Name (SPN) 
 * specified. However, there are some use-cases where it may not be practical to 
 * specify an SPN (ie. Tomcat running on a developer's machine). The DNS 
 * http://localhost is supported but must be configured in the servlet filter's 
 * init params in the web.xml file. 
 * </p>
 * 
 * <p><b>Modifying the web.xml file</b></p>
 * 
 * <p>Here's an example configuration:</p>
 * 
 * <pre><code>  &lt;filter&gt;
 *      &lt;filter-name&gt;SpnegoHttpFilter&lt;/filter-name&gt;
 *      &lt;filter-class&gt;org.codelibs.spnego.SpnegoHttpFilter&lt;/filter-class&gt;
 *      
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.allow.basic&lt;/param-name&gt;
 *          &lt;param-value&gt;true&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.allow.localhost&lt;/param-name&gt;
 *          &lt;param-value&gt;true&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.allow.unsecure.basic&lt;/param-name&gt;
 *          &lt;param-value&gt;true&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.login.client.module&lt;/param-name&gt;
 *          &lt;param-value&gt;spnego-client&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *      
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.krb5.conf&lt;/param-name&gt;
 *          &lt;param-value&gt;krb5.conf&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.login.conf&lt;/param-name&gt;
 *          &lt;param-value&gt;login.conf&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.preauth.username&lt;/param-name&gt;
 *          &lt;param-value&gt;Zeus&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.preauth.password&lt;/param-name&gt;
 *          &lt;param-value&gt;Zeus_Password&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.login.server.module&lt;/param-name&gt;
 *          &lt;param-value&gt;spnego-server&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.prompt.ntlm&lt;/param-name&gt;
 *          &lt;param-value&gt;true&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *          
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.logger.level&lt;/param-name&gt;
 *          &lt;param-value&gt;1&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *  &lt;/filter&gt;
 *</code></pre>
 * 
 * <p><b>Example usage on web page</b></p>
 * 
 * <pre>  &lt;html&gt;
 *  &lt;head&gt;
 *      &lt;title&gt;Hello SPNEGO Example&lt;/title&gt;
 *  &lt;/head&gt;
 *  &lt;body&gt;
 *  Hello &lt;%= request.getRemoteUser() %&gt; !
 *  &lt;/body&gt;
 *  &lt;/html&gt;
 *  </pre>
 *
 * <p>
 * Take a look at the <a href="http://spnego.sourceforge.net/reference_docs.html" 
 * target="_blank">reference docs</a> for other configuration parameters.
 * </p>
 * 
 * <p>See more usage examples at 
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 * 
 * @author Darwin V. Felix
 * 
 */
public class SpnegoHttpFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(Constants.LOGGER_NAME);

    /** Object for performing Basic and SPNEGO authentication. */
    protected SpnegoAuthenticator authenticator;
    
    /** Object for performing User Authorization. */
    protected UserAccessControl accessControl;
    
    /** AuthZ required for every page. */
    protected String sitewide;
    
    /** Landing page if user is denied authZ access. */
    protected String page403;
    
    /** directories which should not be authenticated irrespective of filter-mapping. */
    protected final List<String> excludeDirs = new ArrayList<>();
    
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        try {
            // set some System properties
            final SpnegoFilterConfig config = SpnegoFilterConfig.getInstance(filterConfig);
            this.excludeDirs.addAll(config.getExcludeDirs());
            
            LOGGER.fine(() -> "excludeDirs=" + this.excludeDirs);
            
            // pre-authenticate
            this.authenticator = new SpnegoAuthenticator(config);
            
            // authorization
            final Properties props = SpnegoHttpFilter.toProperties(filterConfig);
            if (!props.getProperty("spnego.authz.class", "").isEmpty()) {
                props.put("spnego.server.realm", this.authenticator.getServerRealm());
                this.page403 = props.getProperty("spnego.authz.403", "").trim();
                this.sitewide = props.getProperty("spnego.authz.sitewide", "").trim();
                this.sitewide = (this.sitewide.isEmpty()) ? null : this.sitewide;
                this.accessControl = (UserAccessControl) Class.forName(
                        props.getProperty("spnego.authz.class")).newInstance();
                this.accessControl.init(props);                
                LOGGER.fine(() -> "page403=" + this.page403);
                LOGGER.fine(() -> "sitewide=" + this.sitewide);
                LOGGER.fine(() -> "accessControl=" + this.accessControl);
            }
            
        } catch (final LoginException | GSSException | PrivilegedActionException | FileNotFoundException | URISyntaxException
                | InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new ServletException(e);
        }
    }

    @Override
    public void destroy() {
        this.page403 = null;
        this.sitewide = null;
        this.excludeDirs.clear();
        if (null != this.accessControl) {
            this.accessControl.destroy();
            this.accessControl = null;
        }
        if (null != this.authenticator) {
            this.authenticator.dispose();
            this.authenticator = null;
        }
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response
        , final FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
                (HttpServletResponse) response);
        
        // skip authentication if resource is in the list of directories to exclude
        if (exclude(httpRequest.getContextPath(), httpRequest.getServletPath())) {
            chain.doFilter(request, response);
            return;
        }
        
        // client/caller principal
        final SpnegoPrincipal principal;
        try {
            principal = this.authenticator.authenticate(httpRequest, spnegoResponse);
        } catch (GSSException gsse) {
            LOGGER.severe(() -> "HTTP Authorization Header="
                + httpRequest.getHeader(Constants.AUTHZ_HEADER));
            throw new ServletException(gsse);
        }

        // context/auth loop not yet complete
        if (spnegoResponse.isStatusSet()) {
            LOGGER.fine(() -> "Sending response in authentication.");
            return;
        }

        // assert
        if (null == principal) {
            LOGGER.severe(() -> "Principal was null.");
            spnegoResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, true);
            return;
        }

        LOGGER.fine(() -> "principal=" + principal);
        
        final SpnegoHttpServletRequest spnegoRequest = 
                new SpnegoHttpServletRequest(httpRequest, principal, this.accessControl);
                
        // site wide authZ check (if enabled)
        if (!isAuthorized((HttpServletRequest) spnegoRequest)) {
            LOGGER.info(() -> "Principal Not AuthoriZed: " + principal);
            if (this.page403.isEmpty()) {
                spnegoResponse.setStatus(HttpServletResponse.SC_FORBIDDEN, true);  
            } else {
                request.getRequestDispatcher(this.page403).forward(spnegoRequest, response);
            }
            return;            
        }

        processRequest(spnegoRequest, response, chain);
    }

    protected void processRequest(final SpnegoHttpServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        chain.doFilter(request, response);
    }

    private boolean isAuthorized(final HttpServletRequest request) {
        if (null != this.sitewide && null != this.accessControl
                && !this.accessControl.hasAccess(request.getRemoteUser(), this.sitewide)) {
            return false;
        }

        return true;
    }
    
    private boolean exclude(final String contextPath, final String servletPath) {
        // each item in excludeDirs ends with a slash
        final String path = contextPath + servletPath + (servletPath.endsWith("/") ? "" : "/");
        
        for (String dir : this.excludeDirs) {
            if (path.startsWith(dir)) {
                return true;
            }
        }
        
        return false;
    }
    
    private static Properties toProperties(final FilterConfig filterConfig) {
        final Properties props = new Properties();
        final Enumeration<String> it = filterConfig.getInitParameterNames();
        
        while (it.hasMoreElements()) {
            final String key = it.nextElement();
            props.put(key, filterConfig.getInitParameter(key));
        }
        
        return props;
    }
    
    /**
     * Defines constants and parameter names that are used in the  
     * web.xml file, and HTTP request headers, etc.
     * 
     * <p>
     * This class is primarily used internally or by implementers of 
     * custom http clients and by {@link SpnegoFilterConfig}.
     * </p>
     * 
     */
    public static final class Constants {

        private Constants() {
            // default private
        }
        
        /** 
         * Servlet init param name in web.xml <b>spnego.allow.basic</b>.
         * 
         * <p>Set this value to <code>true</code> in web.xml if the filter 
         * should allow Basic Authentication.</p>
         * 
         * <p>It is recommended that you only allow Basic Authentication 
         * if you have clients that cannot perform Kerberos authentication. 
         * Also, you should consider requiring SSL/TLS by setting 
         * <code>spnego.allow.unsecure.basic</code> to <code>false</code>.</p>
         */
        public static final String ALLOW_BASIC = "spnego.allow.basic";

        /**
         * Servlet init param name in web.xml <b>spnego.allow.delegation</b>.
         * 
         * <p>Set this value to <code>true</code> if server should support 
         * credential delegation requests.</p>
         * 
         * <p>Take a look at the {@link DelegateServletRequest} for more 
         * information about other pre-requisites.</p>
         */
        public static final String ALLOW_DELEGATION = "spnego.allow.delegation";
        
        /**
         * Servlet init param name in web.xml <b>spnego.allow.localhost</b>.
         * 
         * <p>Flag to indicate if requests coming from http://localhost 
         * or http://127.0.0.1 should not be authenticated using 
         * Kerberos.</p>
         * 
         * <p>This feature helps to obviate the requirement of 
         * creating an SPN for developer machines.</p>
         * 
         */
        public static final String ALLOW_LOCALHOST = "spnego.allow.localhost";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.allow.unsecure.basic</b>.
         * 
         * <p>Set this value to <code>false</code> in web.xml if the filter 
         * should reject connections that do not use SSL/TLS.</p>
         */
        public static final String ALLOW_UNSEC_BASIC = "spnego.allow.unsecure.basic";
        
        /** 
         * HTTP Response Header <b>WWW-Authenticate</b>. 
         * 
         * <p>The filter will respond with this header with a value of "Basic" 
         * and/or "Negotiate" (based on web.xml file).</p>
         */
        public static final String AUTHN_HEADER = "WWW-Authenticate";
        
        /** 
         * HTTP Request Header <b>Authorization</b>. 
         * 
         * <p>Clients should send this header where the value is the 
         * authentication token(s).</p>
         */
        public static final String AUTHZ_HEADER = "Authorization";
        
        /** 
         * HTTP Response Header <b>Basic</b>. 
         * 
         * <p>The filter will set this as the value for the "WWW-Authenticate" 
         * header if "Basic" auth is allowed (based on web.xml file).</p>
         */
        public static final String BASIC_HEADER = "Basic";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.login.client.module</b>. 
         * 
         * <p>The LoginModule name that exists in the login.conf file.</p>
         */
        public static final String CLIENT_MODULE = "spnego.login.client.module";

        /** 
         * HTTP Request Header <b>Content-Type</b>. 
         * 
         */
        public static final String CONTENT_TYPE = "Content-Type";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.exclude.dirs</b>.
         * 
         * <p>
         * A List of URL paths, starting at the context root, 
         * that should NOT undergo authentication (authN). 
         * </p>
         */
        public static final String EXCLUDE_DIRS = "spnego.exclude.dirs";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.krb5.conf</b>. 
         * 
         * <p>The location of the krb5.conf file. On Windows, this file will 
         * sometimes be named krb5.ini and reside <code>%WINDOWS_ROOT%/krb5.ini</code> 
         * here.</p>
         * 
         * <p>By default, Java looks for the file in these locations and order:
         * </p>
         * <ul>
         * <li>System Property (java.security.krb5.conf)</li>
         * <li>%JAVA_HOME%/lib/security/krb5.conf</li>
         * <li>%WINDOWS_ROOT%/krb5.ini</li>
         * </ul>
         */
        public static final String KRB5_CONF = "spnego.krb5.conf";
        
        /**
         * Specify logging level.

         * <pre>
         * 1 = FINEST
         * 2 = FINER
         * 3 = FINE
         * 4 = CONFIG
         * 5 = INFO
         * 6 = WARNING
         * 7 = SEVERE
         * </pre>
         * 
         */
        public static final String LOGGER_LEVEL = "spnego.logger.level";
        
        /**
         * Name of Spnego Logger.
         * 
         * <p>Example: <code>Logger.getLogger(Constants.LOGGER_NAME)</code></p>
         */
        public static final String LOGGER_NAME = "Spnego"; 
        
        /** 
         * Servlet init param name in web.xml <b>spnego.login.conf</b>. 
         * 
         * <p>The location of the login.conf file.</p>
         */
        public static final String LOGIN_CONF = "spnego.login.conf";
        
        /** 
         * HTTP Response Header <b>Negotiate</b>. 
         * 
         * <p>The filter will set this as the value for the "WWW-Authenticate" 
         * header. Note that the filter may also add another header with 
         * a value of "Basic" (if allowed by the web.xml file).</p>
         */
        public static final String NEGOTIATE_HEADER = "Negotiate";
        
        /**
         * NTLM base64-encoded token start value.
         */
        public static final String NTLM_PROLOG = "TlRMTVNT";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.preauth.password</b>. 
         * 
         * <p>Network Domain password. For Windows, this is sometimes known 
         * as the Windows NT password.</p>
         */
        public static final String PREAUTH_PASSWORD = "spnego.preauth.password";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.preauth.username</b>. 
         * 
         * <p>Network Domain username. For Windows, this is sometimes known 
         * as the Windows NT username.</p>
         */
        public static final String PREAUTH_USERNAME = "spnego.preauth.username";
        
        /**
         * If server receives an NTLM token, the filter will return with a 401 
         * and with Basic as the only option (no Negotiate) <b>spnego.prompt.ntlm</b>. 
         */
        public static final String PROMPT_NTLM = "spnego.prompt.ntlm";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.login.server.module</b>. 
         * 
         * <p>The LoginModule name that exists in the login.conf file.</p>
         */
        public static final String SERVER_MODULE = "spnego.login.server.module";
        
        /** 
         * HTTP Request Header <b>SOAPAction</b>. 
         * 
         */
        public static final String SOAP_ACTION = "SOAPAction";
    }
}
