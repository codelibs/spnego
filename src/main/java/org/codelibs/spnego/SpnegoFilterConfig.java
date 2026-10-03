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

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.codelibs.spnego.SpnegoHttpFilter.Constants;

import jakarta.servlet.FilterConfig;

/**
 * Class that applies/enforces web.xml init params.
 * 
 * <p>These properties are set in the servlet's init params 
 * in the web.xml file.</p>
 * 
 * <p>This class also validates if a keyTab should be used 
 * and if all of the LoginModule options have been set.</p>
 * 
 * <p>
 * To see a working example and instructions on how to use a keytab, take 
 * a look at the <a href="http://spnego.sourceforge.net/server_keytab.html"
 * target="_blank">creating a server keytab</a> example.
 * </p>
 * 
 * <p>The servlet filter uses the class as a Singleton:
 * <code>
 * SpnegoFilterConfig config = SpnegoFilterConfig.getInstance(filter);
 * </code>
 * </p>
 * 
 * <p>An application that applies changed settings without a restart builds 
 * a fresh instance instead, which also reloads the JAAS login configuration and 
 * makes the server login reload the Kerberos configuration:
 * <code>
 * SpnegoFilterConfig config = SpnegoFilterConfig.newInstance(filter);
 * </code>
 * </p>
 * 
 * <p>See an example web.xml configuration in the 
 * <a href="http://spnego.sourceforge.net/spnego_tomcat.html" 
 * target="_blank">installing on tomcat</a> documentation. 
 * </p>
 * 
 * @author Darwin V. Felix
 *
 */
public class SpnegoFilterConfig { // NOPMD
    
    private static final Logger LOGGER = Logger.getLogger(Constants.LOGGER_NAME);
    
    private static final String MISSING_PROPERTY = 
        "Servlet Filter init param(s) in web.xml missing: ";
    
    /** scheme of a login.conf location expressed as a URL instead of a path. */
    private static final String FILE_URI_SCHEME = "file:";
    
    private static SpnegoFilterConfig instance = null;

    /** true if Basic auth should be offered. */
    private boolean allowBasic = false;
    
    /** true if server should support credential delegation requests. */
    private boolean allowDelegation = false;
    
    /** true if request from localhost should not be authenticated
     * (secure default: false; localhost is authenticated unless opted in via web.xml). */
    private boolean allowLocalhost = false;

    /** true if non-ssl for basic auth is allowed
     * (secure default: false; Basic over plain HTTP is disabled unless opted in via web.xml). */
    private boolean allowUnsecure = false;
    
    /** true if all req. login module options set. */
    private boolean canUseKeyTab = false;
    
    /** name of the client login module. */
    private String clientLoginModule = null;
    
    /** url directory path(s) that should NOT undergo authentication. */
    private String excludeDirs = null;
    
    /** password to domain account. */
    private String password = null;
    
    /** true if instead of err on ntlm token, prompt for username/pass. */
    private boolean promptNtlm = false;

    /** name of the server login module. */
    private String serverLoginModule = null;
    
    /** domain account to use for pre-authentication. */
    private String username = null;
    
    /** true if the server login must reload the Kerberos configuration. */
    private boolean refreshKrb5Config = false;
    
    private SpnegoFilterConfig() {
        // default private
    }
    
    /**
     * Use the static getInstance() or newInstance() method.
     * 
     * @param config FilterConfig from servlet's init method
     * @param reload true to reload the JAAS login configuration now and to have 
     *     the server login reload the Kerberos configuration
     */
    private SpnegoFilterConfig(final FilterConfig config, final boolean reload) 
        throws FileNotFoundException, URISyntaxException {

        // specify logging level
        setLogLevel(config.getInitParameter(Constants.LOGGER_LEVEL));
        
        // enforce login.conf presence (fail-secure; not gated on assertions)
        loginConfExists(config.getInitParameter(Constants.LOGIN_CONF));
        
        // specify krb5 conf as a System property
        if (!hasInitParameter(config, Constants.KRB5_CONF)) {
            throw new IllegalArgumentException(
                    SpnegoFilterConfig.MISSING_PROPERTY + Constants.KRB5_CONF);
        } else {
            System.setProperty("java.security.krb5.conf"
                    , config.getInitParameter(Constants.KRB5_CONF));            
        }

        // specify login conf as a System property
        if (!hasInitParameter(config, Constants.LOGIN_CONF)) {
            throw new IllegalArgumentException(
                    SpnegoFilterConfig.MISSING_PROPERTY + Constants.LOGIN_CONF);
        } else {
            System.setProperty("java.security.auth.login.config"
                    , config.getInitParameter(Constants.LOGIN_CONF));            
        }
        
        if (reload) {
            // The JDK parses the login file once and caches the result JVM-wide, so 
            // neither a new location nor a changed file would be seen without this. 
            // refresh() reads java.security.auth.login.config again.
            Configuration.getConfiguration().refresh();
            
            // The Kerberos configuration is cached JVM-wide too, and the only supported 
            // way to reload it is the refreshKrb5Config option of Krb5LoginModule. 
            // The server login sets it (see SpnegoAuthenticator), so it reads 
            // java.security.krb5.conf again when it runs.
            this.refreshKrb5Config = true;
        }
        
        // check if exists and no options specified
        doClientModule(config.getInitParameter(Constants.CLIENT_MODULE));
        
        // determine if all req. met to use keyTab
        doServerModule(config.getInitParameter(Constants.SERVER_MODULE));
        
        // if username/password provided, don't use key tab 
        setUsernamePassword(config.getInitParameter(Constants.PREAUTH_USERNAME)
                , config.getInitParameter(Constants.PREAUTH_PASSWORD));
        
        // determine if we should support Basic Authentication
        setBasicSupport(config.getInitParameter(Constants.ALLOW_BASIC)
                , config.getInitParameter(Constants.ALLOW_UNSEC_BASIC));
        
        // determine if we should Basic Auth prompt if rec. NTLM token
        setNtlmSupport(config.getInitParameter(Constants.PROMPT_NTLM));
        
        // requests from localhost will not be authenticated against the KDC 
        if (hasInitParameter(config, Constants.ALLOW_LOCALHOST)) {
            this.allowLocalhost = 
                Boolean.parseBoolean(config.getInitParameter(Constants.ALLOW_LOCALHOST));
        }
        
        // determine if the server supports credential delegation 
        if (hasInitParameter(config, Constants.ALLOW_DELEGATION)) {
            this.allowDelegation = 
                Boolean.parseBoolean(config.getInitParameter(Constants.ALLOW_DELEGATION));
        }
        
        // determine if a url path(s) should NOT undergo authentication
        this.excludeDirs = config.getInitParameter(Constants.EXCLUDE_DIRS);
    }

    private boolean hasInitParameter(final FilterConfig config, final String value) {
        return null != config.getInitParameter(value) && !config.getInitParameter(value).isEmpty();
    }

    private void doClientModule(final String moduleName) {

        // enforce login module requirements (fail-secure; not gated on assertions)
        moduleExists("client", moduleName);

        this.clientLoginModule = moduleName;
        
        // client must not have any options
        
        // confirm that runtime loaded the login file
        final Configuration config = Configuration.getConfiguration();
 
        // we only expect one entry
        final AppConfigurationEntry entry = config.getAppConfigurationEntry(moduleName)[0];
        
        // get login module options
        final Map<String, ?> opt = entry.getOptions();
        
        // assert
        if (!opt.isEmpty()) {
            for (Map.Entry<String, ?> option : opt.entrySet()) {
                // do not allow client modules to have any options
                // unless they are jboss options
                if (!option.getKey().startsWith("jboss")) {
                    throw new UnsupportedOperationException("Login Module for client must not "
                            + "specify any options: " + opt.size()
                            + "; moduleName=" + moduleName
                            + "; options=" + opt.toString());                    
                }
            }
        }
    }
    
    /**
     * Set the canUseKeyTab flag by determining if all LoginModule options 
     * have been set.
     * 
     * <pre>
     * my-spnego-login-module {
     *      com.sun.security.auth.module.Krb5LoginModule
     *      required
     *      storeKey=true
     *      useKeyTab=true
     *      keyTab="file:///C:/my_path/my_file.keytab"
     *      principal="my_preauth_account";
     * };
     * </pre>
     * 
     * @param moduleName
     */
    private void doServerModule(final String moduleName) {

        // enforce login module requirements (fail-secure; not gated on assertions)
        moduleExists("server", moduleName);

        this.serverLoginModule = moduleName;
        
        // confirm that runtime loaded the login file
        final Configuration config = Configuration.getConfiguration();
 
        // we only expect one entry
        final AppConfigurationEntry entry = config.getAppConfigurationEntry(moduleName)[0];
        
        // get login module options
        final Map<String, ?> opt = entry.getOptions();
        
        // storeKey must be set to true
        if (opt.containsKey("storeKey")) {
            final Object store = opt.get("storeKey");
            if (null == store || !Boolean.parseBoolean((String) store)) {
                throw new UnsupportedOperationException("Login Module for server "
                        + "must have storeKey option in login file set to true.");
            }
        } else {
            throw new UnsupportedOperationException("Login Module for server does "
                    + "not have the storeKey option defined in login file.");
        }
        
        if (opt.containsKey("useKeyTab") 
                && opt.containsKey("principal") 
                && opt.containsKey("keyTab")) {
            
            this.canUseKeyTab = true;
        } else {
            this.canUseKeyTab = false;
        }
    }

    /**
     * Returns true if a client sends an NTLM token and the 
     * filter should ask client for a Basic Auth token instead.
     * 
     * @return true if client should be prompted for Basic Auth
     */
    boolean downgradeNtlm() {
        return this.promptNtlm;
    }
    
    /**
     * Return the value defined in the servlet's init params 
     * in the web.xml file.
     * 
     * @return the name of the login module for the client
     */
    String getClientLoginModule() {
        return this.clientLoginModule;
    }
    
    /**
     * Return the value defined in the servlet's init params 
     * in the web.xml file as a List object.
     * 
     * @return a List of directories to exclude
     */
    List<String> getExcludeDirs() {
        if (null == this.excludeDirs || this.excludeDirs.isEmpty()) {
            return Collections.emptyList();
        } else {
            return SpnegoFilterConfig.split(this.excludeDirs);
        }
    }
    
    /**
     * Return the password to the pre-authentication domain account.
     * 
     * @return password of pre-auth domain account
     */
    String getPreauthPassword() {
        return this.password;
    }
    
    /**
     * Return the name of the pre-authentication domain account.
     * 
     * @return name of pre-auth domain account
     */
    String getPreauthUsername() {
        return this.username;
    }
    
    /**
     * Return the value defined in the servlet's init params 
     * in the web.xml file.
     * 
     * @return the name of the login module for the server
     */
    String getServerLoginModule() {
        return this.serverLoginModule;
    }
    
    /**
     * Returns the instance of the servlet's config parameters.
     * 
     * @param config FilterConfi from servlet's init method
     * @return the instance of that represent the init params
     * @throws FileNotFoundException if login conf file not found
     * @throws URISyntaxException if path to login conf is bad
     */
    public static SpnegoFilterConfig getInstance(final FilterConfig config) 
        throws FileNotFoundException, URISyntaxException {
        
        synchronized (SpnegoFilterConfig.class) {
            if (null == SpnegoFilterConfig.instance) {
                SpnegoFilterConfig.instance = new SpnegoFilterConfig(config, false);
            }
        }

        return SpnegoFilterConfig.instance;
    }

    /**
     * Returns a new instance built from the given config parameters.
     * 
     * <p>
     * Unlike {@link #getInstance(FilterConfig)}, every call parses the given config 
     * and neither reads nor replaces the Singleton, so an application can apply 
     * changed settings by building a new instance and a new {@link SpnegoAuthenticator} 
     * from it. The settings that live outside this object are reloaded as well:
     * </p>
     * 
     * <ul>
     * <li>The JAAS login configuration is refreshed from the given login.conf, so a 
     * new location or a changed file is picked up by this call.</li>
     * <li>The server login of a {@link SpnegoAuthenticator} built from the returned 
     * instance reloads the Kerberos configuration from the given krb5.conf, through 
     * the <code>refreshKrb5Config</code> option of Krb5LoginModule.</li>
     * </ul>
     * 
     * <p>
     * Both configurations, and the <code>java.security.krb5.conf</code> and 
     * <code>java.security.auth.login.config</code> system properties they are read 
     * from, are JVM-wide: the last instance built decides them for every 
     * authenticator in the JVM, including older ones that are still in use.
     * </p>
     * 
     * @param config FilterConfig from servlet's init method
     * @return a new instance that represents the init params
     * @throws FileNotFoundException if login conf file not found
     * @throws URISyntaxException if path to login conf is bad
     */
    public static SpnegoFilterConfig newInstance(final FilterConfig config) 
        throws FileNotFoundException, URISyntaxException {
        
        // the constructor sets and reads JVM-wide state, so do not interleave it
        synchronized (SpnegoFilterConfig.class) {
            return new SpnegoFilterConfig(config, true);
        }
    }

    /**
     * Returns true if Basic Authentication is allowed.
     * 
     * @return true if Basic Auth is allowed
     */
    boolean isBasicAllowed() {
        return this.allowBasic;
    }
    
    /**
     * Returns true if the server should support credential delegation requests.
     * 
     * @return true if server supports credential delegation
     */
    boolean isDelegationAllowed() {
        return this.allowDelegation;
    }
    
    /**
     * Returns true if requests from localhost are allowed.
     * 
     * @return true if requests from localhost are allowed
     */
    boolean isLocalhostAllowed() {
        return this.allowLocalhost;
    }

    /**
     * Returns true if SSL/TLS is required.
     * 
     * @return true if SSL/TLS is required
     */
    boolean isUnsecureAllowed() {
        return this.allowUnsecure;
    }
    
    private boolean loginConfExists(final String loginconf) 
        throws FileNotFoundException {

        // confirm login.conf file exists
        if (null == loginconf || loginconf.isEmpty()) {
            throw new FileNotFoundException("Must provide a login.conf file.");
        } else {
            final File file = toLoginConfFile(loginconf);
            if (!file.exists()) {
                throw new FileNotFoundException(loginconf);
            }
        }

        return true;
    }

    /**
     * Resolves the configured login.conf location to a file.
     * 
     * <p>
     * The same value is handed to the <code>java.security.auth.login.config</code> system 
     * property, which JAAS reads as either a URL or a file system path, so both forms are 
     * accepted here. A plain path is the common case: it is what a servlet container resolves 
     * a packaged resource to, and on Windows it can hold characters that are not legal in a 
     * URI. Only a value that starts with the <code>file:</code> scheme is parsed as a URL, and 
     * even then a value that does not survive parsing falls back to being treated as a path.
     * </p>
     * 
     * @param loginconf location of the login.conf file (not null and not empty)
     * @return the file the location points at
     */
    private static File toLoginConfFile(final String loginconf) {

        if (loginconf.regionMatches(true, 0, FILE_URI_SCHEME, 0, FILE_URI_SCHEME.length())) {
            try {
                final URI uri = new URI(loginconf);
                if (!uri.isOpaque() && null != uri.getPath()) {
                    return new File(uri);
                }
                LOGGER.fine(() -> "login.conf is not a hierarchical file URI"
                        + "; treating it as a path: " + loginconf);
            } catch (URISyntaxException e) {
                LOGGER.fine(() -> "login.conf is not a valid file URI"
                        + "; treating it as a path: " + loginconf);
            }
        }

        return new File(loginconf);
    }
    
    private boolean moduleExists(final String side, final String moduleName) {
        
        // confirm that runtime loaded the login file
        final Configuration config = Configuration.getConfiguration();
 
        // we only expect one entry
        final AppConfigurationEntry[] entry = config.getAppConfigurationEntry(moduleName); 
        
        // confirm that the module name exists in the file
        if (null == entry) {
            throw new IllegalArgumentException("The " + side + " module name " 
                    + "was not found in the login file: " + moduleName);
        }
        
        // confirm that the login module class was defined
        if (0 == entry.length) {
            throw new IllegalArgumentException("The " + side + " module name " 
                    + "exists but login module class not defined: " + moduleName);
        }
        
        // confirm that only one login module class specified
        if (entry.length > 1) {
            throw new IllegalArgumentException("Only one login module class " 
                    + "is supported for the " + side + " module: " + entry.length);
        }
        
        // confirm class name is "com.sun.security.auth.module.Krb5LoginModule"
        if (!entry[0].getLoginModuleName().equals(
                "com.sun.security.auth.module.Krb5LoginModule")) {
            throw new UnsupportedOperationException("Login module class not "
                    + "supported: " + entry[0].getLoginModuleName());
        }
        
        // confirm Control Flag is specified as REQUIRED
        if (!entry[0].getControlFlag().equals(
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED)) {
            throw new UnsupportedOperationException("Control Flag must "
                    + "have a value of REQUIRED: " + entry[0].getControlFlag());
        }
        
        return true;
    }

    /**
     * Specify if Basic authentication is allowed and if un-secure/non-ssl 
     * Basic should be allowed.
     * 
     * @param basic true if basic is allowed
     * @param unsecure true if un-secure basic is allowed
     */
    private void setBasicSupport(final String basic, final String unsecure) {
        if (null == basic) {
            throw new IllegalArgumentException(
                    SpnegoFilterConfig.MISSING_PROPERTY + Constants.ALLOW_BASIC);
        }
        
        if (null == unsecure) {
            throw new IllegalArgumentException(
                    SpnegoFilterConfig.MISSING_PROPERTY + Constants.ALLOW_UNSEC_BASIC);
        }
        
        this.allowBasic = Boolean.parseBoolean(basic);
        this.allowUnsecure = Boolean.parseBoolean(unsecure);
    }

    /**
     * Specify the logging level.
     * 
     * @param level logging level
     */
    private void setLogLevel(final String level) {
        if (null != level) {
            switch (Integer.parseInt(level)) {
                case 1:
                    LOGGER.setLevel(Level.FINEST);
                    break;
                case 2:
                    LOGGER.setLevel(Level.FINER);
                    break;
                case 3:
                    LOGGER.setLevel(Level.FINE);
                    break;
                case 4:
                    LOGGER.setLevel(Level.CONFIG);
                    break;
                case 6:
                    LOGGER.setLevel(Level.WARNING);
                    break;
                case 7:
                    LOGGER.setLevel(Level.SEVERE);
                    break;
                default :
                    LOGGER.setLevel(Level.INFO);
                    break;
            }
        }
    }
    
    /**
     * If request contains NTLM token, specify if a 401 should 
     * be sent back to client with Basic Auth as the only 
     * available authentication scheme.
     * 
     * @param ntlm true/false
     */
    private void setNtlmSupport(final String ntlm) {
        if (null == ntlm) {
            throw new IllegalArgumentException(
                    SpnegoFilterConfig.MISSING_PROPERTY + Constants.PROMPT_NTLM);
        }
        
        final boolean downgradeNtlm = Boolean.parseBoolean(ntlm);
        
        if (!this.allowBasic && downgradeNtlm) {
            throw new IllegalArgumentException("If prompt ntlm is true, then "
                    + "allow basic auth must also be true.");
        }
        
        this.promptNtlm = downgradeNtlm;
    }

    /**
     * Set the username and password if specified in web.xml's init params.
     * 
     * @param usr domain account
     * @param psswrd the password to the domain account
     * @throws IllegalArgumentException if user/pass AND keyTab set
     */
    private void setUsernamePassword(final String usr, final String psswrd) {
        boolean mustUseKtab = false;

        if (null == usr) {
            this.username = "";
        } else {
            this.username = usr;
        }
        
        if (null == psswrd) {
            this.password = "";
        } else {
            this.password = psswrd;
        }
        
        if (this.username.isEmpty() || this.password.isEmpty()) {
            mustUseKtab = true;
        }

        if (mustUseKtab && !this.canUseKeyTab) {
            throw new IllegalArgumentException("Must specify a username "
                    + "and password or a keyTab.");            
        }
    }
    
    /**
     * Returns true if the server login should reload the Kerberos configuration.
     * 
     * @return true if this instance was created by newInstance()
     */
    boolean refreshKrb5Config() {
        return this.refreshKrb5Config;
    }

    /**
     * Returns true if LoginContext should use keyTab.
     * 
     * @return true if LoginContext should use keyTab.
     */
    boolean useKeyTab() {
        return this.canUseKeyTab && this.username.isEmpty() && this.password.isEmpty();
    }

    private static String clean(final String path) {
        
        // assert - more than one char (we do not support ROOT) and no wild card
        if (path.length() < 2 || path.contains("*")) {
            throw new IllegalArgumentException(
                "Invalid exclude.dirs pattern or char(s): " + path);
        }
        
        // ensure that it ends with the slash character
        final String tmp;
        if (path.endsWith("/")) {
            tmp = path;
        } else {
            tmp = path + "/";
        }
        
        // we want to include the slash character
        return tmp.substring(0, tmp.lastIndexOf('/') + 1);
    }
    
    private static List<String> split(final String dirs) {
        final List<String> list = new ArrayList<>();
        
        for (String dir : dirs.split(",")) {
            list.add(SpnegoFilterConfig.clean(dir.trim()));
        }
        
        return list;
    }
    
    @Override
    public String toString() {
        final StringBuilder buff = new StringBuilder(100);
        
        buff.append("allowBasic=" + this.allowBasic
                + "; allowUnsecure=" + this.allowUnsecure
                + "; allowDelegation=" + this.allowDelegation
                + "; allowLocalhost=" + this.allowLocalhost
                + "; canUseKeyTab=" + this.canUseKeyTab
                + "; excludeDirs=" + this.excludeDirs
                + "; username=" + this.username
                + "; clientLoginModule=" + this.clientLoginModule
                + "; serverLoginModule=" + this.serverLoginModule);
        
        return buff.toString();
    }
}
