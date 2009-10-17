package net.sourceforge.spnego;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import net.sourceforge.spnego.SpnegoHttpFilter.Constants;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;

/**
 * This Class may be used by custom clients as a convenience when connecting 
 * to a protected HTTP server.
 * 
 * <p>
 * This mechanism is an alternative to HTTP Basic Authentication where the 
 * HTTP server does not support Basic Auth but instead has SPNEGO support 
 * (take a look at {@link SpnegoHttpFilter}).
 * </p>
 * 
 * <p>
 * A krb5.conf and a login.conf is required when using this class. Take a 
 * look at the <a href="http://spnego.sourceforge.net" target="_blank">spnego.sourceforge.net</a> 
 * documentation for an example krb5.conf and login.conf file. 
 * Also, you must provide a keytab file OR a username and password.
 * </p>
 * 
 * <p>
 * Example usage (username/password):
 * <pre>
 *     public static void main(final String[] args) throws Exception {
 *         System.setProperty("java.security.krb5.conf", "krb5.conf");
 *         System.setProperty("sun.security.krb5.debug", "true");
 *         System.setProperty("java.security.auth.login.config", "login.conf");
 *         
 *         SpnegoHttpURLConnection spnego = null;
 *         
 *         try {
 *             spnego = new SpnegoHttpURLConnection("spnego-client", "dfelix", "myp@s5");
 *             spnego.connect(new URL("http://medusa:8080/index.jsp"));
 *             
 *             System.out.println(spnego.getResponseCode());
 *         
 *         } finally {
 *             if (null != spnego) {
 *                 spnego.disconnect();
 *             }
 *         }
 *     }
 * </pre>
 * </p>
 * 
 * <p>
 * Alternatively, if the server supports HTTP Basic Authentication, this Class 
 * is NOT needed and instead you can do something like the following:
 * <pre>
 *     public static void main(final String[] args) throws Exception {
 *         final String creds = "dfelix:myp@s5";
 *         
 *         final String token = Base64.encode(creds.getBytes());
 *         
 *         URL url = new URL("http://medusa:8080/index.jsp");
 *         
 *         HttpURLConnection conn = (HttpURLConnection) url.openConnection();
 *         
 *         conn.setRequestProperty(Constants.AUTHZ_HEADER
 *                 , Constants.BASIC_HEADER + " " + token);
 *                 
 *         conn.connect();
 *         
 *         System.out.println("Response Code:" + conn.getResponseCode());
 *     }
 * </pre>
 * </p>
 * 
 * @see SpnegoHttpFilter
 * 
 * @author Darwin V. Felix
 * 
 */
public final class SpnegoHttpURLConnection {

    private static final Logger LOGGER = Logger.getLogger(Constants.LOGGER_NAME);

    /*
     * If false, this connection object has not created a communications link to 
     * the specified URL. If true, the communications link has been established.
     */
    private transient boolean connected = false;

    /*
     * @see java.net.HttpURLConnection#getRequestMethod()
     */
    private transient String requestMethod = "GET";
    
    /*
     * @see java.net.URLConnection#getRequestProperties()
     */
    private final transient Map<String, List<String>> requestProperties = 
        new LinkedHashMap<String, List<String>>();

    /* Login Context for authenticating client. */
    private final transient LoginContext loginContext;

    /* Flag to determine if GSSContext has been established. */
    private transient boolean cntxtEstablished = false;

    /* Ref to HTTP URL Connection object after calling connect method. */
    private transient HttpURLConnection conn = null;

    /**
     * Creates an instance where the LoginContext relies on a keytab 
     * file being specified by "java.security.auth.login.config".
     * 
     * @param loginModuleName 
     * @throws LoginException 
     */
    public SpnegoHttpURLConnection(final String loginModuleName)
        throws LoginException {

        this.loginContext = new LoginContext(loginModuleName);
        this.loginContext.login();
    }

    /**
     * Creates an instance where the LoginContext does not require a keytab
     * file. However, the "java.security.auth.login.config" property must still
     * be set prior to instantiating this object.
     * 
     * @param loginModuleName 
     * @param username 
     * @param password 
     * @throws LoginException 
     */
    public SpnegoHttpURLConnection(final String loginModuleName,
        final String username, final String password) throws LoginException {

        final CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(
                username, password);

        this.loginContext = new LoginContext(loginModuleName, handler);
        this.loginContext.login();
    }

    /*
     * Throws IllegalStateException if this connection object has not yet created 
     * a communications link to the specified URL.
     */
    private void assertConnected() {
        if (!this.connected) {
            throw new IllegalStateException("Not connected");
        }
    }

    /*
     * Throws IllegalStateException if this connection object has already created 
     * a communications link to the specified URL.
     */
    private void assertNotConnected() {
        if (this.connected) {
            throw new IllegalStateException("Already connected");
        }
    }

    /**
     * Opens a communications link to the resource referenced by 
     * this URL, if such a connection has not already been established.
     * 
     * @param url 
     * @return an HttpURLConnection object
     * @throws GSSException 
     * @throws PrivilegedActionException 
     * @throws IOException 
     * @throws LoginException 
     * 
     * @see java.net.URLConnection#connect()
     */
    public HttpURLConnection connect(final URL url)
        throws GSSException, PrivilegedActionException, IOException, LoginException {

        assertNotConnected();

        GSSContext context = null;
        
        try {
            final Subject subject = this.loginContext.getSubject();

            context = SpnegoProvider.getGSSContext(subject, url);
            context.requestMutualAuth(true);
            context.requestConf(true);
            context.requestInteg(true);

            byte[] data = new byte[0];
            data = context.initSecContext(data, 0, data.length);

            this.conn = (HttpURLConnection) url.openConnection();
            this.connected = true;

            final Set<String> keys = this.requestProperties.keySet();
            for (final String key : keys) {
                for (String value : this.requestProperties.get(key)) {
                    this.conn.addRequestProperty(key, value);
                }
            }

            // TODO : re-factor to support (302) redirects
            this.conn.setInstanceFollowRedirects(false);
            this.conn.setRequestMethod(this.requestMethod);

            this.conn.setRequestProperty(Constants.AUTHZ_HEADER
                , Constants.NEGOTIATE_HEADER + ' ' + Base64.encode(data));

            this.conn.connect();

            final SpnegoAuthScheme scheme = SpnegoProvider.getAuthScheme(
                    this.conn.getHeaderField(Constants.AUTHN_HEADER));
            
            // assert
            if (null == scheme) {
                throw new UnsupportedOperationException("Server did not provide"
                        + Constants.AUTHN_HEADER + " header.");
            }

            data = scheme.getToken();

            if (Constants.NEGOTIATE_HEADER.equalsIgnoreCase(scheme.getScheme())) {
                data = context.initSecContext(data, 0, data.length);
            } else {
                throw new UnsupportedOperationException("Scheme NOT Supported: " 
                        + scheme.getScheme());
            }

            this.cntxtEstablished = context.isEstablished();
            
        } finally {
            if (null != context) {
                context.dispose();
                context = null;
            }
            if (null != this.loginContext) {
                this.loginContext.logout();
            }
        }

        return this.conn;
    }

    /**
     * Logout and clear request properties.
     * 
     * @see java.net.HttpURLConnection#disconnect()
     */
    public void disconnect() {
        try {
            this.loginContext.logout();
        } catch (LoginException le) {
            LOGGER.log(Level.WARNING, "logout failed during disconnect", le);
        }
        this.requestProperties.clear();
        this.connected = false;
        this.conn.disconnect();
    }

    /**
     * Returns true if GSSContext has been established.
     * 
     * @return true if GSSContext has been established, false otherwise.
     */
    public boolean iscntxtEstablished() {
        return this.cntxtEstablished;
    }

    /**
     * Internal sanity check to validate not null key/value pairs.
     */
    private void assertKeyValue(final String key, final String value) {
        if (null == key || key.isEmpty()) {
            throw new IllegalArgumentException("key parameter is null or empty");
        }
        if (null == value) {
            throw new IllegalArgumentException("value parameter is null");
        }
    }

    /**
     * Adds an HTTP Request property.
     * 
     * @param key request property name
     * @param value request propery value
     * @see java.net.URLConnection#addRequestProperty(String, String)
     */
    public void addRequestProperty(final String key, final String value) {
        assertNotConnected();
        assertKeyValue(key, value);

        if (this.requestProperties.containsKey(key)) {
            final List<String> val = this.requestProperties.get(key);
            val.add(value);
            this.requestProperties.put(key, val);            
        } else {
            setRequestProperty(key, value);
        }
    }

    /**
     * Sets an HTTP Request property.
     * 
     * @param key request property name
     * @param value request property value
     * @see java.net.URLConnection#setRequestProperty(String, String)
     */
    public void setRequestProperty(final String key, final String value) {
        assertNotConnected();
        assertKeyValue(key, value);

        this.requestProperties.put(key, Arrays.asList(value));
    }

    /**
     * Get header value by header name.
     * 
     * @param name name header
     * @return header value
     * @see java.net.HttpURLConnection#getHeaderField(String)
     */
    public String getHeaderField(final String name) {
        assertConnected();

        return this.conn.getHeaderField(name);
    }

    /**
     * Returns an input stream that reads from this open connection.
     * 
     * @return input stream that reads from this open connection
     * @throws IOException 
     * 
     * @see java.net.HttpURLConnection#getInputStream()
     */
    public InputStream getInputStream() throws IOException {
        assertConnected();

        return this.conn.getInputStream();
    }

    /**
     * Returns HTTP Status code.
     * 
     * @return HTTP Status Code
     * @throws IOException 
     * 
     * @see java.net.HttpURLConnection#getResponseCode()
     */
    public int getResponseCode() throws IOException {
        assertConnected();

        return this.conn.getResponseCode();
    }

    /**
     * Returns HTTP Status message.
     * 
     * @return HTTP Status Message
     * @throws IOException 
     * 
     * @see java.net.HttpURLConnection#getResponseMessage()
     */
    public String getResponseMessage() throws IOException {
        assertConnected();

        return this.conn.getResponseMessage();
    }

    /**
     * May override the default GET method.
     * @param method 
     * 
     * @see java.net.HttpURLConnection#setRequestMethod(String)
     */
    public void setRequestMethod(final String method) {
        assertNotConnected();

        this.requestMethod = method;
    }
}
