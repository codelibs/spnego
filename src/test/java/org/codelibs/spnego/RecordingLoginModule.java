package org.codelibs.spnego;

import java.security.Principal;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * Test {@link LoginModule} that records how often it was logged in and out.
 *
 * <p>
 * A real {@link javax.security.auth.login.LoginContext} drives this module, so
 * tests can assert that production code logged the JAAS context out instead of
 * only asserting that a mock method was invoked. On {@code commit()} the module
 * adds a principal to the {@link Subject}, and on {@code logout()} it removes it
 * again, which makes a leaked (never logged out) {@link Subject} observable.
 * </p>
 *
 * <p>
 * The module is instantiated by JAAS through reflection, so it has to be public
 * and have a public no-arg constructor. State is static because JAAS owns the
 * instance; call {@link #reset()} before each test.
 * </p>
 */
public class RecordingLoginModule implements LoginModule {

    /** Name a test JAAS configuration may register this module under. */
    public static final String MODULE_NAME = "recording-module";

    /** Number of successful login() calls since the last reset. */
    private static int loginCount;

    /** Number of logout() calls since the last reset. */
    private static int logoutCount;

    /** Subject of the most recent initialize() call. */
    private static Subject lastSubject;

    /** Flag making logout() fail, to check that cleanup never hides the real cause. */
    private static boolean logoutFails;

    /** Subject handed to this module instance by JAAS. */
    private Subject subject;

    /** Principal this module instance added on commit(). */
    private Principal principal;

    /**
     * Default constructor. JAAS instantiates this module reflectively.
     */
    public RecordingLoginModule() {
        super();
    }

    /**
     * Clears the recorded counters and the remembered subject.
     */
    public static void reset() {
        loginCount = 0;
        logoutCount = 0;
        lastSubject = null;
        logoutFails = false;
    }

    /**
     * Makes every subsequent logout() throw a {@link LoginException}.
     */
    public static void failOnLogout() {
        logoutFails = true;
    }

    /**
     * Returns the number of successful login() calls since the last reset.
     *
     * @return login count
     */
    public static int getLoginCount() {
        return loginCount;
    }

    /**
     * Returns the number of logout() calls since the last reset.
     *
     * @return logout count
     */
    public static int getLogoutCount() {
        return logoutCount;
    }

    /**
     * Returns the subject of the most recent initialize() call.
     *
     * @return the subject, or null if this module was never initialized
     */
    public static Subject getLastSubject() {
        return lastSubject;
    }

    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map<String, ?> sharedState,
            final Map<String, ?> options) {
        this.subject = subject;
        lastSubject = subject;
    }

    @Override
    public boolean login() throws LoginException {
        loginCount++;
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        this.principal = new NamedPrincipal("HTTP/server@EXAMPLE.COM");
        this.subject.getPrincipals().add(this.principal);
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        logoutCount++;
        if (logoutFails) {
            throw new LoginException("Recording login module was asked to fail on logout.");
        }
        if (null != this.principal) {
            this.subject.getPrincipals().remove(this.principal);
            this.principal = null;
        }
        return true;
    }

    /**
     * Minimal named principal, standing in for the server identity a real
     * Kerberos login module would attach to the subject.
     */
    private static final class NamedPrincipal implements Principal {

        /** Name of this principal. */
        private final String name;

        NamedPrincipal(final String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return this.name;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }
}
