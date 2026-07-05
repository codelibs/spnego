# SPNEGO

Java library for Integrated Windows Authentication (SPNEGO/Kerberos SSO). Forked from spnego.sourceforge.net.

## Commands

```bash
mvn package              # Build and run tests
mvn test                 # Run tests only
mvn package -DskipTests  # Build without tests
mvn test -Dtest=SpnegoHttpFilterTest  # Run single test class
```

## Architecture

Single-module Maven project under `org.codelibs.spnego`:

- `SpnegoHttpFilter` - Servlet filter for SPNEGO authentication
- `SpnegoAuthenticator` - Core authentication logic
- `SpnegoProvider` - Central factory for GSS credentials/contexts and auth-scheme negotiation
- `SpnegoFilterConfig` - Filter configuration and initialization
- `SpnegoHttpURLConnection` - HTTP client with SPNEGO support
- `SpnegoSOAPConnection` - SOAP client with SPNEGO support
- `SpnegoHttpServletRequest/Response` - Wrapped servlet request/response
- `DelegateServletRequest` - Interface exposing the delegated GSS credential (AD/IE delegation)
- `SpnegoPrincipal` - Authenticated user principal
- `LdapAccessControl` / `SpnegoAccessControl` / `UserAccessControl` - Authorization
- `UserInfo` - User information from the user store
- `SpnegoAuthScheme` - Parsed HTTP auth scheme + token (package-private)
- `Base64` - Base64 encoding/decoding utility

## Code Style

- Java 11 target (configured via `maven-compiler-plugin`)
- Jakarta Servlet API (not javax)
- JUnit 5 + Mockito for tests
- All test classes end with `Test` or `Tests`

## Gotchas

- Servlet API and JAXWS are `provided` scope - not bundled in the JAR
- GPG signing (`maven-gpg-plugin`, `verify` phase) runs only under the `release` profile - source/javadoc jars live there too
- Published to Maven Central via `central-publishing-maven-plugin`
- No `src/main/resources`: JAAS login config, `krb5.conf`, and system properties
  (`java.security.auth.login.config`, `java.security.krb5.conf`,
  `javax.security.auth.useSubjectCredsOnly`) are runtime/deployer-supplied, not bundled
- No `formatter:format` / `license:format` step here (unlike other Fess repos) - don't expect one
