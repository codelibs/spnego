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
- `SpnegoFilterConfig` - Filter configuration and initialization
- `SpnegoHttpURLConnection` - HTTP client with SPNEGO support
- `SpnegoSOAPConnection` - SOAP client with SPNEGO support
- `SpnegoHttpServletRequest/Response` - Wrapped servlet request/response
- `SpnegoPrincipal` - Authenticated user principal
- `LdapAccessControl` / `SpnegoAccessControl` / `UserAccessControl` - Authorization
- `Base64` - Base64 encoding/decoding utility

## Code Style

- Java 11 target (configured via `maven-compiler-plugin`)
- Jakarta Servlet API (not javax)
- JUnit 5 + Mockito for tests
- All test classes end with `Test` or `Tests`

## Gotchas

- Servlet API and JAXWS are `provided` scope - not bundled in the JAR
- GPG signing is required for release builds (`maven-gpg-plugin` in verify phase)
- Published to Maven Central via `central-publishing-maven-plugin`
