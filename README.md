# SPNEGO

[![Java CI with Maven](https://github.com/codelibs/spnego/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/spnego/actions/workflows/maven.yml)
[![Maven Central](https://img.shields.io/maven-central/v/org.codelibs/spnego.svg)](https://central.sonatype.com/artifact/org.codelibs/spnego)
[![License: LGPL v3](https://img.shields.io/badge/license-LGPL%20v3-blue.svg)](LICENSE)

Integrated Windows Authentication (Single Sign-On) for Java web applications and HTTP/SOAP clients.

SPNEGO lets a servlet container such as Tomcat or JBoss transparently authenticate HTTP clients
against a Kerberos realm (for example, an Active Directory domain), so that browsers like
Microsoft Edge, Internet Explorer, Firefox, and Chrome can sign in silently using the user's
existing Windows credentials. On the client side, it provides drop-in replacements for
`HttpURLConnection` and `SOAPConnection` that negotiate SPNEGO/Kerberos automatically.

This project is a maintained fork of [spnego.sourceforge.net](http://spnego.sourceforge.net/),
updated to build on modern JDKs and to use the Jakarta Servlet API.

## Features

- Servlet filter (`SpnegoHttpFilter`) that adds SPNEGO single sign-on to any Jakarta Servlet application.
- Kerberos authentication through the SPNEGO pseudo-mechanism (RFC 4178).
- Optional fallback to HTTP Basic authentication, with controls to reject Basic over unsecured connections.
- HTTP client (`SpnegoHttpURLConnection`) and SOAP client (`SpnegoSOAPConnection`) that speak SPNEGO.
- Optional authorization layer, including an LDAP-backed access control implementation.
- Credential delegation support for scenarios that require forwarding the user's Kerberos ticket.

NTLM tokens are intentionally not supported; the library authenticates using Kerberos only.

## Requirements

- Java 11 or later.
- Jakarta Servlet API 6.0 or later (server-side usage). Provided by the servlet container.
- A reachable Kerberos Key Distribution Center (KDC), such as an Active Directory domain controller.
- A Kerberos configuration file (`krb5.conf`) and a JAAS login configuration file (`login.conf`) at runtime.

## Installation

The library is published to Maven Central under the coordinates `org.codelibs:spnego`.

### Maven

```xml
<dependency>
    <groupId>org.codelibs</groupId>
    <artifactId>spnego</artifactId>
    <version>1.2.1</version>
</dependency>
```

### Gradle

```groovy
implementation 'org.codelibs:spnego:1.2.1'
```

The Jakarta Servlet and JAX-WS dependencies are declared with `provided` scope and are expected to be
supplied by your runtime, so they are not bundled in the JAR.

## Usage

### Server side: the servlet filter

Register `org.codelibs.spnego.SpnegoHttpFilter` in your `web.xml` and map it to the paths you want to
protect. The filter reads its configuration from `init-param` entries.

```xml
<filter>
    <filter-name>SpnegoHttpFilter</filter-name>
    <filter-class>org.codelibs.spnego.SpnegoHttpFilter</filter-class>

    <init-param>
        <param-name>spnego.krb5.conf</param-name>
        <param-value>krb5.conf</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.login.conf</param-name>
        <param-value>login.conf</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.login.client.module</param-name>
        <param-value>spnego-client</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.login.server.module</param-name>
        <param-value>spnego-server</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.preauth.username</param-name>
        <param-value>HTTP-service-account</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.preauth.password</param-name>
        <param-value>service-account-password</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.allow.basic</param-name>
        <param-value>true</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.allow.unsecure.basic</param-name>
        <param-value>false</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.prompt.ntlm</param-name>
        <param-value>true</param-value>
    </init-param>
    <init-param>
        <param-name>spnego.allow.localhost</param-name>
        <param-value>true</param-value>
    </init-param>
</filter>

<filter-mapping>
    <filter-name>SpnegoHttpFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

Once a request has been authenticated, the user's name is available through the standard servlet API:

```java
final String user = request.getRemoteUser();
```

Instead of embedding the service account credentials in `web.xml`, you can point the server login
module at a Kerberos keytab file (see `login.conf` below), which is the recommended approach for
production deployments.

### Required runtime files

SPNEGO relies on two configuration files that you supply at runtime. Their locations are passed to
the filter through `spnego.krb5.conf` and `spnego.login.conf`, and the library sets the corresponding
`java.security.krb5.conf` and `java.security.auth.login.config` system properties for you.

`krb5.conf` describes your Kerberos realm and KDC:

```ini
[libdefaults]
    default_realm = EXAMPLE.COM

[realms]
    EXAMPLE.COM = {
        kdc = dc.example.com
        default_domain = example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

`login.conf` is a standard JAAS configuration that defines the client and server login modules. The
module names must match the `spnego.login.client.module` and `spnego.login.server.module` init
parameters:

```
spnego-client {
    com.sun.security.auth.module.Krb5LoginModule required;
};

spnego-server {
    com.sun.security.auth.module.Krb5LoginModule required
    storeKey=true
    isInitiator=false;
};
```

To authenticate the server with a keytab instead of a username and password, configure the server
module accordingly and omit `spnego.preauth.username` / `spnego.preauth.password`:

```
spnego-server {
    com.sun.security.auth.module.Krb5LoginModule required
    isInitiator=false
    storeKey=true
    useKeyTab=true
    keyTab="/etc/krb5.keytab"
    principal="HTTP/host.example.com@EXAMPLE.COM";
};
```

### Client side: HTTP requests

`SpnegoHttpURLConnection` performs SPNEGO negotiation against a protected endpoint and exposes an API
similar to `java.net.HttpURLConnection`.

```java
System.setProperty("java.security.krb5.conf", "krb5.conf");
System.setProperty("java.security.auth.login.config", "login.conf");

SpnegoHttpURLConnection spnego = null;
try {
    spnego = new SpnegoHttpURLConnection("spnego-client", "username", "password");
    spnego.connect(new URL("http://host.example.com:8080/index.jsp"));

    System.out.println(spnego.getResponseCode());
} finally {
    if (spnego != null) {
        spnego.disconnect();
    }
}
```

You can also construct the connection with a login module that reads a keytab, or with a
pre-established `GSSCredential`.

### Client side: SOAP requests

`SpnegoSOAPConnection` extends `jakarta.xml.soap.SOAPConnection`, so it can replace the connection
created by `SOAPConnectionFactory` while adding SPNEGO negotiation.

```java
SpnegoSOAPConnection conn = null;
try {
    conn = new SpnegoSOAPConnection("spnego-client", "username", "password");
    final SOAPMessage response = conn.call(requestMessage, endpoint);
    // process response
} finally {
    if (conn != null) {
        conn.close();
    }
}
```

## Configuration reference

The servlet filter recognizes the following `init-param` values.

| Parameter | Description |
| --- | --- |
| `spnego.krb5.conf` | Location of the Kerberos `krb5.conf` file. Required. |
| `spnego.login.conf` | Location of the JAAS `login.conf` file. Required. |
| `spnego.login.client.module` | Name of the client login module defined in `login.conf`. |
| `spnego.login.server.module` | Name of the server login module defined in `login.conf`. |
| `spnego.preauth.username` | Domain username used for server pre-authentication. Provide this with a password, or use a keytab instead. |
| `spnego.preauth.password` | Password for the pre-authentication username. |
| `spnego.allow.basic` | Set to `true` to allow HTTP Basic authentication as a fallback. Required. |
| `spnego.allow.unsecure.basic` | Set to `false` to reject Basic authentication over non-SSL/TLS connections. Required. |
| `spnego.prompt.ntlm` | Set to `true` to fall back to Basic when an NTLM token is received. Requires `spnego.allow.basic=true`. Required. |
| `spnego.allow.localhost` | Set to `true` to skip Kerberos authentication for requests to `localhost` / `127.0.0.1`, which avoids needing a Service Principal Name during development. |
| `spnego.allow.delegation` | Set to `true` to support Kerberos credential delegation. |
| `spnego.exclude.dirs` | Comma-separated list of URL paths, relative to the context root, that should not be authenticated. |
| `spnego.logger.level` | Logging verbosity from `1` (most verbose) to `7` (least verbose). |

### Authorization

Beyond authentication, the filter can enforce authorization by delegating to an implementation of
`UserAccessControl`. Set `spnego.authz.class` to the fully qualified class name to enable it; the
bundled `org.codelibs.spnego.LdapAccessControl` looks up user attributes and group membership in an
LDAP directory (for example, Active Directory). See the `LdapAccessControl` source for the full set of
`spnego.authz.*` parameters it supports.

## Building from source

```bash
mvn package              # Build and run the tests
mvn test                 # Run the tests only
mvn package -DskipTests  # Build without running the tests
```

The build targets Java 11 and uses JUnit 5 with Mockito for testing.

## Contributing

Bug reports and pull requests are welcome. Please open an
[issue](https://github.com/codelibs/spnego/issues) for questions, problems, or feature requests.

## License

This project is licensed under the GNU Lesser General Public License, version 3 (LGPL-3.0).
See the [LICENSE](LICENSE) file for details.

## Acknowledgements

SPNEGO was originally created by Darwin V. Felix and published at
[spnego.sourceforge.net](http://spnego.sourceforge.net/). This repository continues that work under
the [CodeLibs Project](https://www.codelibs.org/).
