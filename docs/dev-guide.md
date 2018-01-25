# eID Client - Server Developer's Guide

This developer's guide serves as an entry point for integrating eID Clients in your web applications. 
The target audience is web developers and web application architects.

# Introduction

The eID Client - Server project offers an architecture to introduce the eID card in your applications.
It consists of a client component running on the desktop of the end user.
This component provides the communication between the eID card and a component running on the server.

The client typically looks like this: 

![eID Client](images/eid-client-screenshot.png)

Note: This solution is based on the [eID Applet](https://github.com/Fedict/eid-applet) codebase.
The protocol for communication between client and server is therefore similar.
The look-and-feel of the client might also be familiar. 

## Main features

The main features of the eID Client - Server solution are:
* Pretty easy to integrate within an existing web application.
* Integration on the desktop as Java Web Start application.
* Security and privacy of the citizen is protected.
* Interactive eID card handling.
* Support of CCID secure pinpad readers.

## Availability of the code

### Source code
The source code is available at [https://github.com/Fedict/eid-client-server](https://github.com/Fedict/eid-client-server).
This projects uses the commons-eid project to communicate with the eID card.
Its code can be found at [https://github.com/Fedict/commons-eid](https://github.com/Fedict/commons-eid).

### Binary versions
Binary versions can be found at the Belgian eID Maven repository.

Note: when trying to build the code yourself, be aware that Java Web Start applications have to be digitally signed.
Our Maven repository contains a digitally signed version that can be used freely.
To use the Maven repository add the following repository to your `pom.xml` file:
```xml
<repository>
	<id>eid-belgium</id>
	<url>https://maven.eid.belgium.be/</url>
	<releases>
		<enabled>true</enabled>
	</releases>
</repository>
```

The signed Java Web Start client is available as:
```xml
<dependency>
	<groupId>be.bosa.eid-client-server</groupId>
	<artifactId>eid-client-java-web-start-signed</artifactId>
	<version>VERSION</version>
</dependency>
```

The eID service artifact (containing the servlet) is available as:
```xml
<dependency>
	<groupId>be.bosa.eid-client-server</groupId>
	<artifactId>eid-server</artifactId>
	<version>VERSION</version>
</dependency>
```

The eID service provider interface (containing interfaces for implementors to implement) is available as:
```xml
<dependency>
	<groupId>be.bosa.eid-client-server</groupId>
	<artifactId>eid-server-spi</artifactId>
	<version>VERSION</version>
</dependency>
```

## New features and bug fixes

When a new feature is required or when you have discovered a bug, please log an issue in [the GitHub Issue Tracker](https://github.com/Fedict/eid-client-server/issues)
Own contributions are encouraged as well, but please log an issue first so it can be discussed.

## Mac OS X

At the moment using Java Web Start on Mac OS X is very cumbersome at best, so it is not supported right now.
Check [this issue](https://github.com/Fedict/eid-client-server/issues/2) for more context.

# Using the eID Client Server

## The JNLP File

To start Java Web Start from your browser you have to server a JNLP file. 
This file typically looks like this:

```xml
<?xml version="1.0" encoding="utf-8"?>
<jnlp spec="1.7+" codebase="https://server:port/" href="Sample.jnlp">
	<information>
		<title>eID Java Web Start</title>
		<vendor>BOSA</vendor>
		<homepage href="http://server:port/" />
		<description>eID Java Web Start Client</description>
	</information>
	<security>
		<all-permissions/>
	</security>
	<resources>
		<java version="1.8+" />
		<jar href="eid-client-java-web-start-signed.jar" />
	</resources>
	<application-desc name="eID Client" main-class="be.bosa.eid.client.javawebstart.JavaWebStartApplication">
		<argument>--language=nl</argument>
		<argument>--eidServiceUrl=https://localhost:8443/eid-authentication-service</argument>
		<argument>--targetPage=https://localhost:8443/result.jsp</argument>
	</application-desc>
</jnlp>
```

Description:
* `codebase`: an absolute URL. All other URLs are relative to this one.
* `href`: location of the JNLP file on the server. (It is in fact downloaded from there again.)
* `<all-permissions>`: required to grant access to the eID card. Note that this is only allowed for signed Java Web Start applications.
* `<jar>`: location of the (signed) application.
* Arguments:
  * `--eidServiceUrl`: URL for the eID service servlet is running (required).
  * `--language`: the language to show the application in (optional).
  * `--targetPage`: web page that is loaded when the operation is complete (optional).
  * `--cancelPage`: web page that is loaded when the operation is cancelled (optional).
  * `--authorizationErrorPage`: web page that is loaded when an authorization error occurred (optional).
  * `--backgroundColor`: background color of the window (optional).
  * `--foregroundColor`: foreground color of the text (optional).

## The eID Service

The eID client requires a server-side service component to communicate the identity or authentication data from the 
web browser to the server using a secure channel. 
We call this component the eID Service. 
The eID Service Servlet components ease integration of the eID Applet within servlet container Java EE based web applications. 
The eID Service Servlet requires at least a servlet version 3.0 container and a JRE version 1.8. 

The location of this service is passed using the `eidServiceUrl`.

Note: for the moment we only fully support Java EE servlet containers out of the box. 
At the same time this serves as the reference implementation. 

### Protocol description

The protocol consists of 6 steps:

1. During the first step the web browser loads the JNLP file and starts it using Java Web Start. 
2. After the eID Client has been loaded, it initiates a protocol run with the server-side eID Service. 
3. For some eID operations the web developer is required to configure service provider components. 
These service provider components are invoked by the eID Service during a protocol run. 
4. At the end of a protocol run the eID Applet Service calls callbacks specified as service provider components, 
passing information of the user and his card. 
A unique `requestId` is passed as well. 
The same id is used later to identify the correct information.  
5. Finally the eID Client makes the web browser to navigate to the target page. 
6. The target page can now access the eID identity items made available by the eID Service.
To do so it will receive the same requestId as URL parameter.

### Deploying the eID Service

The eID Service Servlet can be deployed via your `web.xml` web deployment descriptor as shown in the following
example:

```xml
<servlet>
	<servlet-name>EidIdentificationServiceServlet</servlet-name>
	<servlet-class>be.bosa.eid.server.EidServiceServlet</servlet-class>
</servlet>
<servlet-mapping>
	<servlet-name>EidIdentificationServiceServlet</servlet-name>
	<url-pattern>/eid-identification-service</url-pattern>
</servlet-mapping>
```

Make sure to add the correct Maven dependency as well:
```xml
<dependency>
	<groupId>be.bosa.eid-client-server</groupId>
	<artifactId>eid-server</artifactId>
	<version>VERSION</version>
</dependency>
```

## Configuring the eID Service

By default the eID Service will operate the eID Client to make it perform an eID identification. 
This is also known as data capture. 
Via this eID operation your web application is capable of reading out the identity data (i.e. name, first name, 
date of birth, address, ...) of the user's eID card.
Additional behaviour can be provided by adding `init-param` parameters to the servlet, either values or call-back services.

Services can be provided in two ways.
Either the *Service* parameter is provided. In that case a JNDI lookup of this name will be done.
Otherwise the *Service*Class parameter has to be provided.
The eID Service will now try to load and instantiate this class.

eID Service parameters
* `IncludeIdentity`: indicates if the identity should be read from the card. (Can be overridden by the `IdentityService`)
* `IncludeAddress`: indicates if the address should be read from the card. (Can be overridden by the `IdentityService`)
* `IncludePhoto`: indicates if the photo should be read from the card. (Can be overridden by the `IdentityService`)
* `IncludeCertificates`: indicates if the certificates should be read from the card. (Can be overridden by the `IdentityService`)
* `RemoveCard`: indicates if the client should wait for the card to be removed at the end. (Can be overridden by the `IdentityService`)
* `Hostname`: indicates if the client should include the hostname of the client.
* `InetAddress`: indicates if the client should include the IP address of the client.
* `ChangePin`: indicates if the user should change his pin.
* `UnblockPin`: indicates if the client should unblock his pin.
* `Logoff`: indicates if a logoff should be sent to the card at the end (which forgets any stored pin).
* `PreLogoff`: indicates if a logoff should be sent to the card at the start (which forgets any stored pin).
* `SessionIdChannelBinding`: indicates if the session id should be included in signed authentication challenges.
* `ChannelBindingServerCertificate`: indicates if the server certificate should be included in signed authentication challenges.
* `RequireSecureReader`: indicates if a secure reader has to be used (e.g. one with a secure PIN pad).
* `NRCIDSecret`, `NRCIDOrgId` and `NRCIDAppId`: when set, the eID Service will not use the National Registry Number as user id, but will 
instead use a HMAC based on these parameters.

eID Service add-on services 
As mentioned above these are retrieved via JNDI or loaded by class.
* `IdentityService`: this service allows for run-time selected of required identity data like address, photo.
* `IdentityConsumerService`: callback service used to pass identity information to your application.
* `AuthenticationService`: when present indicates that an authentication operation should be performed. 
This service should also validate the returned certificate chain.
* `SecureClientEnvironmentService`: this service can be used by the eID Server Service to check the client environment security requirements.
* `IdentityIntegrityService`: this service can be used by the eID Server Service to run integrity validation on the 
identity data that comes from the eID card, for instance validating the certificate chain.
* `SignatureService`: this service is used to implement digital signatures using the eID card.
* `PrivacyService`: this service can return additional privacy information to the client.
* `ChannelBindingService`: this service returns the X509 Certificate used for verification of the secure channel binding.
* `SecureCardReaderService`: this service returns the message to be displayed on the secure PIN pad.
* `AuditService`: this service allows to audit eID Service security-related events..

### Examples

Examples can be found in the `eid-java-web-start-demo` project.

### User identification

To get user information, set the `IncludeIdentity` parameter to `true` and optionally set `IncludeAddress`, `IncludePhoto` 
and `IncludeCertificates` as well.
These values can also be provided by setting an `IdentityService`.

After identification the requested values will be passed to your implementation of the `IdentityConsumerService`.
A request id will be passed as well. 
The same request id is passed to the target page when the operation is complete.

Note: when this code was still used by the eID applet the HTTP session could be used, since it was shared between the 
browser and the applet.
Since the Java Web Start application is running in a different process session sharing is no longer an option.  

### Authentication

Provide an instance of the `AuthenticationService` to authenticate the user.
When present, the eID Client will let the user sign a hash of a secure challenge and a number of other components.
Be sure to implement the validate certificate chain method as well to validate that the certificate is valid.

Note: when the user is authenticated, the `setUserId()` method on the `IdentityConsumerService` will be called with
a user id for the user.
Use the `NRCIDSecret`, `NRCIDOrgId` and `NRCIDAppId` parameter to convert this to a application specific value using a HMAC. 
Otherwise it will contain the National Registry Number of the user.

Note: authentication can be combined with identification.

### Digital signatures

Provide an instance of the `SignatureService`. 
Its `preSign()` method should return the hash of the document to be signed.
The `postSign()` method can then be used to add the calculated signature to the document to be signed.


Spported file digest algorithms are `SHA-1`, `SHA-256`, `SHA-384`, and `SHA-512`.
Supported signature algorithms are: `SHA1-RSA-PKCS1`, `SHA224-RSA-PKCS1`, `SHA256-RSA-PKCS1`, `SHA384-RSA-PKCS1`, 
`SHA512-RSA-PKCS1`, `RIPEMD128-RSA-PKCS1`, `RIPEMD160-RSA-PKCS1`, `RIPEMD256-RSA-PKCS1`, `SHA1-RSA/PSS-PKCS1`, and 
`SHA256-RSA/PSS-PKCS1`.

Please be aware that the eID digital signatures are legally binding by law. 
Don't make the citizen sign digital documents unless it is absolutely necessary from a legal point of view for the 
correct functioning of your business work flow.

Note: signing can be combined with identification.

### Identity Data Integrity
During an eID identification operation the eID Service Service should perform integrity verification on the retrieved eID identity data. 
This feature prevents malicious parties to alter critical identity data.
Provide an instance of the `IdentityIntegrityService` to do so.

### Privacy announcement

The application can define an identity data usage description at runtime by means of a privacy service component. 
To enable this functionality as part of an eID identification operation, you need to implement the `PrivacyService` interface.

### Secure channel binding

Set the `ChannelBindingServerCertificate` parameter with the file to your server's certificate in DER or PEM format to enable 
secure channel binding.
Alternatively provide an implementation of the `ChannelBindingService`.

This certificate will now be included in the hash signed by the authentication key of the user.

Besides server certificate channel binding the eID Applet also supports unique channel binding using the TLS session identifier.
This option can be activated by setting the `SessionIdChannelBinding` init parameter to `true`.

### PKI Validation

The eID Service does not perform any PKI validation. 
So the signature service component, authentication service component and the identity integrity component need to 
implement PKI validation of the citizen certificates itself. 
PKI validation is out of scope of the provided eID Applet Service.

### eID Administration

The eID Client allows for some administrative eID tasks like changing the PIN and unblocking the PIN. 

The eID PIN change administrative task can be executed by setting the `ChangePin` parameter to `true`.
The eID Unblock PIN change administrative task can be executed by setting the `UnblockPin` parameter to `true`.

### Guaranteeing a secure client environment

The eID Client offers functionality to check whether the client environment is secure enough given the application 
requirements. 
In case the eID Applet Service detects an insecure client environment the eID Applet can either show an error message 
and abort the requested eID operation or show a warning message and ask the citizen whether he/she wants to continue 
or not.

To activate this functionality you need to implement the `SecureClientEnviromentService`

### eID Card Removal and logoff

After an eID authentication, eID signature, or eID administration task (i.e. PIN change) the eID card will re-use the 
PIN authorization for future eID authentication operations. 
This feature was originally implemented on the eID JavaCard Applet (which is located inside the eID chip) to allow for 
mutual authenticated SSL without the need to re-enter the PIN on each SSL session renewal. 
Although this makes sense in the context of SSL, it actually makes for a serious eID security weakness: SSO should be 
handled at the IdP level, not at the card level. 
Only an IdP can have notion of trust domains between different web applications. 

Luckily the eID card foresees in an eID card logoff. 
This eID logoff feature can be enabled during both eID authentication or eID signature operations by setting the 
`Logoff` parameter to `true`.
It is strongly advised to enable the eID card logoff feature to prevent abuse of the authentication functionality of the
eID card.

### Auditing

To comply with certain regulations one might need to have an audit trace of the activities performed on the eID Applet 
Service by clients. 
The eID Applet Service offers auditing support by means of the SPI design pattern.
To activate the audit functionality you need to implement the `AuditService` interface.

### Requiring a secure smart card reader

The eID Applet Service can be configured to make the eID Applet to check whether the eID operation that requires the 
user to enter the eID PIN code (in case of authentication or non-repudiation signature, PIN change or PIN unblock) is 
being executed using a CCID secure smart card reader. 
Although this feature could be spoofed it aims to increase the security awareness as required for some applications. 
This feature can be enabled by setting the `RequireSecureReader` init-param to `true`.

Warning: not everybody has a secure pinpad reader.
Before enabling this feature, make sure that your target audience indeed has access to a secure pinpad reader.

### Requiring a secure smart card reader

The eID Applet Service can be configured to make the eID Applet to check whether the eID operation that requires the 
user to enter the eID PIN code (in case of authentication or non-repudiation signature, PIN change or PIN unblock) is 
being executed using a CCID secure smart card reader. 
Although this feature could be spoofed it aims to increase the security awareness as required for some applications. 
This feature can be enabled by setting the `RequireSecureReader` init-param to `true`.

Warning: not everybody has a secure pinpad reader.
Before enabling this feature, make sure that your target audience indeed has access to a secure pinpad reader.
