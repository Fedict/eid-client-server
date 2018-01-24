[![Build Status](https://travis-ci.org/Fedict/eid-client-server.svg?branch=develop)](https://travis-ci.org/Fedict/eid-client-server)

# eID Client Server Project

eID Client Server is a set of software components to easily access the Belgian eID from a back-end applicatio nusing a 
supported client on the desktop of the user.  
The codebase is a continuation of the eID Applet project that was deprecated in 2016 when applets became no longer 
supported by the main browsers.
The client - server protocol used by the eID applet has remained, but its client is now deployed on the front-end
using Java Web Start.

The source code of the Commons eID Project is licensed under GNU LGPL v3.0.
It is hosted at https://github.com/Fedict/eid-client-server.
The license conditions can be found in the file: LICENSE.

# Modules

* *eid-client-server-shared*: 
This artifact holds Java classes that are shared between the clients and the server.
This artifact basically defines the protocol that is used between them

* *eid-server-spi*: 
This artifact holds the service provider interfaces (SPIs) that can be used to configure the eID Server.
The configuration of the eID Server directly impacts the behavior of the eID clients.

* *eid-server*:
This artifact holds the eID Server components. 
Embed these in your web application to communicate with a client. 

* *eid-client-core*:
This artifact holds the eID Client core Java classes and is used in the actual clients.

* *eid-client-java-web-start*:
A Java Web Start eID client based on *eid-core*. 
This module adds the bells and whistles to run the eID client as a Java Web Start application.

* *eid-client-java-web-start-signed*:
Signed version of the Java Web Start client.

* *eid-java-web-start-demo*:
Simple demo web application that demonstrates the use of Java Web Start to get identity information, authenticate users
and sign documents.  

# Building

eID Client Server can be build using a standard Maven build. Simply run the following command:
```
mvn clean install
```

## Code Signing

Only signed code can be ran outside of the Java sandbox.
When the project is build, this client component will automatically be signed with a self-signed certificate.

To sign with your own private key and certificate add the `codesigning` profile to the `.m2/settings.xml` file:
```xml
<profiles>
	<profile>
		<id>codesigning</id>
		<properties>
			<keystore.path>ABSOLUTE PATH TO THE KEYSTORE FILE</keystore.path>
			<keystore.type>TYPE OF THE KEYSTORE</keystore.type>
			<keystore.alias>ALIAS OF THE KEY IN THE KEYSTORE</keystore.alias>
			<keystore.password>KEYSTORE_PASSWORD</keystore.password>
		</properties>
	</profile>
</profiles>
```

Make sure you encrypt your keystore password: see https://maven.apache.org/guides/mini/guide-encryption.html.

For example:
```xml
<profiles>
	<profile>
		<id>codesigning</id>
		<properties>
			<keystore.path>/Users/foo/security/mykey.p12</keystore.path>
			<keystore.type>PKCS12</keystore.type>
			<keystore.alias>1</keystore.alias>
			<keystore.password>{f4Av613W9IgHOvNqJWatAdwPXvKwnqqLOqSwWLpHbig=}</keystore.password>
		</properties>
	</profile>
</profiles>
```

Then you can build the project with:
```
mvn clean install -Pcodesigning
```

# Running the Demo

After building all artifacts, you can use the embedded Jetty web server to run a demo. 
Enter the `eid-java-web-start-demo` directory and run: 
```
mvn jetty:run-war
```

Then open your browser at [http://localhost:8080](http://localhost:8080/) or 
[https://localhost:8443](https://localhost:8443/).

# To Do

Although already a significant effort was taken in migrating the existing code base, 
there are still some tasks that could prove useful:
* Further refactoring, modernizing and cleaning up the codebase.
* Reintroduce the signing implementation. 
(It was not migrated since too many APIs have changed since the latest version in eid-applet)

Furthermore some ideas for new functionality:
* The Java Web Start client could generate Json Web Tokens, signed by the authentication certificate on the eID card.
* An additional client could be added that would be installed on the system of the end user and implement an 'eid' 
protocol handler. This would make it much easier to start the client.