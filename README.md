[![Build Status](https://travis-ci.org/Fedict/eid-client-server.svg?branch=develop)](https://travis-ci.org/Fedict/eid-client-server)

# eID Client Server Overview

eID Client Server is a set of software components to easily access the Belgian eID in a back-end using a supported
client on the desktop of the user.  
The codebase is a continuation of the eID Applet project that was deprecated in 2016 when applets became no longer 
supported by the main browsers.
The client - server protocol used by the eID applet has remained, but its client is now deployed on the front-end
using Java Web Start.

The source code of the Commons eID Project is licensed under GNU LGPL v3.0.
The license conditions can be found in the file: LICENSE.

# Modules

* *eid-client-server-shared*: 
This artifact holds Java classes that are shared between the clients and the server.
This artifact basically defines the protocol used between them.

* *eid-server-spi*: 
This artifact holds the service provider interfaces (SPIs) that can be used to configure the eID Server.
The configuration of the eID Server directly impacts the behavior of the eID clients.

* *eid-server*:
This artifact holds the eID Server components. 
Embed these in your web application to communicate with a client. 

* *eid-client-core*:
This artifact holds the eID Client core Java classes and is used in the actual clients.

# Building

eID Client Server can be build using a standard Maven build. Simply run the following command:
```
mvn clean install
```

## Code signing

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

# Running the demo

After building all artifacts, you can use the embedded Jetty web server to run a demo. 
Enter the `eid-java-web-start-demo` directory and run: 
```
mvn jetty:run-war
```

Then open your browser at [http://localhost:8080](http://localhost:8080/) or 
[https://localhost:8443](https://localhost:8443/).