/*
 * eID Client - Server Project.
 * Copyright (C) 2018 - 2018 BOSA.
 *
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License version 3.0 as published by
 * the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, see https://www.gnu.org/licenses/.
 */

package be.bosa.eid.server;

import be.bosa.eid.client_server.shared.message.ClientServerProtocolMessageCatalog;
import be.bosa.eid.client_server.shared.message.HelloMessage;
import be.bosa.eid.client_server.shared.message.IdentificationRequestMessage;
import be.bosa.eid.client_server.shared.message.IdentityDataMessage;
import be.bosa.eid.client_server.shared.protocol.Transport;
import be.bosa.eid.client_server.shared.protocol.Unmarshaller;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.jetty.testing.ServletTester;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class EIdServerServletTest {

	private static final Log LOG = LogFactory.getLog(EIdServerServletTest.class);

	private ServletTester servletTester;

	private String location;

	private String sslLocation;

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4), random);
		return keyPairGenerator.generateKeyPair();
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey) throws NoSuchAlgorithmException {
		return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey) throws NoSuchAlgorithmException {
		return new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(publicKey);
	}

	private void persistKey(File pkcs12keyStore, PrivateKey privateKey, X509Certificate certificate,
							char[] keyStorePassword, char[] keyEntryPassword) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, NoSuchProviderException {
		KeyStore keyStore = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
		keyStore.load(null, keyStorePassword);
		LOG.debug("keystore security provider: " + keyStore.getProvider().getName());
		keyStore.setKeyEntry("default", privateKey, keyEntryPassword, new Certificate[]{certificate});
		FileOutputStream keyStoreOut = new FileOutputStream(pkcs12keyStore);
		keyStore.store(keyStoreOut, keyStorePassword);
		keyStoreOut.close();
	}

	private X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn, DateTime notBefore, DateTime notAfter)
			throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException, CertificateException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		String signatureAlgorithm = "SHA1WithRSAEncryption";
		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());
		certificateGenerator.setIssuerDN(new X509Principal(subjectDn));
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128, new SecureRandom()));

		certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(subjectPublicKey));
		certificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(subjectPublicKey));
		certificateGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));

		X509Certificate certificate = certificateGenerator.generate(issuerPrivateKey);
		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
	}

	private static int getFreePort() throws Exception {
		ServerSocket serverSocket = new ServerSocket(0);
		int port = serverSocket.getLocalPort();
		serverSocket.close();
		return port;
	}

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		this.servletTester.addServlet(EidServerServlet.class, "/");

		Security.addProvider(new BouncyCastleProvider());

		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair, "CN=localhost", notBefore, notAfter);
		File tmpP12File = File.createTempFile("ssl-", ".p12");
		LOG.debug("p12 file: " + tmpP12File.getAbsolutePath());
		persistKey(tmpP12File, keyPair.getPrivate(), certificate, "secret".toCharArray(), "secret".toCharArray());

		SslSocketConnector sslSocketConnector = new SslSocketConnector();
		sslSocketConnector.setKeystore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststoreType("pkcs12");
		sslSocketConnector.setKeystoreType("pkcs12");
		sslSocketConnector.setPassword("secret");
		sslSocketConnector.setKeyPassword("secret");
		sslSocketConnector.setTrustPassword("secret");
		sslSocketConnector.setMaxIdleTime(30000);
		int sslPort = getFreePort();
		sslSocketConnector.setPort(sslPort);
		this.servletTester.getContext().getServer().addConnector(sslSocketConnector);
		this.sslLocation = "https://localhost:" + sslPort + "/";

		this.servletTester.start();
		this.location = this.servletTester.createSocketConnector(true);

		SSLContext sslContext = SSLContext.getInstance("TLS");
		TrustManager trustManager = new TestTrustManager(certificate);
		sslContext.init(null, new TrustManager[]{trustManager}, null);
		SSLContext.setDefault(sslContext);
	}

	private static class TestTrustManager implements X509TrustManager {
		private final X509Certificate serverCertificate;

		public TestTrustManager(X509Certificate serverCertificate) {
			this.serverCertificate = serverCertificate;
		}

		public void checkClientTrusted(X509Certificate[] chain, String authnType) throws CertificateException {
			throw new CertificateException("not implemented");
		}

		public void checkServerTrusted(X509Certificate[] chain, String authnType) throws CertificateException {
			if (!this.serverCertificate.equals(chain[0])) {
				throw new CertificateException("server certificate not trusted");
			}
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void get() throws Exception {
		// setup
		LOG.debug("URL: " + this.location);
		HttpClient httpClient = createTrustAllHttpClient();
		HttpGet request = new HttpGet(this.location);

		HttpResponse response = httpClient.execute(request);

		assertEquals(HttpServletResponse.SC_OK, response.getStatusLine().getStatusCode());
		String responseBody = EntityUtils.toString(response.getEntity());
		LOG.debug("Response body: " + responseBody);
		assertTrue(responseBody.indexOf("server service") != 1);
	}

	@Test
	public void doPostRequiresSSL() throws Exception {
		// setup
		LOG.debug("URL: " + this.location);
		HttpClient httpClient = createTrustAllHttpClient();
		HttpPost request = new HttpPost(this.location);

		HttpResponse response = httpClient.execute(request);

		assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, response.getStatusLine().getStatusCode());
	}

	@Test
	@Ignore("Sample identity card has expired")
	public void sslPostIdentityMessage() throws Exception {
		// setup
		byte[] idFile = IOUtils.toByteArray(EIdServerServletTest.class.getResourceAsStream("/id-alice.tlv")); // XXX: expired

		LOG.debug("SSL URL: " + this.sslLocation);
		HttpClient httpClient = createTrustAllHttpClient();

		HelloMessage helloMessage = new HelloMessage();
		HttpPost request1 = new HttpPost(this.sslLocation);
		PostMethodHttpTransmitter httpTransmitter = new PostMethodHttpTransmitter(request1);
		Transport.transfer(helloMessage, httpTransmitter);

		HttpResponse response = httpClient.execute(request1);
		assertEquals(HttpServletResponse.SC_OK, response.getStatusLine().getStatusCode());

		String setCookieValue = response.getFirstHeader("Set-Cookie").getValue();
		int sessionIdIdx = setCookieValue.indexOf("JSESSIONID=") + "JESSSIONID=".length();
		String sessionId = setCookieValue.substring(sessionIdIdx, setCookieValue.indexOf(";", sessionIdIdx));
		LOG.debug("session id: " + sessionId);

		HttpPost request2 = new HttpPost(this.sslLocation);
		request2.addHeader("X-EIdServerProtocol-Version", "1");
		request2.addHeader("X-EIdServerProtocol-Type", "IdentityDataMessage");
		request2.addHeader("X-EIdServerProtocol-IdentityFileSize", Integer.toString(idFile.length));
		request2.setEntity(new ByteArrayEntity(idFile));

		// operate
		HttpResponse response2 = httpClient.execute(request2);

		// verify
		assertEquals(HttpServletResponse.SC_OK, response2.getStatusLine().getStatusCode());

		HttpSession httpSession = this.servletTester.getContext().getSessionHandler().getSessionManager().getHttpSession(sessionId);
		Identity identity = (Identity) httpSession.getAttribute("eid.identity");
		assertNotNull(identity);
		assertEquals("Alice Geldigekaart2266", identity.firstName);

		Address address = (Address) httpSession.getAttribute("eid.address");
		assertNull(address);
	}

	@Test
	@Ignore("Sample identity card has expired")
	public void sslPostIdentityMessageViaTransport() throws Exception {
		// setup
		byte[] idFile = IOUtils.toByteArray(EIdServerServletTest.class.getResourceAsStream("/id-alice.tlv")); // XXX: expired

		LOG.debug("SSL URL: " + this.sslLocation);
		HttpClient httpClient = createTrustAllHttpClient();

		HelloMessage helloMessage = new HelloMessage();
		HttpPost request1 = new HttpPost(this.sslLocation);
		PostMethodHttpTransmitter httpTransmitter = new PostMethodHttpTransmitter(request1);
		Transport.transfer(helloMessage, httpTransmitter);
		HttpResponse response = httpClient.execute(request1);
		assertEquals(HttpServletResponse.SC_OK, response.getStatusLine().getStatusCode());

		String setCookieValue = response.getFirstHeader("Set-Cookie").getValue();
		int sessionIdIdx = setCookieValue.indexOf("JSESSIONID=") + "JSESSIONID=".length();
		String sessionId = setCookieValue.substring(sessionIdIdx, setCookieValue.indexOf(";", sessionIdIdx));
		LOG.debug("session id: " + sessionId);

		HttpPost request2 = new HttpPost(this.sslLocation);
		httpTransmitter = new PostMethodHttpTransmitter(request2);
		IdentityDataMessage identityDataMessage = new IdentityDataMessage();
		identityDataMessage.identityFileSize = idFile.length;
		identityDataMessage.body = idFile;
		Transport.transfer(identityDataMessage, httpTransmitter);

		HttpResponse response2 = httpClient.execute(request2);

		assertEquals(HttpServletResponse.SC_OK, response2.getStatusLine().getStatusCode());

		HttpSession httpSession = this.servletTester.getContext().getSessionHandler().getSessionManager().getHttpSession(sessionId);
		Identity identity = (Identity) httpSession.getAttribute("eid.identity");
		assertNotNull(identity);
		assertEquals("Alice Geldigekaart2266", identity.firstName);

		Address address = (Address) httpSession.getAttribute("eid.address");
		assertNull(address);
	}

	@Test
	public void helloMessage() throws Exception {
		HttpClient httpClient = createTrustAllHttpClient();
		HttpPost request = new HttpPost(this.sslLocation);
		HelloMessage helloMessage = new HelloMessage();
		PostMethodHttpTransmitter httpTransmitter = new PostMethodHttpTransmitter(request);
		Transport.transfer(helloMessage, httpTransmitter);

		// operate
		HttpResponse response = httpClient.execute(request);

		// verify
		assertEquals(HttpServletResponse.SC_OK, response.getStatusLine().getStatusCode());

		Unmarshaller unmarshaller = new Unmarshaller(new ClientServerProtocolMessageCatalog());

		HttpResponseHttpReceiver httpReceiver = new HttpResponseHttpReceiver(response);
		Object resultMessageObject = unmarshaller.receive(httpReceiver);
		assertTrue(resultMessageObject instanceof IdentificationRequestMessage);
	}

	private CloseableHttpClient createTrustAllHttpClient() throws Exception {
		SSLContext sslContext = new SSLContextBuilder()
				.loadTrustMaterial(null, new TrustAllStrategy())
				.build();

		return HttpClients.custom()
				.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
				.setSSLContext(sslContext)
				.build();
	}
}
