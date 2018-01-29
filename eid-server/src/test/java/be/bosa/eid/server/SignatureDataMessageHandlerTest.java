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

import be.bosa.eid.client_server.shared.message.SignatureDataMessage;
import be.bosa.eid.server.impl.handler.SignatureDataMessageHandler;
import be.bosa.eid.server.spi.AddressDTO;
import be.bosa.eid.server.spi.DigestInfo;
import be.bosa.eid.server.spi.IdentityDTO;
import be.bosa.eid.server.spi.SignatureService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SignatureDataMessageHandlerTest {

	private static final Log LOG = LogFactory.getLog(SignatureDataMessageHandlerTest.class);

	private SignatureDataMessageHandler testedInstance;

	@BeforeClass
	public static void setUpClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Before
	public void setUp() {
		this.testedInstance = new SignatureDataMessageHandler();
		SignatureTestService.reset();
	}

	@Test
	public void testHandleMessage() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = mock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);

		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SignatureService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SignatureServiceClass")).thenReturn(SignatureTestService.class.getName());

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE)).thenReturn(digestValue);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE)).thenReturn("SHA-1");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(document);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EidServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);

		assertEquals(signatureValue, SignatureTestService.getSignatureValue());
	}

	@Test
	public void testHandleMessagePSS() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = mock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);

		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SignatureService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SignatureServiceClass")).thenReturn(SignatureTestService.class.getName());

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE)).thenReturn(digestValue);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE)).thenReturn("SHA-1-PSS");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA1withRSA/PSS", "BC");
		signature.initSign(keyPair.getPrivate());
		signature.update(document);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EidServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);

		assertEquals(signatureValue, SignatureTestService.getSignatureValue());
	}

	@Test
	public void testHandleMessagePSS_SHA256() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = mock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);

		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SignatureService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SignatureServiceClass")).thenReturn(SignatureTestService.class.getName());

		MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE)).thenReturn(digestValue);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE)).thenReturn("SHA-256-PSS");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");
		signature.initSign(keyPair.getPrivate());
		signature.update(document);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EidServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);

		assertEquals(signatureValue, SignatureTestService.getSignatureValue());
	}

	@Test
	public void testHandleMessageWithAudit() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(),
				"CN=Test,SERIALNUMBER=1234", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null);

		ServletConfig mockServletConfig = mock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);

		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(AuditTestService.class.getName());
		when(mockServletConfig.getInitParameter("SignatureService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SignatureServiceClass")).thenReturn(SignatureTestService.class.getName());

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE)).thenReturn(digestValue);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE)).thenReturn("SHA-1");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(document);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EidServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);

		assertEquals(signatureValue, SignatureTestService.getSignatureValue());
		assertEquals("1234", AuditTestService.getAuditSigningUserId());
	}

	@Test
	public void testHandleMessageInvalidSignature() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = mock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);

		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(AuditTestService.class.getName());
		when(mockServletConfig.getInitParameter("SignatureService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SignatureServiceClass")).thenReturn(SignatureTestService.class.getName());

		when(mockServletRequest.getRemoteAddr()).thenReturn("remote-address");

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE)).thenReturn(digestValue);
		when(mockHttpSession.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE)).thenReturn("SHA-1");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update("foobar-document".getBytes());
		message.signatureValue = signature.sign();

		// operate
		EidServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		try {
			this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);
			fail();
		} catch (ServletException e) {
			LOG.debug("expected exception: " + e.getMessage());
			assertNull(SignatureTestService.getSignatureValue());
			assertEquals("remote-address", AuditTestService.getAuditSignatureRemoteAddress());
			assertEquals(certificate, AuditTestService.getAuditSignatureClientCertificate());
		}
	}

	public static class SignatureTestService implements SignatureService {

		private static byte[] signatureValue;

		public static void reset() {
			SignatureTestService.signatureValue = null;
		}

		public static byte[] getSignatureValue() {
			return SignatureTestService.signatureValue;
		}

		public String getFilesDigestAlgorithm() {
			return null;
		}

		public void postSign(String requestId, byte[] signatureValue, List<X509Certificate> signingCertificateChain) {
			SignatureTestService.signatureValue = signatureValue;
		}

		public DigestInfo preSign(String requestId, List<DigestInfo> digestInfos, List<X509Certificate> signingCertificateChain,
								  IdentityDTO identity, AddressDTO address, byte[] photo) {
			return null;
		}
	}
}
