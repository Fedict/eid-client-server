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

import be.bosa.eid.client_server.shared.message.AuthenticationContract;
import be.bosa.eid.client_server.shared.message.AuthenticationDataMessage;
import be.bosa.eid.server.impl.AuthenticationChallenge;
import be.bosa.eid.server.impl.UserIdentifierUtil;
import be.bosa.eid.server.impl.handler.AuthenticationDataMessageHandler;
import be.bosa.eid.server.impl.handler.HelloMessageHandler;
import be.bosa.eid.server.impl.handler.IdentityDataMessageHandler;
import be.bosa.eid.server.spi.AuthenticationService;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthenticationDataMessageHandlerTest {

	private static final String NRCID_SECRET = "112233445566778899AABBCCDDEEFF00112233445566778899";
	private static final String EID_IDENTIFIER = "eid.identifier";
	private static final String NRCID_APP_ID = "my-app-id";
	private static final String NRCID_ORG_ID = "my-org-id";
	private static final String REMOTE_ADDRESS = "1.2.3.4";
	private static final byte[] SALT = "salt".getBytes();
	private static final byte[] SESSION_ID = "session-id".getBytes();

	private AuthenticationDataMessageHandler testedInstance;

	@Before
	public void setUp() {
		this.testedInstance = new AuthenticationDataMessageHandler();
		AuthenticationTestService.reset();
		AuditTestService.reset();
	}

	@Test
	public void testHandleMessage() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(), "CN=Test, SERIALNUMBER=" + userId,
				notBefore, notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);
		ServletConfig mockServletConfig = mock(ServletConfig.class);

		byte[] challenge = AuthenticationChallenge.generateChallenge(testHttpSession);

		AuthenticationContract authenticationContract = new AuthenticationContract(salt, null, null, sessionId, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		message.signatureValue = signature.sign();

		
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuthenticationTestService.class.getName());
		when(mockServletConfig.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuditTestService.class.getName());
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE + "Class")).thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);

		when(mockServletRequest.getAttribute("javax.servlet.request.ssl_session")).thenReturn(new String(Hex.encodeHex(sessionId)));
		when(mockServletRequest.getRemoteAddr()).thenReturn("1.2.3.4");

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, testHttpSession);

		assertTrue(AuthenticationTestService.isCalled());
		assertEquals(userId, AuditTestService.getAuditUserId());
		assertEquals(userId, testHttpSession.getAttribute(EID_IDENTIFIER));
	}

	@Test
	public void testHandleMessageNRCID() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(),
				"CN=Test, SERIALNUMBER=" + userId, notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);
		ServletConfig mockServletConfig = mock(ServletConfig.class);

		byte[] challenge = AuthenticationChallenge.generateChallenge(testHttpSession);

		AuthenticationContract authenticationContract = new AuthenticationContract(salt, null, null, sessionId, null,
				challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		message.signatureValue = signature.sign();

		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuthenticationTestService.class.getName());
		when(mockServletConfig.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuditTestService.class.getName());
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME)).thenReturn(null);

		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.thenReturn(NRCID_SECRET);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.thenReturn(NRCID_APP_ID);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.thenReturn(NRCID_ORG_ID);

		when(mockServletRequest.getAttribute("javax.servlet.request.ssl_session")).thenReturn(new String(Hex.encodeHex(sessionId)));
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE + "Class")).thenReturn(null);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);
		when(mockServletRequest.getRemoteAddr()).thenReturn("1.2.3.4");
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, testHttpSession);

		assertTrue(AuthenticationTestService.isCalled());

		String nrcid = UserIdentifierUtil.getNonReversibleCitizenIdentifier(userId, NRCID_ORG_ID, NRCID_APP_ID, NRCID_SECRET);
		assertTrue(nrcid.equals(AuditTestService.getAuditUserId()));
		assertTrue(nrcid.equals(testHttpSession.getAttribute(EID_IDENTIFIER)));
	}

	@Test
	public void testHandleMessageExpiredChallenge() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(),
				"CN=Test, SERIALNUMBER=" + userId, notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);
		ServletConfig mockServletConfig = mock(ServletConfig.class);

		byte[] challenge = AuthenticationChallenge.generateChallenge(testHttpSession);

		Thread.sleep(1000);

		AuthenticationContract authenticationContract = new AuthenticationContract(salt, null, null, sessionId, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		message.signatureValue = signature.sign();

		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.thenReturn("1"); // 1 ms
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuthenticationTestService.class.getName());
		when(mockServletConfig.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuditTestService.class.getName());
		when(mockServletRequest.getRemoteAddr()).thenReturn(REMOTE_ADDRESS);

		when(mockServletRequest.getAttribute("javax.servlet.request.ssl_session")).thenReturn(new String(Hex.encodeHex(sessionId)));
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		try {
			this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, testHttpSession);
			fail();
		} catch (ServletException e) {
			assertNull(AuditTestService.getAuditUserId());
			assertNull(testHttpSession.getAttribute(EID_IDENTIFIER));
			assertEquals(certificate, AuditTestService.getAuditClientCertificate());
			assertEquals(REMOTE_ADDRESS, AuditTestService.getAuditRemoteAddress());
		}
	}

	@Test
	public void testInvalidAuthenticationSignature() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(),
				"CN=Test, SERIALNUMBER=" + userId, notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);
		ServletConfig mockServletConfig = mock(ServletConfig.class);

		AuthenticationChallenge.generateChallenge(testHttpSession);

		AuthenticationContract authenticationContract = new AuthenticationContract(salt, null, null,
				sessionId, null, "foobar-challenge".getBytes());
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		message.signatureValue = signature.sign();

		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuthenticationTestService.class.getName());
		when(mockServletConfig.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuditTestService.class.getName());
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);

		when(mockServletRequest.getAttribute("javax.servlet.request.ssl_session")).thenReturn(new String(Hex.encodeHex(sessionId)));
		when(mockServletRequest.getRemoteAddr()).thenReturn(REMOTE_ADDRESS);

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);

		try {
			this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, testHttpSession);
			fail();
		} catch (SecurityException e) {
			// expected
		}

		assertFalse(AuthenticationTestService.isCalled());
		assertNull(AuditTestService.getAuditUserId());
		assertEquals(REMOTE_ADDRESS, AuditTestService.getAuditRemoteAddress());
		assertEquals(certificate, AuditTestService.getAuditClientCertificate());
		assertNull(testHttpSession.getAttribute(EID_IDENTIFIER));
	}

	@Test
	public void testHandleMessageWithoutAuditService() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(),
				"CN=Test, SERIALNUMBER=" + userId, notBefore, notAfter, null, keyPair.getPrivate(), true, 0, null,
				null);

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = SALT;
		message.sessionId = SESSION_ID;

		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);
		ServletConfig mockServletConfig = mock(ServletConfig.class);

		byte[] challenge = AuthenticationChallenge.generateChallenge(testHttpSession);

		AuthenticationContract authenticationContract = new AuthenticationContract(SALT, null, null,
				SESSION_ID, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		message.signatureValue = signature.sign();

		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(AuthenticationTestService.class.getName());
		when(mockServletConfig.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE)).thenReturn(null);
		when(mockServletConfig.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE + "Class"))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.thenReturn(null);
		when(mockServletConfig.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME + "Class"))
				.thenReturn(null);

		when(mockServletRequest.getAttribute("javax.servlet.request.ssl_session")).thenReturn(new String(Hex.encodeHex(SESSION_ID)));
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);
		when(mockServletRequest.getRemoteAddr()).thenReturn(REMOTE_ADDRESS);

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, testHttpSession);

		assertTrue(AuthenticationTestService.isCalled());
		assertNull(AuditTestService.getAuditUserId());
		assertEquals(userId, testHttpSession.getAttribute(EID_IDENTIFIER));
	}

	public static class AuthenticationTestService implements AuthenticationService {

		private static boolean called;

		public static void reset() {
			AuthenticationTestService.called = false;
		}

		public static boolean isCalled() {
			return AuthenticationTestService.called;
		}

		private static final Log LOG = LogFactory.getLog(AuthenticationTestService.class);

		public void validateCertificateChain(List<X509Certificate> certificateChain) throws SecurityException {
			LOG.debug("validate certificate chain");
			AuthenticationTestService.called = true;
		}
	}
}
