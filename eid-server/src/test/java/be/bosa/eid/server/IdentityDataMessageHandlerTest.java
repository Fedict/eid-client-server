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

import be.bosa.eid.client_server.shared.message.IdentityDataMessage;
import be.bosa.eid.server.impl.RequestContext;
import be.bosa.eid.server.impl.handler.IdentityDataMessageHandler;
import be.bosa.eid.server.spi.AddressDTO;
import be.bosa.eid.server.spi.IdentityConsumerService;
import be.bosa.eid.server.spi.IdentityDTO;
import be.bosa.eid.server.spi.IdentityIntegrityService;
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

import static be.bosa.eid.server.impl.handler.HelloMessageHandler.REQUEST_ID_ATTRIBUTE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdentityDataMessageHandlerTest {

	private static final Log LOG = LogFactory.getLog(IdentityDataMessageHandlerTest.class);
	private static final String REMOTE_ADDRESS = "remote-address";
	private static final String REQUEST_ID = "requestId";

	private IdentityDataMessageHandler testedInstance;

	@Before
	public void setUp() {
		this.testedInstance = new IdentityDataMessageHandler();
		IdentityIntegrityTestService.reset();
		AuditTestService.reset();
	}

	@Test
	public void testHandleMessage() throws Exception {
		// setup
		ServletConfig mockServletConfig = mock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);


		when(mockHttpSession.getAttribute(REQUEST_ID_ATTRIBUTE)).thenReturn(REQUEST_ID);
		when(mockServletConfig.getInitParameter("IdentityIntegrityService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("IdentityIntegrityServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SkipNationalNumberCheck")).thenReturn(null);

		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_ADDRESS_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_PHOTO_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);

		byte[] idFile = "foobar-id-file".getBytes();
		IdentityDataMessage message = new IdentityDataMessage();
		message.idFile = idFile;

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);


	}

	@Test
	public void testHandleMessageWithIntegrityCheck() throws Exception {
		KeyPair rootKeyPair = MiscTestUtils.generateKeyPair();
		KeyPair rrnKeyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate rootCertificate = MiscTestUtils.generateCertificate(rootKeyPair.getPublic(), "CN=TestRootCA",
				notBefore, notAfter, null, rootKeyPair.getPrivate(), true, 0, null, null);
		X509Certificate rrnCertificate = MiscTestUtils.generateCertificate(rrnKeyPair.getPublic(),
				"CN=TestNationalRegistration", notBefore, notAfter, null, rootKeyPair.getPrivate(), false, 0, null,
				null);

		ServletConfig mockServletConfig = mock(ServletConfig.class);
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);

		when(mockServletConfig.getInitParameter("IdentityIntegrityService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("IdentityIntegrityServiceClass")).thenReturn(IdentityIntegrityTestService.class.getName());
		when(mockServletConfig.getInitParameter("IdentityConsumerService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("IdentityConsumerServiceClass")).thenReturn(IdentityConsumerTestService.class.getName());
		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SkipNationalNumberCheck")).thenReturn(null);

		when(mockHttpSession.getAttribute(REQUEST_ID_ATTRIBUTE)).thenReturn(REQUEST_ID);
		when(mockHttpSession.getAttribute("eid.identifier")).thenReturn(null);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_ADDRESS_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_PHOTO_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);

		byte[] idFile = "foobar-id-file".getBytes();
		IdentityDataMessage message = new IdentityDataMessage();
		message.idFile = idFile;

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(rrnKeyPair.getPrivate());
		signature.update(idFile);
		message.identitySignatureFile = signature.sign();
		message.rrnCertFile = rrnCertificate.getEncoded();
		message.rootCertFile = rootCertificate.getEncoded();

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, new HashMap<>(), mockServletRequest, mockHttpSession);

		assertEquals(rrnCertificate, IdentityIntegrityTestService.getCertificate());
		assertEquals(rrnCertificate, IdentityIntegrityTestService.getCertificate());
		assertNotNull(IdentityConsumerTestService.identity);
	}

	@Test
	public void testHandleMessageInvalidIntegritySignature() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(),
				"CN=TestNationalRegistration", notBefore, notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = mock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);

		when(mockServletConfig.getInitParameter("IdentityIntegrityService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("IdentityIntegrityServiceClass")).thenReturn(IdentityIntegrityTestService.class.getName());
		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(AuditTestService.class.getName());
		when(mockServletConfig.getInitParameter("SkipNationalNumberCheck")).thenReturn(null);

		when(mockServletRequest.getRemoteAddr()).thenReturn(REMOTE_ADDRESS);

		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_ADDRESS_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_PHOTO_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);

		byte[] idFile = "foobar-id-file".getBytes();
		IdentityDataMessage message = new IdentityDataMessage();
		message.idFile = idFile;

		KeyPair intruderKeyPair = MiscTestUtils.generateKeyPair();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(intruderKeyPair.getPrivate());
		signature.update(idFile);
		message.identitySignatureFile = signature.sign();
		message.rrnCertFile = certificate.getEncoded();

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		try {
			this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);
			fail();
		} catch (ServletException e) {
			LOG.debug("expected exception: " + e.getMessage());
			assertNull(IdentityIntegrityTestService.getCertificate());
			assertEquals(REMOTE_ADDRESS, AuditTestService.getAuditIntegrityRemoteAddress());
		}
	}

	@Test
	public void testHandleMessageCorruptIntegritySignature() throws Exception {
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(),
				"CN=TestNationalRegistration", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null);

		ServletConfig mockServletConfig = mock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<>();
		HttpSession mockHttpSession = mock(HttpSession.class);
		HttpServletRequest mockServletRequest = mock(HttpServletRequest.class);

		when(mockServletConfig.getInitParameter("IdentityIntegrityService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("IdentityIntegrityServiceClass")).thenReturn(IdentityIntegrityTestService.class.getName());
		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(AuditTestService.class.getName());
		when(mockServletConfig.getInitParameter("SkipNationalNumberCheck")).thenReturn(null);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);

		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_ADDRESS_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_PHOTO_SESSION_ATTRIBUTE)).thenReturn(false);

		when(mockServletRequest.getRemoteAddr()).thenReturn(REMOTE_ADDRESS);

		byte[] idFile = "foobar-id-file".getBytes();
		IdentityDataMessage message = new IdentityDataMessage();
		message.idFile = idFile;

		message.identitySignatureFile = "foobar-signature".getBytes();
		message.rrnCertFile = certificate.getEncoded();

		EidServerServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		try {
			this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);
			fail();
		} catch (ServletException e) {
			LOG.debug("expected exception: " + e.getMessage(), e);
			LOG.debug("exception type: " + e.getClass().getName());
			assertNull(IdentityIntegrityTestService.getCertificate());
			assertEquals(REMOTE_ADDRESS, AuditTestService.getAuditIntegrityRemoteAddress());
		}
	}

	public static class IdentityIntegrityTestService implements IdentityIntegrityService {
		private static X509Certificate certificate;

		public static void reset() {
			IdentityIntegrityTestService.certificate = null;
		}

		public static X509Certificate getCertificate() {
			return IdentityIntegrityTestService.certificate;
		}

		public void checkNationalRegistrationCertificate(List<X509Certificate> certificateChain)
				throws SecurityException {
			IdentityIntegrityTestService.certificate = certificateChain.get(0);
		}
	}

	public static class IdentityConsumerTestService implements IdentityConsumerService {

		private static String userId;
		private static IdentityDTO identity;
		private static AddressDTO address;
		private static byte[] photo;
		private static X509Certificate authnCert;
		private static X509Certificate signCert;
		private static X509Certificate caCert;
		private static X509Certificate rootCert;

		@Override
		public void setUserId(String requestId, String userId) {
			assertEquals(REQUEST_ID, requestId);
			IdentityConsumerTestService.userId = userId;
		}

		@Override
		public void setIdentity(String requestId, IdentityDTO identity) {
			assertEquals(REQUEST_ID, requestId);
			IdentityConsumerTestService.identity = identity;
		}

		@Override
		public void setAddress(String requestId, AddressDTO address) {
			assertEquals(REQUEST_ID, requestId);
			IdentityConsumerTestService.address = address;
		}

		@Override
		public void setPhoto(String requestId, byte[] photo) {
			assertEquals(REQUEST_ID, requestId);
			IdentityConsumerTestService.photo = photo;
		}

		@Override
		public void setCertificates(String requestId, X509Certificate authnCert, X509Certificate signCert, X509Certificate caCert, X509Certificate rootCert) {
			assertEquals(REQUEST_ID, requestId);
			IdentityConsumerTestService.authnCert = authnCert;
			IdentityConsumerTestService.signCert = signCert;
			IdentityConsumerTestService.caCert = caCert;
			IdentityConsumerTestService.rootCert = rootCert;
		}

		public String getUserId() {
			return userId;
		}

		public IdentityDTO getIdentity() {
			return identity;
		}

		public AddressDTO getAddress() {
			return address;
		}

		public byte[] getPhoto() {
			return photo;
		}

		public X509Certificate getAuthnCert() {
			return authnCert;
		}

		public X509Certificate getSignCert() {
			return signCert;
		}

		public X509Certificate getCaCert() {
			return caCert;
		}

		public X509Certificate getRootCert() {
			return rootCert;
		}
	}
}
