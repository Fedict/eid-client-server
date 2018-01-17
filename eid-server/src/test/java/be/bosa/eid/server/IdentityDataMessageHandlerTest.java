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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class IdentityDataMessageHandlerTest {

	private static final Log LOG = LogFactory.getLog(IdentityDataMessageHandlerTest.class);
	private static final String REMOTE_ADDRESS = "remote-address";

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

		when(mockServletConfig.getInitParameter("IdentityIntegrityService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("IdentityIntegrityServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SkipNationalNumberCheck")).thenReturn(null);

		when(mockHttpSession.getAttribute("eid")).thenReturn(null);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_ADDRESS_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockHttpSession.getAttribute(RequestContext.INCLUDE_PHOTO_SESSION_ATTRIBUTE)).thenReturn(false);
		when(mockServletConfig.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES)).thenReturn(null);

		byte[] idFile = "foobar-id-file".getBytes();
		IdentityDataMessage message = new IdentityDataMessage();
		message.idFile = idFile;

		AppletServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders, mockServletRequest, mockHttpSession);

		verify(mockHttpSession).setAttribute(eq("eid.identity"), isA(Identity.class));
		verify(mockHttpSession).setAttribute(eq("eid"), isA(EIdData.class));
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
		when(mockServletConfig.getInitParameter("AuditService")).thenReturn(null);
		when(mockServletConfig.getInitParameter("AuditServiceClass")).thenReturn(null);
		when(mockServletConfig.getInitParameter("SkipNationalNumberCheck")).thenReturn(null);

		when(mockHttpSession.getAttribute("eid.identifier")).thenReturn(null);
		when(mockHttpSession.getAttribute("eid")).thenReturn(null);
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

		AppletServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, new HashMap<>(), mockServletRequest, mockHttpSession);

		verify(mockHttpSession).setAttribute(eq("eid.identity"), isA(Identity.class));
		verify(mockHttpSession).setAttribute(eq("eid"), isA(EIdData.class));
		assertEquals(rrnCertificate, IdentityIntegrityTestService.getCertificate());
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

		AppletServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
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

		AppletServiceServlet.injectInitParams(mockServletConfig, this.testedInstance);
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
}
