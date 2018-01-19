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

package be.bosa.eid.server.impl.handler;

import be.bosa.eid.client_server.shared.message.AuthSignRequestMessage;
import be.bosa.eid.client_server.shared.message.AuthenticationContract;
import be.bosa.eid.client_server.shared.message.AuthenticationDataMessage;
import be.bosa.eid.client_server.shared.message.ErrorCode;
import be.bosa.eid.client_server.shared.message.FinishedMessage;
import be.bosa.eid.server.Address;
import be.bosa.eid.server.EIdCertsData;
import be.bosa.eid.server.EIdData;
import be.bosa.eid.server.Identity;
import be.bosa.eid.server.impl.AuthenticationChallenge;
import be.bosa.eid.server.impl.AuthenticationSignatureContextImpl;
import be.bosa.eid.server.impl.RequestContext;
import be.bosa.eid.server.impl.ServiceLocator;
import be.bosa.eid.server.impl.UserIdentifierUtil;
import be.bosa.eid.server.impl.tlv.TlvParser;
import be.bosa.eid.server.spi.AuditService;
import be.bosa.eid.server.spi.AuthenticationService;
import be.bosa.eid.server.spi.AuthenticationSignatureContext;
import be.bosa.eid.server.spi.AuthenticationSignatureService;
import be.bosa.eid.server.spi.CertificateSecurityException;
import be.bosa.eid.server.spi.ChannelBindingService;
import be.bosa.eid.server.spi.ExpiredCertificateSecurityException;
import be.bosa.eid.server.spi.IdentityIntegrityService;
import be.bosa.eid.server.spi.PreSignResult;
import be.bosa.eid.server.spi.RevokedCertificateSecurityException;
import be.bosa.eid.server.spi.TrustCertificateSecurityException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Authentication data message protocol handler.
 *
 * @author Frank Cornelis
 */
@HandlesMessage(AuthenticationDataMessage.class)
public class AuthenticationDataMessageHandler implements MessageHandler<AuthenticationDataMessage> {

	public static final String AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE = "eid.identifier";
	public static final String PLAIN_TEXT_DIGEST_ALGO_OID = "2.16.56.1.2.1.3.1";

	private static final Log LOG = LogFactory.getLog(AuthenticationDataMessageHandler.class);

	@InitParam(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuditService> auditServiceLocator;

	@InitParam(HelloMessageHandler.CHANNEL_BINDING_SERVICE)
	private ServiceLocator<ChannelBindingService> channelBindingServiceLocator;

	@InitParam(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME)
	private String hostname;

	@InitParam(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME)
	private InetAddress inetAddress;

	@InitParam(CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME)
	private Long maxMaturity;

	private X509Certificate serverCertificate;

	@InitParam(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME)
	private boolean sessionIdChannelBinding;

	public static final String AUTHN_SERVICE_INIT_PARAM_NAME = "AuthenticationService";
	public static final String AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME = "AuthenticationSignatureService";
	public static final String AUDIT_SERVICE_INIT_PARAM_NAME = "AuditService";
	public static final String CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME = "ChallengeMaxMaturity";
	public static final String NRCID_SECRET_INIT_PARAM_NAME = "NRCIDSecret";
	public static final String NRCID_ORG_ID_INIT_PARAM_NAME = "NRCIDOrgId";
	public static final String NRCID_APP_ID_INIT_PARAM_NAME = "NRCIDAppId";

	@InitParam(NRCID_SECRET_INIT_PARAM_NAME)
	private String nrcidSecret;

	@InitParam(NRCID_ORG_ID_INIT_PARAM_NAME)
	private String nrcidOrgId;

	@InitParam(NRCID_APP_ID_INIT_PARAM_NAME)
	private String nrcidAppId;

	@InitParam(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	@InitParam(IdentityDataMessageHandler.INCLUDE_DATA_FILES)
	private boolean includeDataFiles;

	@InitParam(AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuthenticationSignatureService> authenticationSignatureServiceLocator;

	public Object handleMessage(AuthenticationDataMessage message, Map<String, String> httpHeaders,
								HttpServletRequest request, HttpSession session) throws ServletException {
		LOG.debug("authentication data message received");

		if (message.authnCert == null) {
			/*
			 * Can be the case for future (Kids) eID cards that have some
			 * certificates missing.
			 */
			String msg = "authentication certificate not present";
			LOG.warn(msg);
			throw new ServletException(msg);
		}
		byte[] signatureValue = message.signatureValue;
		LOG.debug("authn signing certificate subject: " + message.authnCert.getSubjectX500Principal());
		PublicKey signingKey = message.authnCert.getPublicKey();

		if (this.sessionIdChannelBinding) {
			checkSessionIdChannelBinding(message, request);
			if (this.serverCertificate == null) {
				LOG.warn("adviced to use in combination with server certificate channel binding");
			}
		}

		ChannelBindingService channelBindingService = this.channelBindingServiceLocator.locateService();
		if (this.serverCertificate != null || channelBindingService != null) {
			LOG.debug("using server certificate channel binding");
		}

		if (!this.sessionIdChannelBinding && this.serverCertificate == null && channelBindingService == null) {
			LOG.warn("not using any secure channel binding");
		}

		byte[] challenge;
		try {
			challenge = AuthenticationChallenge.getAuthnChallenge(session, this.maxMaturity);
		} catch (SecurityException e) {
			AuditService auditService = this.auditServiceLocator.locateService();
			if (auditService != null) {
				String remoteAddress = request.getRemoteAddr();
				auditService.authenticationError(remoteAddress, message.authnCert);
			}
			throw new ServletException("security error: " + e.getMessage(), e);
		}

		byte[] serverCertificateClientPOV = null;
		try {
			if (message.serverCertificate != null) {
				serverCertificateClientPOV = message.serverCertificate.getEncoded();
			}
		} catch (CertificateEncodingException e) {
			throw new ServletException("server cert decoding error: " + e.getMessage(), e);
		}

		/*
		 * We validate the authentication contract using the client-side
		 * communicated server SSL certificate in case of secure channel
		 * binding.
		 */
		AuthenticationContract authenticationContract = new AuthenticationContract(message.saltValue, this.hostname,
				this.inetAddress, message.sessionId, serverCertificateClientPOV, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();

		try {
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(signingKey);
			signature.update(toBeSigned);
			if (!signature.verify(signatureValue)) {
				AuditService auditService = this.auditServiceLocator.locateService();
				if (auditService != null) {
					String remoteAddress = request.getRemoteAddr();
					auditService.authenticationError(remoteAddress, message.authnCert);
				}
				throw new SecurityException("authn signature incorrect");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException("algo error");
		} catch (InvalidKeyException e) {
			throw new SecurityException("authn key error");
		} catch (SignatureException e) {
			throw new SecurityException("signature error");
		}

		RequestContext requestContext = new RequestContext(session);
		String transactionMessage = requestContext.getTransactionMessage();
		if (transactionMessage != null) {
			LOG.debug("verifying TransactionMessage signature");
			byte[] transactionMessageSignature = message.transactionMessageSignature;
			if (transactionMessageSignature == null) {
				throw new SecurityException("missing TransactionMessage signature");
			}
			try {
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, signingKey);
				byte[] signatureDigestInfoValue = cipher.doFinal(transactionMessageSignature);
				ASN1InputStream aIn = new ASN1InputStream(signatureDigestInfoValue);
				DigestInfo signatureDigestInfo = new DigestInfo((ASN1Sequence) aIn.readObject());
				if (!PLAIN_TEXT_DIGEST_ALGO_OID.equals(signatureDigestInfo.getAlgorithmId().getAlgorithm().getId())) {
					throw new SecurityException("TransactionMessage signature algo OID incorrect");
				}
				if (!Arrays.equals(transactionMessage.getBytes(), signatureDigestInfo.getDigest())) {
					throw new SecurityException("signed TransactionMessage incorrect");
				}
				LOG.debug("TransactionMessage signature validated");
			} catch (GeneralSecurityException | IOException e) {
				LOG.error("error verifying TransactionMessage signature", e);
				AuditService auditService = this.auditServiceLocator.locateService();
				if (auditService != null) {
					String remoteAddress = request.getRemoteAddr();
					auditService.authenticationError(remoteAddress, message.authnCert);
				}
				throw new SecurityException("error verifying TransactionMessage signature: " + e.getMessage());
			}
		}

		/*
		 * Secure channel binding verification.
		 */
		if (channelBindingService != null) {
			X509Certificate serverCertificate = channelBindingService.getServerCertificate();
			if (serverCertificate == null) {
				LOG.warn("could not verify secure channel binding as the server does not know its identity yet");
			} else {
				if (!serverCertificate.equals(message.serverCertificate)) {
					AuditService auditService = this.auditServiceLocator.locateService();
					if (auditService != null) {
						String remoteAddress = request.getRemoteAddr();
						auditService.authenticationError(remoteAddress, message.authnCert);
					}
					throw new SecurityException("secure channel binding identity mismatch");
				}
				LOG.debug("secure channel binding verified");
			}
		} else {
			if (this.serverCertificate != null) {
				if (!this.serverCertificate.equals(message.serverCertificate)) {
					AuditService auditService = this.auditServiceLocator.locateService();
					if (auditService != null) {
						String remoteAddress = request.getRemoteAddr();
						auditService.authenticationError(remoteAddress, message.authnCert);
					}
					throw new SecurityException("secure channel binding identity mismatch");
				}
				LOG.debug("secure channel binding verified");
			}
		}

		AuthenticationService authenticationService = this.authenticationServiceLocator.locateService();
		List<X509Certificate> certificateChain = new LinkedList<>();
		certificateChain.add(message.authnCert);
		certificateChain.add(message.citizenCaCert);
		certificateChain.add(message.rootCaCert);
		try {
			authenticationService.validateCertificateChain(certificateChain);
		} catch (ExpiredCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_EXPIRED);
		} catch (RevokedCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_REVOKED);
		} catch (TrustCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_NOT_TRUSTED);
		} catch (CertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE);
		} catch (Exception e) {
			/*
			 * We don't want to depend on the full JavaEE profile in this
			 * artifact.
			 */
			return handleException(e);
		}

		String userId = UserIdentifierUtil.getUserId(message.authnCert);
		LOG.info("authenticated: " + userId + " @ " + request.getRemoteAddr());
		if (this.nrcidSecret != null) {
			userId = UserIdentifierUtil.getNonReversibleCitizenIdentifier(userId, this.nrcidOrgId, this.nrcidAppId, this.nrcidSecret);
		}
		/*
		 * Some people state that you cannot use the national register number
		 * without hashing. Problem is that hashing introduces hash collision
		 * problems. The probability is very low, but what if it's your leg
		 * they're cutting of because of a patient mismatch based on the SHA1 of
		 * your national register number?
		 */

		/*
		 * Push authenticated used Id into the HTTP session.
		 */
		session.setAttribute(AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE, userId);

		EIdData eidData = (EIdData) session.getAttribute(IdentityDataMessageHandler.EID_SESSION_ATTRIBUTE);
		if (eidData == null) {
			eidData = new EIdData();
			session.setAttribute(IdentityDataMessageHandler.EID_SESSION_ATTRIBUTE, eidData);
		}
		eidData.identifier = userId;

		AuditService auditService = this.auditServiceLocator.locateService();
		if (auditService != null) {
			auditService.authenticated(userId);
		}

		boolean includeIdentity = requestContext.includeIdentity();
		boolean includeAddress = requestContext.includeAddress();
		boolean includeCertificates = requestContext.includeCertificates();
		boolean includePhoto = requestContext.includePhoto();

		/*
		 * Also process the identity data in case it was requested.
		 */
		if (includeIdentity) {
			if (message.identityData == null) {
				throw new ServletException("identity data not included while requested");
			}
		}
		if (includeAddress) {
			if (message.addressData == null) {
				throw new ServletException("address data not included while requested");
			}
		}
		if (includePhoto) {
			if (message.photoData == null) {
				throw new ServletException("photo data not included while requested");
			}
		}
		IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator.locateService();
		if (identityIntegrityService != null) {
			if (message.rrnCertificate == null) {
				throw new ServletException("national registry certificate not included while requested");
			}
			List<X509Certificate> rrnCertificateChain = new LinkedList<>();
			rrnCertificateChain.add(message.rrnCertificate);
			rrnCertificateChain.add(message.rootCaCert);

			try {
				identityIntegrityService.checkNationalRegistrationCertificate(rrnCertificateChain);
			} catch (ExpiredCertificateSecurityException e) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_EXPIRED);
			} catch (RevokedCertificateSecurityException e) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_REVOKED);
			} catch (TrustCertificateSecurityException e) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_NOT_TRUSTED);
			} catch (CertificateSecurityException e) {
				return new FinishedMessage(ErrorCode.CERTIFICATE);
			} catch (Exception e) {
				return handleException(e);
			}

			PublicKey rrnPublicKey = message.rrnCertificate.getPublicKey();
			if (includeIdentity) {
				if (message.identitySignatureData == null) {
					throw new ServletException("identity signature data not included while requested");
				}
				verifySignature(message.rrnCertificate.getSigAlgName(), message.identitySignatureData, rrnPublicKey,
						request, message.identityData);
			}
			if (includeAddress) {
				if (message.addressSignatureData == null) {
					throw new ServletException("address signature data not included while requested");
				}
				byte[] addressFile = Util.trimRight(message.addressData);
				verifySignature(message.rrnCertificate.getSigAlgName(), message.addressSignatureData, rrnPublicKey,
						request, addressFile, message.identitySignatureData);
			}
		}
		if (includeIdentity) {
			Identity identity = TlvParser.parse(message.identityData, Identity.class);
			if (!UserIdentifierUtil.getUserId(message.authnCert).equals(identity.nationalNumber)) {
				throw new ServletException("national number mismatch");
			}
			session.setAttribute(IdentityDataMessageHandler.IDENTITY_SESSION_ATTRIBUTE, identity);
			eidData.identity = identity;
			auditService = this.auditServiceLocator.locateService();
			if (auditService != null) {
				auditService.identified(identity.nationalNumber);
			}
		}
		if (includeAddress) {
			Address address = TlvParser.parse(message.addressData, Address.class);
			session.setAttribute(IdentityDataMessageHandler.ADDRESS_SESSION_ATTRIBUTE, address);
			eidData.address = address;
		}
		if (includePhoto) {
			if (includeIdentity) {
				byte[] expectedPhotoDigest = eidData.identity.photoDigest;
				byte[] actualPhotoDigest = digestPhoto(Util.getDigestAlgo(expectedPhotoDigest.length), message.photoData);
				if (!Arrays.equals(expectedPhotoDigest, actualPhotoDigest)) {
					throw new ServletException("photo digest incorrect");
				}
			}
			session.setAttribute(IdentityDataMessageHandler.PHOTO_SESSION_ATTRIBUTE, message.photoData);
			eidData.photo = message.photoData;
		}
		if (includeCertificates) {
			if (includeIdentity) {
				eidData.certs = new EIdCertsData();
				eidData.certs.authn = message.authnCert;
				eidData.certs.ca = message.citizenCaCert;
				eidData.certs.root = message.rootCaCert;
				eidData.certs.sign = message.signCert;
			}
			session.setAttribute(IdentityDataMessageHandler.AUTHN_CERT_SESSION_ATTRIBUTE, message.authnCert);
			session.setAttribute(IdentityDataMessageHandler.CA_CERT_SESSION_ATTRIBUTE, message.citizenCaCert);
			session.setAttribute(IdentityDataMessageHandler.ROOT_CERT_SESSION_ATTRIBTUE, message.rootCaCert);
			session.setAttribute(IdentityDataMessageHandler.SIGN_CERT_SESSION_ATTRIBUTE, message.signCert);
		}

		if (this.includeDataFiles) {
			session.setAttribute(IdentityDataMessageHandler.EID_DATA_IDENTITY_SESSION_ATTRIBUTE, message.identityData);
			session.setAttribute(IdentityDataMessageHandler.EID_DATA_ADDRESS_SESSION_ATTRIBUTE, message.addressData);
		}

		AuthenticationSignatureService authenticationSignatureService = this.authenticationSignatureServiceLocator
				.locateService();
		if (authenticationSignatureService != null) {
			List<X509Certificate> authnCertificateChain;
			if (message.authnCert != null) {
				authnCertificateChain = new LinkedList<>();
				authnCertificateChain.add(message.authnCert);
				authnCertificateChain.add(message.citizenCaCert);
				authnCertificateChain.add(message.rootCaCert);
			} else {
				authnCertificateChain = null;
			}
			AuthenticationSignatureContext authenticationSignatureContext = new AuthenticationSignatureContextImpl(session);
			PreSignResult preSignResult = authenticationSignatureService.preSign(authnCertificateChain, authenticationSignatureContext);
			if (preSignResult == null) {
				return new FinishedMessage();
			}
			boolean logoff = preSignResult.getLogoff();
			byte[] computedDigestValue = preSignResult.getDigestInfo().digestValue;
			String digestAlgo = preSignResult.getDigestInfo().digestAlgo;
			String authnMessage = preSignResult.getDigestInfo().description;
			return new AuthSignRequestMessage(computedDigestValue, digestAlgo, authnMessage, logoff);
		}

		return new FinishedMessage();
	}

	private Object handleException(Exception e) {
		if ("javax.ejb.EJBException".equals(e.getClass().getName())) {
			Exception exception;
			try {
				Method getCausedByExceptionMethod = e.getClass().getMethod("getCausedByException");
				exception = (Exception) getCausedByExceptionMethod.invoke(e, new Object[]{});
			} catch (Exception e2) {
				LOG.debug("error: " + e.getMessage(), e);
				throw new SecurityException("error retrieving the root cause: " + e2.getMessage());
			}
			if (exception instanceof ExpiredCertificateSecurityException) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_EXPIRED);
			}
			if (exception instanceof RevokedCertificateSecurityException) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_REVOKED);
			}
			if (exception instanceof TrustCertificateSecurityException) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_NOT_TRUSTED);
			}
			if (exception instanceof CertificateSecurityException) {
				return new FinishedMessage(ErrorCode.CERTIFICATE);
			}
		}
		throw new SecurityException("error checking the NRN certificate: " + e.getMessage(), e);
	}

	private byte[] digestPhoto(String digestAlgoName, byte[] photoFile) {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(digestAlgoName);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA error: " + e.getMessage(), e);
		}
		return messageDigest.digest(photoFile);
	}

	private void verifySignature(String signatureAlgo, byte[] signatureData, PublicKey publicKey,
								 HttpServletRequest request, byte[]... data) throws ServletException {
		Signature signature;
		try {
			signature = Signature.getInstance(signatureAlgo);
		} catch (NoSuchAlgorithmException e) {
			throw new ServletException("algo error: " + e.getMessage(), e);
		}
		try {
			signature.initVerify(publicKey);
		} catch (InvalidKeyException e) {
			throw new ServletException("key error: " + e.getMessage(), e);
		}
		try {
			for (byte[] dataItem : data) {
				signature.update(dataItem);
			}

			if (!signature.verify(signatureData)) {
				AuditService auditService = this.auditServiceLocator.locateService();
				if (auditService != null) {
					String remoteAddress = request.getRemoteAddr();
					auditService.identityIntegrityError(remoteAddress);
				}
				throw new ServletException("signature incorrect");
			}
		} catch (SignatureException e) {
			throw new ServletException("signature error: " + e.getMessage(), e);
		}
	}

	private void checkSessionIdChannelBinding(AuthenticationDataMessage message, HttpServletRequest request) {
		LOG.debug("using TLS session Id channel binding");
		byte[] sessionId = message.sessionId;
		/*
		 * Next is Tomcat specific.
		 */
		String actualSessionId = (String) request.getAttribute("javax.servlet.request.ssl_session");
		if (actualSessionId == null) {
			/*
			 * Servlet specs v3.0
			 */
			actualSessionId = (String) request.getAttribute("javax.servlet.request.ssl_session_id");
		}
		if (actualSessionId == null) {
			LOG.warn("could not verify the SSL session identifier");
			return;
		}
		if (!Arrays.equals(sessionId, Hex.decode(actualSessionId))) {
			LOG.warn("SSL session Id mismatch");
			LOG.debug("signed SSL session Id: " + new String(Hex.encode(sessionId)));
			LOG.debug("actual SSL session Id: " + actualSessionId);
			throw new SecurityException("SSL session Id mismatch");
		}
		LOG.debug("SSL session identifier checked");
	}

	public void init(ServletConfig config) throws ServletException {
		String channelBindingServerCertificate = config
				.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE);
		if (channelBindingServerCertificate != null) {
			File serverCertificateFile = new File(channelBindingServerCertificate);
			if (!serverCertificateFile.exists()) {
				throw new ServletException("server certificate not found: " + serverCertificateFile);
			}
			byte[] encodedServerCertificate;
			try {
				encodedServerCertificate = FileUtils.readFileToByteArray(serverCertificateFile);
			} catch (IOException e) {
				throw new ServletException("error reading server certificate: " + e.getMessage(), e);
			}
			this.serverCertificate = getCertificate(encodedServerCertificate);
		}
	}

	private X509Certificate getCertificate(byte[] certData) {
		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException("cert factory error: " + e.getMessage(), e);
		}
		try {
			return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certData));
		} catch (CertificateException e) {
			throw new RuntimeException("certificate decoding error: " + e.getMessage(), e);
		}
	}
}
