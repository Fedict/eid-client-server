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

import be.bosa.eid.client_server.shared.message.AdministrationMessage;
import be.bosa.eid.client_server.shared.message.AuthenticationRequestMessage;
import be.bosa.eid.client_server.shared.message.ClientEnvironmentMessage;
import be.bosa.eid.client_server.shared.message.ErrorCode;
import be.bosa.eid.client_server.shared.message.FilesDigestRequestMessage;
import be.bosa.eid.client_server.shared.message.FinishedMessage;
import be.bosa.eid.client_server.shared.message.IdentificationRequestMessage;
import be.bosa.eid.client_server.shared.message.InsecureClientMessage;
import be.bosa.eid.client_server.shared.message.SignCertificatesRequestMessage;
import be.bosa.eid.client_server.shared.message.SignRequestMessage;
import be.bosa.eid.server.impl.AuthenticationChallenge;
import be.bosa.eid.server.impl.RequestContext;
import be.bosa.eid.server.impl.ServiceLocator;
import be.bosa.eid.server.spi.AuthenticationService;
import be.bosa.eid.server.spi.AuthorizationException;
import be.bosa.eid.server.spi.DigestInfo;
import be.bosa.eid.server.spi.IdentityIntegrityService;
import be.bosa.eid.server.spi.IdentityRequest;
import be.bosa.eid.server.spi.IdentityService;
import be.bosa.eid.server.spi.InsecureClientEnvironmentException;
import be.bosa.eid.server.spi.PrivacyService;
import be.bosa.eid.server.spi.SecureCardReaderService;
import be.bosa.eid.server.spi.SecureClientEnvironmentService;
import be.bosa.eid.server.spi.SignatureService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

/**
 * Handler for client environment message.
 *
 * @author Frank Cornelis
 */
@HandlesMessage(ClientEnvironmentMessage.class)
public class ClientEnvironmentMessageHandler implements MessageHandler<ClientEnvironmentMessage> {

	private static final Log LOG = LogFactory.getLog(ClientEnvironmentMessageHandler.class);

	@InitParam(HelloMessageHandler.SECURE_CLIENT_ENV_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SecureClientEnvironmentService> secureClientEnvServiceLocator;

	@InitParam(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME)
	private boolean includePhoto;

	@InitParam(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME)
	private boolean includeAddress;

	@InitParam(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME)
	private boolean includeIdentity;

	@InitParam(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	@InitParam(HelloMessageHandler.PRIVACY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<PrivacyService> privacyServiceLocator;

	@InitParam(HelloMessageHandler.REMOVE_CARD_INIT_PARAM_NAME)
	private boolean removeCard;

	@InitParam(HelloMessageHandler.CHANGE_PIN_INIT_PARAM_NAME)
	private boolean changePin;

	@InitParam(HelloMessageHandler.UNBLOCK_PIN_INIT_PARAM_NAME)
	private boolean unblockPin;

	private boolean includeHostname;

	private boolean includeInetAddress;

	@InitParam(HelloMessageHandler.LOGOFF_INIT_PARAM_NAME)
	private boolean logoff;

	@InitParam(HelloMessageHandler.PRE_LOGOFF_INIT_PARAM_NAME)
	private boolean preLogoff;

	@InitParam(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME)
	private boolean includeCertificates;

	@InitParam(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME)
	private boolean sessionIdChannelBinding;

	private boolean serverCertificateChannelBinding;

	@InitParam(HelloMessageHandler.REQUIRE_SECURE_READER_INIT_PARAM_NAME)
	private boolean requireSecureReader;

	@InitParam(HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(HelloMessageHandler.IDENTITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityService> identityServiceLocator;

	@InitParam(HelloMessageHandler.SECURE_CARD_READER_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SecureCardReaderService> secureCardReaderServiceLocator;

	public Object handleMessage(ClientEnvironmentMessage message, Map<String, String> httpHeaders,
								HttpServletRequest request, HttpSession session) throws ServletException {
		SecureClientEnvironmentService secureClientEnvService = this.secureClientEnvServiceLocator.locateService();
		if (secureClientEnvService == null) {
			throw new ServletException("no secure client env service configured");
		}

		String remoteAddress = request.getRemoteAddr();
		Integer sslKeySize = (Integer) request.getAttribute("javax.servlet.request.key_size");
		String userAgent = httpHeaders.get("user-agent");
		String sslCipherSuite = (String) request.getAttribute("javax.servlet.request.cipher_suite");
		try {
			secureClientEnvService.checkSecureClientEnvironment(message.javaVersion, message.javaVendor, message.osName,
					message.osArch, message.osVersion, userAgent, message.navigatorAppName, message.navigatorAppVersion,
					message.navigatorUserAgent, remoteAddress, sslKeySize, sslCipherSuite, message.readerList);
		} catch (InsecureClientEnvironmentException e) {
			return new InsecureClientMessage(e.isWarnOnly());
		}

		if (this.changePin || this.unblockPin) {
			return new AdministrationMessage(this.changePin, this.unblockPin, this.logoff, this.removeCard, this.requireSecureReader);
		}

		SignatureService signatureService = this.signatureServiceLocator.locateService();
		if (signatureService != null) {
			// TODO DRY refactor: is a copy-paste from HelloMessageHandler
			String filesDigestAlgo = signatureService.getFilesDigestAlgorithm();
			if (filesDigestAlgo != null) {
				LOG.debug("files digest algo: " + filesDigestAlgo);
				FilesDigestRequestMessage filesDigestRequestMessage = new FilesDigestRequestMessage();
				filesDigestRequestMessage.digestAlgo = filesDigestAlgo;
				return filesDigestRequestMessage;
			}

			if (this.includeCertificates) {
				LOG.debug("include signing certificate chain during pre-sign");
				IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator.locateService();
				boolean includeIntegrityData = identityIntegrityService != null;
				IdentityService identityService = this.identityServiceLocator.locateService();
				boolean includeIdentity;
				boolean includeAddress;
				boolean includePhoto;
				if (identityService != null) {
					IdentityRequest identityRequest = identityService.getIdentityRequest();
					includeIdentity = identityRequest.includeIdentity();
					includeAddress = identityRequest.includeAddress();
					includePhoto = identityRequest.includePhoto();
				} else {
					includeIdentity = this.includeIdentity;
					includeAddress = this.includeAddress;
					includePhoto = this.includePhoto;
				}
				RequestContext requestContext = new RequestContext(session);
				requestContext.setIncludeIdentity(includeIdentity);
				requestContext.setIncludeAddress(includeAddress);
				requestContext.setIncludePhoto(includePhoto);
				return new SignCertificatesRequestMessage(includeIdentity, includeAddress, includePhoto, includeIntegrityData);
			}

			DigestInfo digestInfo;
			try {
				digestInfo = signatureService.preSign(null, null, null, null, null);
			} catch (NoSuchAlgorithmException e) {
				throw new ServletException("no such algo: " + e.getMessage(), e);
			} catch (AuthorizationException e) {
				return new FinishedMessage(ErrorCode.AUTHORIZATION);
			}

			// also save it in the session for later verification
			SignatureDataMessageHandler.setDigestValue(digestInfo.digestValue, digestInfo.digestAlgo, session);

			IdentityService identityService = this.identityServiceLocator.locateService();
			boolean removeCard;
			if (identityService != null) {
				IdentityRequest identityRequest = identityService.getIdentityRequest();
				removeCard = identityRequest.removeCard();
			} else {
				removeCard = this.removeCard;
			}

			return new SignRequestMessage(digestInfo.digestValue, digestInfo.digestAlgo, digestInfo.description, this.logoff, removeCard, this.requireSecureReader);
		}

		AuthenticationService authenticationService = this.authenticationServiceLocator.locateService();
		if (authenticationService != null) {
			byte[] challenge = AuthenticationChallenge.generateChallenge(session);
			IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator.locateService();
			boolean includeIntegrityData = identityIntegrityService != null;
			boolean includeIdentity;
			boolean includeAddress;
			boolean includePhoto;
			boolean includeCertificates;
			boolean removeCard;

			IdentityService identityService = this.identityServiceLocator.locateService();
			if (identityService != null) {
				IdentityRequest identityRequest = identityService.getIdentityRequest();
				includeIdentity = identityRequest.includeIdentity();
				includeAddress = identityRequest.includeAddress();
				includePhoto = identityRequest.includePhoto();
				includeCertificates = identityRequest.includeCertificates();
				removeCard = identityRequest.removeCard();
			} else {
				includeIdentity = this.includeIdentity;
				includeAddress = this.includeAddress;
				includePhoto = this.includePhoto;
				includeCertificates = this.includeCertificates;
				removeCard = this.removeCard;
			}

			RequestContext requestContext = new RequestContext(session);
			requestContext.setIncludeIdentity(includeIdentity);
			requestContext.setIncludeAddress(includeAddress);
			requestContext.setIncludePhoto(includePhoto);
			requestContext.setIncludeCertificates(includeCertificates);

			String transactionMessage = null;
			SecureCardReaderService secureCardReaderService = this.secureCardReaderServiceLocator.locateService();
			if (secureCardReaderService != null) {
				transactionMessage = secureCardReaderService.getTransactionMessage();
				if (transactionMessage != null && transactionMessage.length() > SecureCardReaderService.TRANSACTION_MESSAGE_MAX_SIZE) {
					transactionMessage = transactionMessage.substring(0, SecureCardReaderService.TRANSACTION_MESSAGE_MAX_SIZE);
				}
				LOG.debug("transaction message: " + transactionMessage);
			}
			requestContext.setTransactionMessage(transactionMessage);

			return new AuthenticationRequestMessage(challenge,
					this.includeHostname, this.includeInetAddress, this.logoff, this.preLogoff, removeCard,
					this.sessionIdChannelBinding, this.serverCertificateChannelBinding, includeIdentity,
					includeCertificates, includeAddress, includePhoto, includeIntegrityData, this.requireSecureReader,
					transactionMessage);
		} else {
			IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator.locateService();
			boolean includeIntegrityData = identityIntegrityService != null;
			PrivacyService privacyService = this.privacyServiceLocator.locateService();
			String identityDataUsage;
			if (privacyService != null) {
				String clientLanguage = HelloMessageHandler.getClientLanguage(session);
				identityDataUsage = privacyService.getIdentityDataUsage(clientLanguage);
			} else {
				identityDataUsage = null;
			}
			boolean includeAddress;
			boolean includePhoto;
			boolean includeCertificates;
			boolean removeCard;
			IdentityService identityService = this.identityServiceLocator.locateService();
			if (identityService != null) {
				IdentityRequest identityRequest = identityService.getIdentityRequest();
				includeAddress = identityRequest.includeAddress();
				includePhoto = identityRequest.includePhoto();
				includeCertificates = identityRequest.includeCertificates();
				removeCard = identityRequest.removeCard();
			} else {
				includeAddress = this.includeAddress;
				includePhoto = this.includePhoto;
				includeCertificates = this.includeCertificates;
				removeCard = this.removeCard;
			}
			RequestContext requestContext = new RequestContext(session);
			requestContext.setIncludeAddress(includeAddress);
			requestContext.setIncludePhoto(includePhoto);
			requestContext.setIncludeCertificates(includeCertificates);
			return new IdentificationRequestMessage(includeAddress, includePhoto, includeIntegrityData, includeCertificates, removeCard, identityDataUsage);
		}
	}

	public void init(ServletConfig config) {
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.setSeed(System.currentTimeMillis());

		String hostname = config.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME);
		if (hostname != null) {
			this.includeHostname = true;
		}

		String inetAddress = config.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME);
		if (inetAddress != null) {
			this.includeInetAddress = true;
		}

		String channelBindingServerCertificate = config
				.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE);
		if (channelBindingServerCertificate != null) {
			this.serverCertificateChannelBinding = true;
		}
		String channelBindingService = config.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE);
		if (channelBindingService != null) {
			this.serverCertificateChannelBinding = true;
		}
	}
}
