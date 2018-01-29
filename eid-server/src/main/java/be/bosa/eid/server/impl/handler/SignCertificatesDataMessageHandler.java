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

import be.bosa.eid.client_server.shared.message.ErrorCode;
import be.bosa.eid.client_server.shared.message.FinishedMessage;
import be.bosa.eid.client_server.shared.message.SignCertificatesDataMessage;
import be.bosa.eid.client_server.shared.message.SignRequestMessage;
import be.bosa.eid.server.Address;
import be.bosa.eid.server.Identity;
import be.bosa.eid.server.dto.DTOMapper;
import be.bosa.eid.server.impl.RequestContext;
import be.bosa.eid.server.impl.ServiceLocator;
import be.bosa.eid.server.impl.tlv.TlvParser;
import be.bosa.eid.server.spi.AddressDTO;
import be.bosa.eid.server.spi.AuditService;
import be.bosa.eid.server.spi.AuthorizationException;
import be.bosa.eid.server.spi.DigestInfo;
import be.bosa.eid.server.spi.IdentityDTO;
import be.bosa.eid.server.spi.IdentityIntegrityService;
import be.bosa.eid.server.spi.IdentityRequest;
import be.bosa.eid.server.spi.IdentityService;
import be.bosa.eid.server.spi.SignatureService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Sign Certificate Data Message Handler.
 *
 * @author Frank Cornelis
 */
@HandlesMessage(SignCertificatesDataMessage.class)
public class SignCertificatesDataMessageHandler implements MessageHandler<SignCertificatesDataMessage> {

	private static final Log LOG = LogFactory.getLog(SignCertificatesDataMessageHandler.class);

	@InitParam(HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(HelloMessageHandler.REMOVE_CARD_INIT_PARAM_NAME)
	private boolean removeCard;

	@InitParam(HelloMessageHandler.LOGOFF_INIT_PARAM_NAME)
	private boolean logoff;

	@InitParam(HelloMessageHandler.REQUIRE_SECURE_READER_INIT_PARAM_NAME)
	private boolean requireSecureReader;

	@InitParam(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuditService> auditServiceLocator;

	@InitParam(HelloMessageHandler.IDENTITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityService> identityServiceLocator;

	public Object handleMessage(SignCertificatesDataMessage message, Map<String, String> httpHeaders,
								HttpServletRequest request, HttpSession session) throws ServletException {
		SignatureService signatureService = this.signatureServiceLocator.locateService();

		List<X509Certificate> signingCertificateChain = message.certificateChain;
		X509Certificate signingCertificate = signingCertificateChain.get(0);
		if (signingCertificate == null) {
			throw new ServletException("missing non-repudiation certificate");
		}
		LOG.debug("signing certificate: " + signingCertificateChain.get(0).getSubjectX500Principal());

		RequestContext requestContext = new RequestContext(session);
		boolean includeIdentity = requestContext.includeIdentity();
		boolean includeAddress = requestContext.includeAddress();
		boolean includePhoto = requestContext.includePhoto();

		Identity identity = null;
		Address address = null;
		if (includeIdentity || includeAddress || includePhoto) {
			/*
			 * Pre-sign phase including identity data.
			 */
			if (includeIdentity) {
				if (message.identityData == null) {
					throw new ServletException("identity data missing");
				}
				identity = TlvParser.parse(message.identityData, Identity.class);
			}

			if (includeAddress) {
				if (message.addressData == null) {
					throw new ServletException("address data missing");
				}
				address = TlvParser.parse(message.addressData, Address.class);
			}

			if (includePhoto) {
				if (message.photoData == null) {
					throw new ServletException("photo data missing");
				}
				if (identity != null) {
					byte[] expectedPhotoDigest = identity.photoDigest;
					byte[] actualPhotoDigest;

					try {
						actualPhotoDigest = digestPhoto(Util.getDigestAlgo(expectedPhotoDigest.length), message.photoData);
					} catch (RuntimeException e) {
						throw new ServletException("photo signed with unsupported algorithm");
					}

					if (!Arrays.equals(expectedPhotoDigest, actualPhotoDigest)) {
						throw new ServletException("photo digest incorrect");
					}
				}
			}

			IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator.locateService();
			if (identityIntegrityService != null) {
				if (message.rrnCertificate == null) {
					throw new ServletException("national registry certificate not included while requested");
				}
				PublicKey rrnPublicKey = message.rrnCertificate.getPublicKey();
				if (message.identityData != null) {
					if (message.identitySignatureData == null) {
						throw new ServletException("missing identity data signature");
					}
					verifySignature(message.rrnCertificate.getSigAlgName(), message.identitySignatureData, rrnPublicKey, request, message.identityData);
					if (message.addressData != null) {
						if (message.addressSignatureData == null) {
							throw new ServletException("missing address data signature");
						}
						byte[] addressFile = Util.trimRight(message.addressData);
						verifySignature(message.rrnCertificate.getSigAlgName(), message.addressSignatureData,
								rrnPublicKey, request, addressFile, message.identitySignatureData);
					}
				}

				LOG.debug("checking national registration certificate: "
						+ message.rrnCertificate.getSubjectX500Principal());
				List<X509Certificate> rrnCertificateChain = new LinkedList<>();
				rrnCertificateChain.add(message.rrnCertificate);
				rrnCertificateChain.add(message.rootCertificate);
				identityIntegrityService.checkNationalRegistrationCertificate(rrnCertificateChain);
			}
		}

		DigestInfo digestInfo;
		DTOMapper dtoMapper = new DTOMapper();
		IdentityDTO identityDTO = dtoMapper.map(identity, IdentityDTO.class);
		AddressDTO addressDTO = dtoMapper.map(address, AddressDTO.class);
		try {
			digestInfo = signatureService.preSign(getRequestId(session),
					null, signingCertificateChain, identityDTO, addressDTO, message.photoData);
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

	public void init(ServletConfig config) {
		// empty
	}

	private byte[] digestPhoto(String digestAlgoName, byte[] photoFile) {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(digestAlgoName);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("digest error: " + e.getMessage(), e);
		}
		return messageDigest.digest(photoFile);
	}

	private void verifySignature(String signatureAlgoName, byte[] signatureData, PublicKey publicKey,
								 HttpServletRequest request, byte[]... data) throws ServletException {
		Signature signature;
		try {
			signature = Signature.getInstance(signatureAlgoName);
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
			boolean result = signature.verify(signatureData);
			if (!result) {
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

}
