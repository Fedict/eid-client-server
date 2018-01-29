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
import be.bosa.eid.client_server.shared.message.FileDigestsDataMessage;
import be.bosa.eid.client_server.shared.message.FinishedMessage;
import be.bosa.eid.client_server.shared.message.SignRequestMessage;
import be.bosa.eid.server.impl.ServiceLocator;
import be.bosa.eid.server.spi.AuthorizationException;
import be.bosa.eid.server.spi.DigestInfo;
import be.bosa.eid.server.spi.IdentityRequest;
import be.bosa.eid.server.spi.IdentityService;
import be.bosa.eid.server.spi.SignatureService;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Message handler for file digests data messages.
 *
 * @author Frank Cornelis
 */
@HandlesMessage(FileDigestsDataMessage.class)
public class FileDigestsDataMessageHandler implements MessageHandler<FileDigestsDataMessage> {

	@InitParam(HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(HelloMessageHandler.REMOVE_CARD_INIT_PARAM_NAME)
	private boolean removeCard;

	@InitParam(HelloMessageHandler.LOGOFF_INIT_PARAM_NAME)
	private boolean logoff;

	@InitParam(HelloMessageHandler.REQUIRE_SECURE_READER_INIT_PARAM_NAME)
	private boolean requireSecureReader;

	@InitParam(HelloMessageHandler.IDENTITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityService> identityServiceLocator;

	public Object handleMessage(FileDigestsDataMessage message, Map<String, String> httpHeaders,
								HttpServletRequest request, HttpSession session) throws ServletException {
		List<DigestInfo> fileDigestInfos = new LinkedList<>();

		List<String> messageFileDigestInfos = message.fileDigestInfos;
		Iterator<String> messageIterator = messageFileDigestInfos.iterator();
		while (messageIterator.hasNext()) {
			String digestAlgo = messageIterator.next();
			String hexDigestValue = messageIterator.next();
			String description = messageIterator.next();
			byte[] digestValue;
			try {
				digestValue = Hex.decodeHex(hexDigestValue.toCharArray());
			} catch (DecoderException e) {
				throw new ServletException("digest value decode error: " + e.getMessage(), e);
			}
			fileDigestInfos.add(new DigestInfo(digestValue, digestAlgo, description));
		}

		// TODO DRY refactor: is a copy-paste from HelloMessageHandler
		SignatureService signatureService = this.signatureServiceLocator.locateService();

		DigestInfo digestInfo;
		try {
			digestInfo = signatureService.preSign(getRequestId(session), fileDigestInfos, null, null, null, null);
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
}
