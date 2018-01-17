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

import be.bosa.eid.client_server.shared.message.AuthSignResponseMessage;
import be.bosa.eid.client_server.shared.message.FinishedMessage;
import be.bosa.eid.server.impl.AuthenticationSignatureContextImpl;
import be.bosa.eid.server.impl.ServiceLocator;
import be.bosa.eid.server.spi.AuthenticationSignatureContext;
import be.bosa.eid.server.spi.AuthenticationSignatureService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * Message handler for authentication signature response messages.
 *
 * @author Frank Cornelis
 */
@HandlesMessage(AuthSignResponseMessage.class)
public class AuthSignResponseMessageHandler implements MessageHandler<AuthSignResponseMessage> {

	private static final Log LOG = LogFactory.getLog(AuthSignResponseMessageHandler.class);

	@InitParam(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuthenticationSignatureService> authenticationSignatureServiceLocator;

	public Object handleMessage(AuthSignResponseMessage message, Map<String, String> httpHeaders,
								HttpServletRequest request, HttpSession session) throws ServletException {
		LOG.debug("handleMessage");

		byte[] signatureValue = message.signatureValue;

		AuthenticationSignatureService authenticationSignatureService =
				this.authenticationSignatureServiceLocator.locateService();
		AuthenticationSignatureContext authenticationSignatureContext = new AuthenticationSignatureContextImpl(session);
		authenticationSignatureService.postSign(signatureValue, null, authenticationSignatureContext);

		return new FinishedMessage();
	}

	public void init(ServletConfig config) {
		LOG.debug("init");
	}
}
