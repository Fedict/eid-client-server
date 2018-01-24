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

package be.bosa.eid.server.impl;

import be.bosa.eid.client_server.shared.protocol.ProtocolState;
import be.bosa.eid.client_server.shared.protocol.ProtocolStateListener;
import be.bosa.eid.server.impl.handler.AuthenticationDataMessageHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Protocol state listener that manages the cleanup of session attributes.
 * <p>
 * <p>
 * Removes old identity data from the session. In case something goes wrong with
 * the new identity processing we don't want to end up with a web application
 * that thinks that the citizen performed a successful identification.
 * </p>
 *
 * @author Frank Cornelis
 */
public class CleanSessionProtocolStateListener implements ProtocolStateListener {

	private static final Log LOG = LogFactory.getLog(CleanSessionProtocolStateListener.class);

	private final HttpSession httpSession;

	/**
	 * Main constructor.
	 */
	public CleanSessionProtocolStateListener(HttpServletRequest request) {
		this.httpSession = request.getSession();
	}

	public void protocolStateTransition(ProtocolState newProtocolState) {
		if (newProtocolState == ProtocolState.AUTHENTICATE) {
			LOG.debug("cleaning up the authn session attributes...");
			this.httpSession.removeAttribute(AuthenticationDataMessageHandler.AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE);
		}
	}

	public void startProtocolRun() {
	}

	public void stopProtocolRun() {
	}
}
