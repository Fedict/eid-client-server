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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Authentication Challenge. Manages challenge freshness and randomness.
 *
 * @author Frank Cornelis
 */
public class AuthenticationChallenge implements Serializable {

	public static final String AUTHN_CHALLENGE_SESSION_ATTRIBUTE = AuthenticationChallenge.class.getName();

	private static final Log LOG = LogFactory.getLog(AuthenticationChallenge.class);

	/**
	 * The default maximum allowed maturity of the challenge in milliseconds.
	 */
	public static final long DEFAULT_MAX_MATURITY = 1000 * 60 * 5;

	private final byte[] challenge;

	private final Date timestamp;

	private static final SecureRandom secureRandom;

	static {
		secureRandom = new SecureRandom();
	}

	private AuthenticationChallenge() {
		/*
		 * Since SHA-1 is 20 bytes, we also take 20 here. More bytes wouldn't
		 * bring us anything.
		 */
		this.challenge = new byte[20];
		secureRandom.nextBytes(this.challenge);

		this.timestamp = new Date();
	}

	/**
	 * Generates a challenge and stores it in the given HTTP session for later
	 * consumption.
	 *
	 * @return the challenge.
	 */
	public static byte[] generateChallenge(HttpSession session) {
		AuthenticationChallenge authenticationChallenge = new AuthenticationChallenge();
		if (session.getAttribute(AUTHN_CHALLENGE_SESSION_ATTRIBUTE) != null) {
			LOG.warn("overwriting a previous authentication challenge");
		}
		session.setAttribute(AUTHN_CHALLENGE_SESSION_ATTRIBUTE, authenticationChallenge);
		return authenticationChallenge.getChallenge();
	}

	private byte[] getChallenge() {
		/*
		 * This method indeed is private. We want controlled consumption of the
		 * authentication challenge.
		 */
		return this.challenge;
	}

	private Date getTimestamp() {
		return this.timestamp;
	}

	/**
	 * Gives back the authentication challenge. This challenge is checked for
	 * freshness and can be consumed only once.
	 */
	public static byte[] getAuthnChallenge(HttpSession session, Long maxMaturity) {
		AuthenticationChallenge authenticationChallenge = (AuthenticationChallenge) session
				.getAttribute(AUTHN_CHALLENGE_SESSION_ATTRIBUTE);
		if (authenticationChallenge == null) {
			throw new SecurityException("no challenge in session");
		}
		session.removeAttribute(AUTHN_CHALLENGE_SESSION_ATTRIBUTE);
		Date now = new Date();
		if (maxMaturity == null) {
			maxMaturity = DEFAULT_MAX_MATURITY;
		}
		long dt = now.getTime() - authenticationChallenge.getTimestamp().getTime();
		if (dt > maxMaturity) {
			throw new SecurityException("maximum challenge maturity reached");
		}
		return authenticationChallenge.getChallenge();
	}

	/**
	 * Gives back the authentication challenge. This challenge is checked for
	 * freshness and can be consumed only once.
	 */
	public static byte[] getAuthnChallenge(HttpSession session) {
		return getAuthnChallenge(session, null);
	}
}
