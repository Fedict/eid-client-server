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


import be.bosa.eid.server.spi.AuthenticationSignatureContext;

import javax.servlet.http.HttpSession;

/**
 * Implementation of the {@link AuthenticationSignatureContext}.
 *
 * @author Frank Cornelis
 */
public class AuthenticationSignatureContextImpl implements AuthenticationSignatureContext {

	private final HttpSession httpSession;

	private static final String PREFIX = AuthenticationSignatureContextImpl.class.getName() + ".";

	/**
	 * Main constructor.
	 */
	public AuthenticationSignatureContextImpl(HttpSession httpSession) {
		this.httpSession = httpSession;
	}

	public void store(String name, Object object) {
		String finalName = getFinalName(name);
		this.httpSession.setAttribute(finalName, object);
	}

	public Object load(String name) {
		String finalName = getFinalName(name);
		return this.httpSession.getAttribute(finalName);
	}

	private String getFinalName(String name) {
		return PREFIX + name;
	}
}
