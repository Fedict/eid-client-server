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

import be.bosa.eid.server.AppletServiceServlet;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * Interface for a message handler. A message handler has the same lifecycle as
 * the {@link AppletServiceServlet} dispatcher servlet.
 *
 * @param <T> the message type.
 * @author Frank Cornelis
 * @see AppletServiceServlet
 */
public interface MessageHandler<T> {

	/**
	 * Handles the given message. Returns the response message to send back,
	 * this can be <code>null</code>.
	 *
	 * @param request     the request from which the body already may be consumed.
	 * @return the optional response message to send back.
	 */
	Object handleMessage(T message, Map<String, String> httpHeaders, HttpServletRequest request, HttpSession session)
			throws ServletException;

	/**
	 * Initializes this message handler.
	 */
	void init(ServletConfig config) throws ServletException;
}
