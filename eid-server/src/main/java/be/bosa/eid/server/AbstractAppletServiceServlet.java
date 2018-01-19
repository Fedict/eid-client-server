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

import be.bosa.eid.client_server.shared.annotation.ResponsesAllowed;
import be.bosa.eid.client_server.shared.message.ClientServerProtocolMessageCatalog;
import be.bosa.eid.client_server.shared.protocol.ProtocolException;
import be.bosa.eid.client_server.shared.protocol.ProtocolStateMachine;
import be.bosa.eid.client_server.shared.protocol.Transport;
import be.bosa.eid.client_server.shared.protocol.Unmarshaller;
import be.bosa.eid.server.impl.CleanSessionProtocolStateListener;
import be.bosa.eid.server.impl.HttpServletProtocolContext;
import be.bosa.eid.server.impl.HttpServletRequestHttpReceiver;
import be.bosa.eid.server.impl.HttpServletResponseHttpTransmitter;
import be.bosa.eid.server.impl.RequestContext;
import be.bosa.eid.server.impl.handler.MessageHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * The eID applet service abstract Servlet. This abstract servlet is the basis
 * for the classic Java EE 5 AppletServiceServlet, and the Java EE 6 CDI based
 * version.
 *
 * @author Frank Cornelis
 */
public abstract class AbstractAppletServiceServlet extends HttpServlet {

	private static final Log LOG = LogFactory.getLog(AbstractAppletServiceServlet.class);

	private Unmarshaller unmarshaller;

	private static final String SKIP_SECURE_CONNECTION_CHECK_INIT_PARAM = "SkipSecureConnectionCheck";

	private boolean skipSecureConnectionCheck;

	public AbstractAppletServiceServlet() {
		super();
		LOG.debug("constructor");
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);

		LOG.debug("init");

		this.unmarshaller = new Unmarshaller(new ClientServerProtocolMessageCatalog());

		String skipSecureConnectionCheck = config.getInitParameter(SKIP_SECURE_CONNECTION_CHECK_INIT_PARAM);
		if (skipSecureConnectionCheck != null) {
			this.skipSecureConnectionCheck = Boolean.parseBoolean(skipSecureConnectionCheck);
			LOG.debug("skipping secure connection check: " + this.skipSecureConnectionCheck);
		}
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		LOG.debug("doGet");
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		out.println("<html>");
		out.println("<head><title>eID Applet Service</title></head>");
		out.println("<body>");
		out.println("<h1>eID Applet Service</h1>");
		out.println("<p>The eID Applet Service should not be accessed directly.</p>");
		out.println("</body></html>");
		out.close();
	}

	/**
	 * This method needs to be implemented by servlets that extend this abstract
	 * base servlet.
	 */
	protected abstract <T> MessageHandler<T> getMessageHandler(Class<T> messageClass);

	@SuppressWarnings("unchecked")
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException {
		LOG.debug("doPost");

		/*
		 * First retrieve the HTTP headers. The unmarshaller may digest the
		 * body, which makes it impossible to retrieve the headers afterwards.
		 */
		Map<String, String> httpHeaders = new HashMap<>();
		Enumeration<String> headerNamesEnum = request.getHeaderNames();
		while (headerNamesEnum.hasMoreElements()) {
			String headerName = headerNamesEnum.nextElement();
			httpHeaders.put(headerName, request.getHeader(headerName));
		}
		/*
		 * Incoming message unmarshaller.
		 */
		HttpServletRequestHttpReceiver httpReceiver = new HttpServletRequestHttpReceiver(request, this.skipSecureConnectionCheck);
		Object transferObject;
		transferObject = this.unmarshaller.receive(httpReceiver);

		/*
		 * Protocol state checker for incoming message.
		 */
		HttpServletProtocolContext protocolContext = new HttpServletProtocolContext(request);
		ProtocolStateMachine protocolStateMachine = new ProtocolStateMachine(protocolContext);
		CleanSessionProtocolStateListener cleanSessionProtocolStateListener = new CleanSessionProtocolStateListener(request);
		protocolStateMachine.addProtocolStateListener(cleanSessionProtocolStateListener);
		RequestContext requestContext = new RequestContext(request);
		protocolStateMachine.addProtocolStateListener(requestContext);
		try {
			protocolStateMachine.checkRequestMessage(transferObject);
		} catch (ProtocolException e) {
			throw new RuntimeException("Protocol error", e);
		}

		/*
		 * Message dispatcher
		 */
		Class<?> messageClass = transferObject.getClass();
		MessageHandler messageHandler = getMessageHandler(messageClass);
		if (messageHandler == null) {
			throw new ServletException("unsupported message");
		}
		HttpSession session = request.getSession();
		Object responseMessage = messageHandler.handleMessage(transferObject, httpHeaders, request, session);

		/*
		 * Check outgoing messages for protocol constraints.
		 */
		ResponsesAllowed responsesAllowedAnnotation = messageClass.getAnnotation(ResponsesAllowed.class);
		if (responsesAllowedAnnotation != null) {
			/*
			 * Make sure the message handlers respect the protocol.
			 */
			if (responseMessage == null) {
				throw new ServletException("null response message while @ResponsesAllowed constraint was set");
			}
			Class<?>[] responsesAllowed = responsesAllowedAnnotation.value();
			if (!isOfClass(responseMessage, responsesAllowed)) {
				throw new ServletException("response message type incorrect");
			}
		}

		/*
		 * Protocol state checker for outgoing message.
		 */
		protocolStateMachine.checkResponseMessage(transferObject, responseMessage);

		/*
		 * Marshall outgoing message.
		 */
		if (responseMessage != null) {
			HttpServletResponseHttpTransmitter httpTransmitter = new HttpServletResponseHttpTransmitter(response);
			Transport.transfer(responseMessage, httpTransmitter);
		}
	}

	private boolean isOfClass(Object object, Class<?>[] classes) {
		for (Class<?> clazz : classes) {
			if (clazz.equals(object.getClass())) {
				return true;
			}
		}
		return false;
	}
}
