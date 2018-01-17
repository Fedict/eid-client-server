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

import be.bosa.eid.client_server.shared.protocol.HttpReceiver;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

/**
 * HttpServletRequest based HTTP receiver.
 *
 * @author Frank Cornelis
 */
public class HttpServletRequestHttpReceiver implements HttpReceiver {

	private static final Log LOG = LogFactory.getLog(HttpServletRequestHttpReceiver.class);

	private final HttpServletRequest httpServletRequest;

	private final boolean skipSecureConnectionCheck;

	/**
	 * Main constructor.
	 * @param skipSecureConnectionCheck set to <code>true</code> to skip the check on a secure SSL
	 *                                  connection.
	 */
	public HttpServletRequestHttpReceiver(HttpServletRequest httpServletRequest, boolean skipSecureConnectionCheck) {
		this.httpServletRequest = httpServletRequest;
		this.skipSecureConnectionCheck = skipSecureConnectionCheck;
	}

	public byte[] getBody() {
		try {
			ServletInputStream inputStream = this.httpServletRequest.getInputStream();
			return IOUtils.toByteArray(inputStream);
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> getHeaderNames() {
		Enumeration headerNamesEnumeration = this.httpServletRequest.getHeaderNames();
		List<String> headerNames = new LinkedList<>();
		while (headerNamesEnumeration.hasMoreElements()) {
			String headerName = (String) headerNamesEnumeration.nextElement();
			headerNames.add(headerName);
		}
		return headerNames;
	}

	public String getHeaderValue(String headerName) {
		return this.httpServletRequest.getHeader(headerName);
	}

	public boolean isSecure() {
		String referrerHeader = this.httpServletRequest.getHeader("Referer");
		if (referrerHeader != null) {
			/*
			 * Only the eID Applet should be able to call our eID Applet
			 * Service.
			 */
			LOG.warn("Refered HTTP header should not be present");
			return false;
		}

		return this.skipSecureConnectionCheck || this.httpServletRequest.isSecure();
	}
}
