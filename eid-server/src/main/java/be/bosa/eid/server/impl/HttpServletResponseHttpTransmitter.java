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

import be.bosa.eid.client_server.shared.protocol.HttpTransmitter;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Implementation of a transport component using {@link HttpServletResponse}.
 *
 * @author Frank Cornelis
 */
public class HttpServletResponseHttpTransmitter implements HttpTransmitter {

	private final HttpServletResponse httpServletResponse;

	/**
	 * Main constructor.
	 */
	public HttpServletResponseHttpTransmitter(HttpServletResponse httpServletResponse) {
		this.httpServletResponse = httpServletResponse;
	}

	public void addHeader(String headerName, String headerValue) {
		this.httpServletResponse.addHeader(headerName, headerValue);
	}

	public void setBody(byte[] bodyValue) {
		try {
			ServletOutputStream outputStream = this.httpServletResponse.getOutputStream();
			outputStream.write(bodyValue);
			outputStream.close();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
	}

	public boolean isSecure() {
		/*
		 * We assume here that the request was already verified as being secure.
		 */
		return true;
	}
}
