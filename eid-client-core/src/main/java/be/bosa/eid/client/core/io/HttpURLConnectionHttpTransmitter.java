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

package be.bosa.eid.client.core.io;

import be.bosa.eid.client_server.shared.protocol.HttpTransmitter;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;

/**
 * Implementation of an {@link HttpTransmitter} using {@link HttpURLConnection}.
 *
 * @author Frank Cornelis
 */
public class HttpURLConnectionHttpTransmitter implements HttpTransmitter {

	private final HttpURLConnection connection;

	/**
	 * Main constructor.
	 */
	public HttpURLConnectionHttpTransmitter(HttpURLConnection connection) {
		this.connection = connection;

		this.connection.setUseCaches(false);
		this.connection.setAllowUserInteraction(false);
		this.connection.setRequestProperty("Content-Type", "application/octet-stream");
		this.connection.setChunkedStreamingMode(1);
		this.connection.setDoInput(true);
		this.connection.setDoOutput(true);

		try {
			this.connection.setRequestMethod("POST");
		} catch (ProtocolException e) {
			throw new RuntimeException("protocol error: " + e.getMessage(), e);
		}
		
	}

	@Override
	public void addHeader(String headerName, String headerValue) {
		connection.setRequestProperty(headerName, headerValue);
	}

	@Override
	public void setBody(byte[] bodyValue) {
		try {
			connection.setChunkedStreamingMode(bodyValue.length);

			OutputStream connectionOutputStream = connection.getOutputStream();
			connectionOutputStream.write(bodyValue);
			connectionOutputStream.close();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
	}

	@Override
	public boolean isSecure() {
		String host = connection.getURL().getHost();
		String protocol = connection.getURL().getProtocol();
		return "localhost".equals(host) || "https".equals(protocol);
	}
}
