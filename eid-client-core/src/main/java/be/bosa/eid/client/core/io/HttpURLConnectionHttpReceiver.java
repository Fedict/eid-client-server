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

import be.bosa.eid.client_server.shared.protocol.HttpReceiver;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Implementation of an {@link HttpReceiver} based on the {@link HttpURLConnection}.
 *
 * @author Frank Cornelis
 */
public class HttpURLConnectionHttpReceiver implements HttpReceiver {

	private final HttpURLConnection connection;

	/**
	 * Main constructor.
	 */
	public HttpURLConnectionHttpReceiver(HttpURLConnection connection) {
		this.connection = connection;
	}

	@Override
	public byte[] getBody() {
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			copy(connection.getInputStream(), outputStream);
			return outputStream.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage());
		}
	}

	private static void copy(InputStream input, OutputStream output) throws IOException {
		byte[] buffer = new byte[1024];
		int n = input.read(buffer);
		while (n != -1) {
			output.write(buffer, 0, n);
			n = input.read(buffer);
		}
	}

	@Override
	public List<String> getHeaderNames() {
		return connection.getHeaderFields().keySet().stream()
				.filter(Objects::nonNull)
				.collect(Collectors.toList());
	}

	@Override
	public String getHeaderValue(String headerName) {
		return connection.getHeaderField(headerName);
	}

	@Override
	public boolean isSecure() {
		String host = connection.getURL().getHost();
		String protocol = connection.getURL().getProtocol();
		return "localhost".equals(host) || "https".equals(protocol);
	}
}