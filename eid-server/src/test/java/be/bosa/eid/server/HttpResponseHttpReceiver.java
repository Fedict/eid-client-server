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

import be.bosa.eid.client_server.shared.protocol.HttpReceiver;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class HttpResponseHttpReceiver implements HttpReceiver {

	private final HttpResponse httpResponse;

	public HttpResponseHttpReceiver(HttpResponse httpResponse) {
		this.httpResponse = httpResponse;
	}

	public byte[] getBody() {
		try {
			return EntityUtils.toByteArray(httpResponse.getEntity());
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
	}

	public List<String> getHeaderNames() {
		return Arrays.stream(httpResponse.getAllHeaders())
				.map(Header::getName)
				.collect(Collectors.toList());
	}

	public String getHeaderValue(String headerName) {
		return httpResponse.getFirstHeader(headerName).getValue();
	}

	public boolean isSecure() {
		return true;
	}
}
