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


import be.bosa.eid.client_server.shared.protocol.HttpTransmitter;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;

public class PostMethodHttpTransmitter implements HttpTransmitter {

	private final HttpPost httpPost;

	public PostMethodHttpTransmitter(HttpPost httpPost) {
		this.httpPost = httpPost;
	}

	public void addHeader(String headerName, String headerValue) {
		httpPost.addHeader(headerName, headerValue);
	}

	public boolean isSecure() {
		return httpPost.getURI().getScheme().startsWith("https");
	}

	public void setBody(byte[] bodyValue) {
		HttpEntity entity = new ByteArrayEntity(bodyValue);
		httpPost.setEntity(entity);
	}

}
