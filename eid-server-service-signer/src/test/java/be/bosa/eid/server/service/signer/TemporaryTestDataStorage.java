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

package be.bosa.eid.server.service.signer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

class TemporaryTestDataStorage implements TemporaryDataStorage {

	private ByteArrayOutputStream outputStream;

	private Map<String, Serializable> attributes;

	public TemporaryTestDataStorage() {
		this.outputStream = new ByteArrayOutputStream();
		this.attributes = new HashMap<>();
	}

	public InputStream getTempInputStream() {
		byte[] data = this.outputStream.toByteArray();
		return new ByteArrayInputStream(data);
	}

	public OutputStream getTempOutputStream() {
		return this.outputStream;
	}

	public Serializable getAttribute(String attributeName) {
		return this.attributes.get(attributeName);
	}

	public void setAttribute(String attributeName, Serializable attributeValue) {
		this.attributes.put(attributeName, attributeValue);
	}
}