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

package be.fedict.eid.applet.service.signer;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;

/**
 * Interface for temporary data storage.
 *
 * @author Frank Cornelis
 */
public interface TemporaryDataStorage {

	/**
	 * Gives back the temporary output stream that can be used for data storage.
	 */
	OutputStream getTempOutputStream();

	/**
	 * Gives back the temporary input stream for retrieval of the previously
	 * stored data.
	 */
	InputStream getTempInputStream();

	/**
	 * Stores an attribute to the temporary data storage.
	 */
	void setAttribute(String attributeName, Serializable attributeValue);

	/**
	 * Retrieves an attribute from the temporary data storage.
	 */
	Serializable getAttribute(String attributeName);
}
