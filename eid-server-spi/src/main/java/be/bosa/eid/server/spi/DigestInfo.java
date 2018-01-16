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

package be.bosa.eid.server.spi;

import java.io.Serializable;

/**
 * Digest Information data transfer class.
 *
 * @author Frank Cornelis
 */
public class DigestInfo implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * Main constructor.
	 */
	public DigestInfo(byte[] digestValue, String digestAlgo, String description) {
		this.digestValue = digestValue;
		this.digestAlgo = digestAlgo;
		this.description = description;
	}

	public final byte[] digestValue;

	public final String description;

	public final String digestAlgo;
}
