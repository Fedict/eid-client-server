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

import java.io.Serializable;

/**
 * Top-level eID data container.
 *
 * @author Frank Cornelis
 */
public class EIdData implements Serializable {

	public Identity identity;

	public Address address;

	public byte[] photo;

	public String identifier;

	public EIdCertsData certs;

	public Identity getIdentity() {
		return this.identity;
	}

	public Address getAddress() {
		return this.address;
	}

	public byte[] getPhoto() {
		return this.photo;
	}

	public String getIdentifier() {
		return this.identifier;
	}

	public EIdCertsData getCerts() {
		return this.certs;
	}
}
