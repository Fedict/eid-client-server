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

import be.bosa.eid.server.dto.Mapping;
import be.bosa.eid.server.dto.MapsTo;
import be.bosa.eid.server.impl.tlv.TlvField;
import be.bosa.eid.server.spi.AddressDTO;

import java.io.Serializable;

/**
 * Holds all the fields within the eID address file. The nationality can be
 * found in the eID identity file.
 *
 * @author Frank Cornelis
 * @see Identity
 */
public class Address implements Serializable {

	@TlvField(1)
	@Mapping(@MapsTo(AddressDTO.class))
	public String streetAndNumber;

	@TlvField(2)
	@Mapping(@MapsTo(AddressDTO.class))
	public String zip;

	@TlvField(3)
	@Mapping(@MapsTo(value = AddressDTO.class, field = "city"))
	public String municipality;

	/*
	 * We're also providing getters to make this class more useful within web
	 * frameworks like JBoss Seam.
	 */

	public String getStreetAndNumber() {
		return this.streetAndNumber;
	}

	public String getZip() {
		return this.zip;
	}

	public String getMunicipality() {
		return this.municipality;
	}
}
