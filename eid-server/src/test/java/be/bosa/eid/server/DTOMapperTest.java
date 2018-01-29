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

import be.bosa.eid.server.dto.DTOMapper;
import be.bosa.eid.server.spi.AddressDTO;
import be.bosa.eid.server.spi.IdentityDTO;
import org.junit.Test;

import java.util.GregorianCalendar;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for Data Transfer Object Mapper implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class DTOMapperTest {

	@Test
	public void testMapEmptyIdentity() {
		Identity identity = new Identity();

		IdentityDTO result = new DTOMapper().map(identity, IdentityDTO.class);

		assertNotNull(result);
	}

	@Test
	public void testMapIdentity() {
		Identity identity = new Identity();
		identity.firstName = "hello-world";
		identity.name = "test-name";
		identity.cardNumber = "card-number";
		identity.chipNumber = "chip-number";
		identity.dateOfBirth = new GregorianCalendar();
		identity.placeOfBirth = "place-of-birth";
		identity.nationality = "nationality";
		identity.middleName = "middle-name";
		identity.nationalNumber = "national-number";
		identity.cardDeliveryMunicipality = "cardDeliveryMunicipality";
		identity.cardValidityDateBegin = new GregorianCalendar();
		identity.cardValidityDateEnd = new GregorianCalendar();
		identity.nobleCondition = "nobleCondition";
		identity.duplicate = "duplicate";
		identity.gender = Gender.MALE;

		IdentityDTO result = new DTOMapper().map(identity, IdentityDTO.class);

		assertNotNull(result);
		assertEquals("hello-world", result.firstName);
		assertEquals("test-name", result.name);
		assertEquals("card-number", result.cardNumber);
		assertEquals("chip-number", result.chipNumber);
		assertEquals(identity.dateOfBirth, result.dateOfBirth);
		assertEquals("place-of-birth", result.placeOfBirth);
		assertEquals("nationality", result.nationality);
		assertEquals("middle-name", result.middleName);
		assertEquals("national-number", result.nationalNumber);
		assertEquals("cardDeliveryMunicipality", result.cardDeliveryMunicipality);
		assertEquals(identity.cardValidityDateBegin, result.cardValidityDateBegin);
		assertEquals(identity.cardValidityDateEnd, result.cardValidityDateEnd);
		assertEquals("nobleCondition", result.nobleCondition);
		assertEquals("duplicate", result.duplicate);
		assertTrue(result.male);
		assertFalse(result.female);
	}

	@Test
	public void testMapFemaleIdentity() {
		Identity identity = new Identity();
		identity.gender = Gender.FEMALE;

		IdentityDTO result = new DTOMapper().map(identity, IdentityDTO.class);

		assertNotNull(result);
		assertFalse(result.male);
		assertTrue(result.female);
	}

	@Test
	public void testMapNull() {
		IdentityDTO result = new DTOMapper().map(null, IdentityDTO.class);

		// verify
		assertNull(result);
	}

	@Test
	public void testMapAddress() {
		Address address = new Address();
		address.streetAndNumber = "street 12345";
		address.zip = "1234";
		address.municipality = "city";

		AddressDTO result = new DTOMapper().map(address, AddressDTO.class);

		assertNotNull(result);
		assertEquals("street 12345", result.streetAndNumber);
		assertEquals("1234", result.zip);
		assertEquals("city", result.city);
	}
}
