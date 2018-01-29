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

package be.bosa.eid.server.dto;

import be.bosa.eid.server.Gender;

/**
 * Converts a gender field value to a female boolean value.
 *
 * @author Frank Cornelis
 */
public class GenderToFemaleValueConvertor implements ValueConvertor<Gender, Boolean> {

	public Boolean convert(Gender value) {
		return Gender.FEMALE == value;
	}
}
