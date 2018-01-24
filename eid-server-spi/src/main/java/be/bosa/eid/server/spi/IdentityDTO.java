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
import java.util.GregorianCalendar;

/**
 * Identity Data Transfer Object.
 *
 * @author Frank Cornelis
 */
public class IdentityDTO implements Serializable {

	public String cardNumber;
	public String chipNumber;
	public GregorianCalendar cardValidityDateBegin;
	public GregorianCalendar cardValidityDateEnd;
	public String cardDeliveryMunicipality;
	public String nationalNumber;
	public String name;
	public String firstName;
	public String middleName;
	public String nationality;
	public String placeOfBirth;
	public GregorianCalendar dateOfBirth;
	public boolean male;
	public boolean female;
	public String nobleCondition;
	public String duplicate;

	public String getCardNumber() {
		return cardNumber;
	}

	public String getChipNumber() {
		return chipNumber;
	}

	public GregorianCalendar getCardValidityDateBegin() {
		return cardValidityDateBegin;
	}

	public GregorianCalendar getCardValidityDateEnd() {
		return cardValidityDateEnd;
	}

	public String getCardDeliveryMunicipality() {
		return cardDeliveryMunicipality;
	}

	public String getNationalNumber() {
		return nationalNumber;
	}

	public String getName() {
		return name;
	}

	public String getFirstName() {
		return firstName;
	}

	public String getMiddleName() {
		return middleName;
	}

	public String getNationality() {
		return nationality;
	}

	public String getPlaceOfBirth() {
		return placeOfBirth;
	}

	public GregorianCalendar getDateOfBirth() {
		return dateOfBirth;
	}

	public boolean isMale() {
		return male;
	}

	public boolean isFemale() {
		return female;
	}

	public String getNobleCondition() {
		return nobleCondition;
	}

	public String getDuplicate() {
		return duplicate;
	}
}
