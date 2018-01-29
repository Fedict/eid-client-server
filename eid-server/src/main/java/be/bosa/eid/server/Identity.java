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

import be.bosa.eid.server.dto.GenderToFemaleValueConvertor;
import be.bosa.eid.server.dto.GenderToMaleValueConvertor;
import be.bosa.eid.server.dto.Mapping;
import be.bosa.eid.server.dto.MapsTo;
import be.bosa.eid.server.impl.tlv.ChipNumberDataConvertor;
import be.bosa.eid.server.impl.tlv.ConvertData;
import be.bosa.eid.server.impl.tlv.CountryOfProtectionDataConvertor;
import be.bosa.eid.server.impl.tlv.DateOfBirthDataConvertor;
import be.bosa.eid.server.impl.tlv.DateOfProtectionDataConvertor;
import be.bosa.eid.server.impl.tlv.DocumentTypeConvertor;
import be.bosa.eid.server.impl.tlv.GenderDataConvertor;
import be.bosa.eid.server.impl.tlv.SpecialOrganisationConvertor;
import be.bosa.eid.server.impl.tlv.SpecialStatusConvertor;
import be.bosa.eid.server.impl.tlv.TlvField;
import be.bosa.eid.server.impl.tlv.ValidityDateDataConvertor;
import be.bosa.eid.server.spi.IdentityDTO;

import java.io.Serializable;
import java.util.GregorianCalendar;

/**
 * Holds all fields within the eID identity file. The annotations are used by
 * the TLV parser to parse the identity file as stored in the eID card to an
 * object of this class.
 *
 * @author Frank Cornelis
 * @see Address
 * @see TlvField
 * @see ConvertData
 */
public class Identity implements Serializable {

	/*
	 * We implement serializable to allow this class to be used in distributed
	 * containers as defined in the Servlet v2.4 specification.
	 */
	@TlvField(1)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String cardNumber;

	@TlvField(2)
	@ConvertData(ChipNumberDataConvertor.class)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String chipNumber;

	@TlvField(3)
	@ConvertData(ValidityDateDataConvertor.class)
	@Mapping(@MapsTo(IdentityDTO.class))
	public GregorianCalendar cardValidityDateBegin;

	@TlvField(4)
	@ConvertData(ValidityDateDataConvertor.class)
	@Mapping(@MapsTo(IdentityDTO.class))
	public GregorianCalendar cardValidityDateEnd;

	@TlvField(5)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String cardDeliveryMunicipality;

	@TlvField(6)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String nationalNumber;

	@TlvField(7)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String name;

	@TlvField(8)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String firstName;

	@TlvField(9)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String middleName;

	@TlvField(10)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String nationality;

	@TlvField(11)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String placeOfBirth;

	@TlvField(12)
	@ConvertData(DateOfBirthDataConvertor.class)
	@Mapping(@MapsTo(IdentityDTO.class))
	public GregorianCalendar dateOfBirth;

	@TlvField(13)
	@ConvertData(GenderDataConvertor.class)
	@Mapping({@MapsTo(value = IdentityDTO.class, field = "male", convertor = GenderToMaleValueConvertor.class),
			@MapsTo(value = IdentityDTO.class, field = "female", convertor = GenderToFemaleValueConvertor.class)})
	public Gender gender;

	/**
	 * Optional Noble Condition.
	 */
	@TlvField(14)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String nobleCondition;

	@TlvField(15)
	@ConvertData(DocumentTypeConvertor.class)
	public DocumentType documentType;

	@TlvField(16)
	@ConvertData(SpecialStatusConvertor.class)
	public SpecialStatus specialStatus;

	@TlvField(17)
	public byte[] photoDigest;

	@TlvField(18)
	@Mapping(@MapsTo(IdentityDTO.class))
	public String duplicate;

	@TlvField(19)
	@ConvertData(SpecialOrganisationConvertor.class)
	public SpecialOrganisation specialOrganisation;

	@TlvField(20)
	public boolean memberOfFamily;

	@TlvField(21)
	public String dateAndCountryOfProtection;

	@TlvField(21)
	@ConvertData(DateOfProtectionDataConvertor.class)
	public GregorianCalendar dateOfProtection;

	@TlvField(21)
	@ConvertData(CountryOfProtectionDataConvertor.class)
	public String countryOfProtection;

	public String getCardNumber() {
		return this.cardNumber;
	}

	public String getChipNumber() {
		return this.chipNumber;
	}

	public GregorianCalendar getCardValidityDateBegin() {
		return this.cardValidityDateBegin;
	}

	public GregorianCalendar getCardValidityDateEnd() {
		return this.cardValidityDateEnd;
	}

	public String getCardDeliveryMunicipality() {
		return this.cardDeliveryMunicipality;
	}

	public String getNationalNumber() {
		return this.nationalNumber;
	}

	public String getName() {
		return this.name;
	}

	public String getFirstName() {
		return this.firstName;
	}

	public String getMiddleName() {
		return this.middleName;
	}

	public String getNationality() {
		return this.nationality;
	}

	public String getPlaceOfBirth() {
		return this.placeOfBirth;
	}

	public GregorianCalendar getDateOfBirth() {
		return this.dateOfBirth;
	}

	public Gender getGender() {
		return this.gender;
	}

	public String getNobleCondition() {
		return this.nobleCondition;
	}

	public DocumentType getDocumentType() {
		return this.documentType;
	}

	public byte[] getPhotoDigest() {
		return this.photoDigest;
	}

	public SpecialStatus getSpecialStatus() {
		return this.specialStatus;
	}

	public String getDuplicate() {
		return this.duplicate;
	}

	public boolean isMemberOfFamily() {
		return this.memberOfFamily;
	}

	public SpecialOrganisation getSpecialOrganisation() {
		return this.specialOrganisation;
	}

	public String getDateAndCountryOfProtection() {
		return this.dateAndCountryOfProtection;
	}

	public GregorianCalendar getDateOfProtection() {
		return this.dateOfProtection;
	}

	public String getCountryOfProtection() {
		return this.countryOfProtection;
	}

	@Override
	public String toString() {
		return "[" + this.name + " " + this.firstName + "]";
	}
}
