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

package be.bosa.eid.server.impl;

import be.bosa.eid.server.Address;
import be.bosa.eid.server.EIdData;
import be.bosa.eid.server.Identity;
import be.bosa.eid.server.VcardServlet;
import be.bosa.eid.server.util.VcardLight;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;

/**
 * vCard generator for eID identity data. The implementation is using a "light"
 * implementation
 *
 * @author Bart Hanssens
 * @see VcardServlet
 */
public class VcardGenerator {
	private static final Log LOG = LogFactory.getLog(VcardGenerator.class);

	/**
	 * Generate vCard using data from the eID card
	 *
	 * @param eIdData ID data retrieved from eID card
	 * @return vCard as raw bytes
	 */
	public byte[] generateVcard(EIdData eIdData) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		VcardLight vcard = new VcardLight(baos);
		vcard.open();

		if (eIdData != null && eIdData.getIdentity() != null) {
			Identity identity = eIdData.getIdentity();

			vcard.addName(identity.firstName, identity.middleName, identity.name);

			if (eIdData.getAddress() != null) {
				Address address = eIdData.getAddress();
				vcard.addAddress(address.streetAndNumber, address.zip, address.municipality);
			} else {
				LOG.debug("no address");
			}
			vcard.addBorn(identity.dateOfBirth.getTime());

			if (eIdData.getPhoto() != null) {
				byte[] photoData = eIdData.getPhoto();
				vcard.addImage(photoData);
			} else {
				LOG.debug("no photo");
			}
		}
		vcard.close();

		return baos.toByteArray();
	}
}
