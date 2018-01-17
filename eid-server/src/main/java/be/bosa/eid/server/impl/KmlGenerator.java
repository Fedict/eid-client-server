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
import be.bosa.eid.server.KmlServlet;
import be.bosa.eid.server.util.KmlLight;
import be.bosa.eid.server.util.KmlLightDocument;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;

/**
 * KML generator for eID identity data. The implementation is using a "light"
 * implementation
 *
 * @author Bart Hanssens
 * @see KmlServlet
 */
public class KmlGenerator {
	private static final Log LOG = LogFactory.getLog(KmlGenerator.class);

	/**
	 * Generate zipped KML (.kmz) using data from the eID card
	 *
	 * @param eIdData ID data retrieved from eID card
	 * @return KMZ as raw bytes
	 */
	public byte[] generateKml(EIdData eIdData) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		KmlLight kml = new KmlLight(baos);
		KmlLightDocument doc = new KmlLightDocument();

		String htmlDescription = "";

		if (eIdData != null && eIdData.getIdentity() != null) {
			Identity identity = eIdData.getIdentity();

			if (eIdData.getPhoto() != null) {
				byte[] photoData = eIdData.getPhoto();
				kml.addImage(photoData);
				htmlDescription += "<img src='photo.jpg' align='left'>";
			} else {
				LOG.debug("no photo");
			}

			Element elName = doc.createName(identity.firstName + " " + identity.name);

			/* name */
			htmlDescription += identity.firstName + " ";
			if (identity.middleName != null) {
				htmlDescription += identity.middleName + " ";
			}
			htmlDescription += identity.name;
			htmlDescription += "<br/>";

			/* nationality */
			htmlDescription += identity.nationality;
			htmlDescription += "<br/>";

			/* day of birth */
			SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
			String birthday = formatter.format(identity.dateOfBirth.getTime());
			htmlDescription += "(°" + birthday + ", " + identity.placeOfBirth + ")";
			htmlDescription += "<br/>";

			/* validity of the card */
			Element elValid = null;

			if (identity.cardValidityDateBegin != null) {
				elValid = doc.createTimespan(identity.cardValidityDateBegin.getTime(),
						identity.cardValidityDateEnd.getTime());
			} else {
				LOG.debug("card validity begin date is unknown");
			}

			/* citizen's address */
			Element elAddress = null;

			if (eIdData.getAddress() != null) {
				Address address = eIdData.getAddress();

				/*
				 * not needed, or it will appear twice in GoogleEarth
				 * htmlDescription += address.streetAndNumber + ", " +
				 * address.zip + " " + address.municipality; htmlDescription +=
				 * "<br/>";
				 */
				elAddress = doc.createAddress(address.streetAndNumber, address.municipality, address.zip);
			} else {
				LOG.debug("no address");
			}

			Element elDescription = doc.createDescriptionNode(htmlDescription);
			doc.addPlacemark(elName, elAddress, elDescription, elValid);
		}
		kml.addKmlFile(doc.getDocumentAsBytes());
		kml.close();

		return baos.toByteArray();
	}
}
