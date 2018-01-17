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

package be.bosa.eid.server.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * A "light" implementation of a KML document
 *
 * @author Bart Hanssens
 */
public class KmlLightDocument {
	private static final Log LOG = LogFactory.getLog(KmlLightDocument.class);

	public static final String KML_NS = "http://www.opengis.net/kml/2.2";

	private Document docKml;

	/**
	 * Create a name, to be used as a label
	 *
	 * @param name name to be used
	 * @return name element
	 */
	public Element createName(String name) {
		Element elName = docKml.createElement("name");
		Text txtName = docKml.createTextNode(name);
		elName.appendChild(txtName);

		return elName;
	}

	/**
	 * Create a address. Note: it's up to the processing application to convert
	 * the address to (GPS) coordinates.
	 *
	 * @param street       street name and number
	 * @param municipality muncipality / city
	 * @param zip          zip code
	 * @return address element
	 */
	public Element createAddress(String street, String municipality, String zip) {
		/* Use google-style address, with empty "region" */
		String address = street + ", " + municipality + ", " + zip + ", " + ", Belgium";

		Element elAddress = docKml.createElement("address");
		Text txtAddress = docKml.createTextNode(address);
		elAddress.appendChild(txtAddress);

		return elAddress;
	}

	/**
	 * Create a description element, the description can contain HTML markup
	 *
	 * @param description text to be used
	 * @return element containing description
	 */
	public Element createDescriptionNode(String description) {
		Element elDescription = docKml.createElement("description");
		Text txtDescription = docKml.createCDATASection(description);
		elDescription.appendChild(txtDescription);

		return elDescription;
	}

	/**
	 * Create a timespan element
	 */
	public Element createTimespan(Date begin, Date end) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

		Element elTimespan = docKml.createElement("TimeSpan");
		if (begin != null) {
			Element elBegin = docKml.createElement("begin");
			elBegin.setTextContent(dateFormat.format(begin));
			elTimespan.appendChild(elBegin);
		}
		if (end != null) {
			Element elEnd = docKml.createElement("end");
			elEnd.setTextContent(dateFormat.format(end));
			elTimespan.appendChild(elEnd);
		}

		return elTimespan;
	}

	/**
	 * Create a placemark.
	 *
	 * @param name        the name (title)
	 * @param address     the address
	 * @param description the short description
	 * @param timespan    day of birth
	 */
	public void addPlacemark(Node name, Node address, Node description, Node timespan) {
		Element elPlacemark = docKml.createElement("Placemark");
		// elPlacemark.setAttribute("id", "1");

		elPlacemark.appendChild(name);

		if (address != null) {
			elPlacemark.appendChild(address);
		} else {
			LOG.debug("address is null");
		}

		elPlacemark.appendChild(description);

		if (timespan != null) {
			elPlacemark.appendChild(timespan);
		}
		docKml.getDocumentElement().appendChild(elPlacemark);
	}

	/**
	 * Get the raw KML bytes
	 *
	 * @return KML document
	 */
	public byte[] getDocumentAsBytes() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {
			TransformerFactory fact = TransformerFactory.newInstance();
			Transformer trans = fact.newTransformer();
			trans.transform(new DOMSource(docKml), new StreamResult(baos));
		} catch (Exception e) {
			throw new IOException(e);
		}
		return baos.toByteArray();
	}

	/**
	 * Constructor
	 */
	public KmlLightDocument() throws IOException {
		try {
			DocumentBuilderFactory fact = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = fact.newDocumentBuilder();

			docKml = builder.newDocument();
			Element elKml = docKml.createElement("kml");
			elKml.setAttribute("xmlns", KmlLightDocument.KML_NS);

			docKml.appendChild(elKml);
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
}
