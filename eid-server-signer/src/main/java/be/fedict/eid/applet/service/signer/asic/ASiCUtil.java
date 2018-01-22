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

package be.fedict.eid.applet.service.signer.asic;

import be.fedict.eid.applet.service.signer.odf.ODFUtil;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.ParserConfigurationException;
import java.util.zip.ZipEntry;

/**
 * Associated Signature Container utility class.
 *
 * @author Frank Cornelis
 */
public class ASiCUtil {

	public static String SIGNATURE_FILE = "META-INF/signatures.xml";

	public static String ASIC_NS = "http://uri.etsi.org/2918/v1.1.1#";

	public static String ASIC_NS_PREFIX = "asic";

	public static String SIGNATURE_ELEMENT = "XAdESSignatures";

	private ASiCUtil() {
		super();
	}

	public static boolean isSignatureZipEntry(ZipEntry zipEntry) {
		return zipEntry.getName().equals(SIGNATURE_FILE);
	}

	public static Document createNewSignatureDocument() throws ParserConfigurationException {
		Document document = ODFUtil.getNewDocument();
		Element rootElement = document.createElementNS(ASIC_NS, ASIC_NS_PREFIX + ":" + SIGNATURE_ELEMENT);
		rootElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:" + ASIC_NS_PREFIX, ASIC_NS);
		document.appendChild(rootElement);
		return document;
	}
}
