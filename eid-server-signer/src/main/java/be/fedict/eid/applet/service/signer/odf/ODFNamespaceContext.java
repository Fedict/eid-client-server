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
package be.fedict.eid.applet.service.signer.odf;

import javax.xml.namespace.NamespaceContext;
import java.util.Iterator;

/**
 * Helper class, only needed for XPath purposes in ODFUtil
 *
 * @author Bart Hanssens
 */
public class ODFNamespaceContext implements NamespaceContext {
	/* Not required for XPath processing */
	public String getPrefix(String uri) {
		throw new UnsupportedOperationException();
	}

	public Iterator getPrefixes(String uri) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get namespace URI for a given prefix
	 */
	public String getNamespaceURI(String prefix) {
		/*
		 * Currently, draw: and xlink are the only prefixes we care about, since
		 * they are used to link to OLE objects
		 */
		if ("draw".equals(prefix)) {
			return "urn:oasis:names:tc:opendocument:xmlns:drawing:1.0";
		}
		if ("xlink".equals(prefix)) {
			return "http://www.w3.org/1999/xlink";
		}
		return "";
	}
}
