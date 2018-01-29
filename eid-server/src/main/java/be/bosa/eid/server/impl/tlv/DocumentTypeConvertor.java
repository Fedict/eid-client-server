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

package be.bosa.eid.server.impl.tlv;

import be.bosa.eid.server.DocumentType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Data Convertor for eID document type.
 *
 * @author Frank Cornelis
 */
public class DocumentTypeConvertor implements DataConvertor<DocumentType> {

	private static final Log LOG = LogFactory.getLog(DocumentTypeConvertor.class);

	public DocumentType convert(byte[] value) {
		LOG.debug("# bytes for document type field: " + value.length);
		/*
		 * More recent eID cards use 2 bytes per default for the document type
		 * field.
		 */
		DocumentType documentType = DocumentType.toDocumentType(value);
		if (documentType == null) {
			LOG.debug("unknown document type: " + DocumentType.toString(value));
		}
		return documentType;
	}
}
