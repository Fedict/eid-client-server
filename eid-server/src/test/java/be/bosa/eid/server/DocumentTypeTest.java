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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DocumentTypeTest {

	private static final Log LOG = LogFactory.getLog(DocumentTypeTest.class);

	@Test
	public void testkeys() {
		for (DocumentType documentType : DocumentType.values()) {
			LOG.debug("document type: " + documentType + ", key: " + documentType.getKey());
		}

		assertEquals(1, DocumentType.BELGIAN_CITIZEN.getKey());
		assertEquals(6, DocumentType.KIDS_CARD.getKey());
		assertEquals(16, DocumentType.FOREIGNER_E_PLUS.getKey());
		assertEquals("1", DocumentType.toString(new byte[] { '1' }));
		assertEquals("16", DocumentType.toString(new byte[] { '1', '6' }));
	}
}
