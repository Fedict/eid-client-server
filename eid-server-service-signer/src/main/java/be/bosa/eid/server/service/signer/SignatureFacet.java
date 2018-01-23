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

package be.bosa.eid.server.service.signer;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * JSR105 Signature Facet interface.
 *
 * @author Frank Cornelis
 */
public interface SignatureFacet {

	/**
	 * This method is being invoked by the XML signature service engine during
	 * pre-sign phase. Via this method a signature facet implementation can add
	 * signature facets to an XML signature.
	 *
	 * @param signingCertificateChain the optional signing certificate chain
	 */
	void preSign(XMLSignatureFactory signatureFactory, Document document, String signatureId,
				 List<X509Certificate> signingCertificateChain, List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException;

	/**
	 * This method is being invoked by the XML signature service engine during
	 * the post-sign phase. Via this method a signature facet can extend the XML
	 * signatures with for example key information.
	 */
	void postSign(Element signatureElement, List<X509Certificate> signingCertificateChain);
}
