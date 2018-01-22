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

package test.unit.be.fedict.eid.applet.service.signer;

import be.fedict.eid.applet.service.signer.SignatureFacet;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

public class SignatureTestFacet implements SignatureFacet {

	private final List<String> uris;

	public SignatureTestFacet() {
		this.uris = new LinkedList<String>();
	}

	public void postSign(Element signatureElement, List<X509Certificate> signingCertificateChain) {
		// empty
	}

	public void preSign(XMLSignatureFactory signatureFactory, Document document, String signatureId,
						List<X509Certificate> signingCertificateChain, List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		DigestMethod digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA1, null);
		for (String uri : this.uris) {
			Reference reference = signatureFactory.newReference(uri, digestMethod);
			references.add(reference);
		}
	}

	public void addReferenceUri(String uri) {
		this.uris.add(uri);
	}
}
