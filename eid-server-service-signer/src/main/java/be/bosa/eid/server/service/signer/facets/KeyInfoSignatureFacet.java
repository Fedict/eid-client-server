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

package be.bosa.eid.server.service.signer.facets;

import be.bosa.eid.server.service.signer.SignatureFacet;
import be.bosa.eid.server.service.signer.util.DummyKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.jcp.xml.dsig.internal.dom.DOMKeyInfo;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.KeyException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

/**
 * Signature Facet implementation that adds ds:KeyInfo to the XML signature.
 *
 * @author Frank Cornelis
 */
public class KeyInfoSignatureFacet implements SignatureFacet {

	private static final Log LOG = LogFactory.getLog(KeyInfoSignatureFacet.class);

	private final boolean includeEntireCertificateChain;

	private final boolean includeIssuerSerial;

	private final boolean includeKeyValue;

	/**
	 * Main constructor.
	 */
	public KeyInfoSignatureFacet(boolean includeEntireCertificateChain, boolean includeIssuerSerial,
								 boolean includeKeyValue) {
		this.includeEntireCertificateChain = includeEntireCertificateChain;
		this.includeIssuerSerial = includeIssuerSerial;
		this.includeKeyValue = includeKeyValue;
	}

	public void postSign(Element signatureElement, List<X509Certificate> signingCertificateChain) {
		LOG.debug("postSign");

		/*
		 * Construct the ds:KeyInfo element using JSR 105.
		 */
		KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance("DOM", new XMLDSigRI());
		List<Object> x509DataObjects = new LinkedList<>();
		X509Certificate signingCertificate = signingCertificateChain.get(0);

		List<Object> keyInfoContent = new LinkedList<>();

		if (this.includeKeyValue) {
			KeyValue keyValue;
			try {
				keyValue = keyInfoFactory.newKeyValue(signingCertificate.getPublicKey());
			} catch (KeyException e) {
				throw new RuntimeException("key exception: " + e.getMessage(), e);
			}
			keyInfoContent.add(keyValue);
		}

		if (this.includeIssuerSerial) {
			x509DataObjects.add(keyInfoFactory.newX509IssuerSerial(
					signingCertificate.getIssuerX500Principal().toString(), signingCertificate.getSerialNumber()));
		}

		if (this.includeEntireCertificateChain) {
			x509DataObjects.addAll(signingCertificateChain);
		} else {
			x509DataObjects.add(signingCertificate);
		}

		if (!x509DataObjects.isEmpty()) {
			X509Data x509Data = keyInfoFactory.newX509Data(x509DataObjects);
			keyInfoContent.add(x509Data);
		}
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(keyInfoContent);
		DOMKeyInfo domKeyInfo = (DOMKeyInfo) keyInfo;

		XMLSignContext xmlSignContext = new DOMSignContext(new DummyKey(), signatureElement);

		try {
			domKeyInfo.marshal(keyInfo, xmlSignContext);
		} catch (MarshalException e) {
			throw new RuntimeException("marshall error: " + e.getMessage(), e);
		}
	}

	public void preSign(XMLSignatureFactory signatureFactory, Document document, String signatureId,
						List<X509Certificate> signingCertificateChain, List<Reference> references, List<XMLObject> objects) {
		// empty
	}

}
