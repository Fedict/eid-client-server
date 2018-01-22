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

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.util.DateUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * OpenOffice.org signature facet.
 *
 * @author fcorneli
 */
public class OpenOfficeSignatureFacet implements SignatureFacet {

	private static final Log LOG = LogFactory.getLog(OpenOfficeSignatureFacet.class);

	private final DigestAlgo digestAlgo;

	public OpenOfficeSignatureFacet(DigestAlgo digestAlgo) {
		this.digestAlgo = digestAlgo;
	}

	public void preSign(XMLSignatureFactory signatureFactory, Document document, String signatureId,
			List<X509Certificate> signingCertificateChain, List<Reference> references, List<XMLObject> objects)
					throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		LOG.debug("pre sign");

		Element dateElement = document.createElementNS("", "dc:date");
		dateElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:dc", "http://purl.org/dc/elements/1.1/");

		String now = DateUtil.getNowAsIso8601DateTimeStringWithTimeZoneUtc();
		now = now.substring(0, now.indexOf("Z"));
		LOG.debug("now: " + now);
		dateElement.setTextContent(now);

		String signaturePropertyId = "sign-prop-" + UUID.randomUUID().toString();
		List<XMLStructure> signaturePropertyContent = new LinkedList<>();
		signaturePropertyContent.add(new DOMStructure(dateElement));
		SignatureProperty signatureProperty = signatureFactory.newSignatureProperty(signaturePropertyContent,
				"#" + signatureId, signaturePropertyId);

		List<XMLStructure> objectContent = new LinkedList<>();
		List<SignatureProperty> signaturePropertiesContent = new LinkedList<>();
		signaturePropertiesContent.add(signatureProperty);
		SignatureProperties signatureProperties = signatureFactory.newSignatureProperties(signaturePropertiesContent,
				null);
		objectContent.add(signatureProperties);

		objects.add(signatureFactory.newXMLObject(objectContent, null, null, null));

		DigestMethod digestMethod = signatureFactory.newDigestMethod(this.digestAlgo.getXmlAlgoId(), null);
		Reference reference = signatureFactory.newReference("#" + signaturePropertyId, digestMethod);
		references.add(reference);
	}

	public void postSign(Element signatureElement, List<X509Certificate> signingCertificateChain) {
		// empty
	}
}
