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

import be.fedict.eid.applet.service.signer.KeyInfoKeySelector;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * ODF Signature Verifier.
 *
 * @author fcorneli
 */
public class ODFSignatureVerifier {

	private static final Log LOG = LogFactory.getLog(ODFSignatureVerifier.class);

	private ODFSignatureVerifier() {
		super();
	}

	/**
	 * Checks whether the ODF document available via the given URL has been
	 * signed.
	 */
	public static boolean hasOdfSignature(URL odfUrl) throws IOException, ParserConfigurationException, SAXException,
			MarshalException,
			XMLSignatureException {
		List<X509Certificate> signers = getSigners(odfUrl);
		return !signers.isEmpty();
	}

	/**
	 * return list of signers for the document available via the given URL.
	 *
	 * @return list of X509 certificates
	 */
	public static List<X509Certificate> getSigners(URL odfUrl)
			throws IOException, ParserConfigurationException, SAXException, MarshalException, XMLSignatureException {
		List<X509Certificate> signers = new LinkedList<>();
		if (null == odfUrl) {
			throw new IllegalArgumentException("odfUrl is null");
		}
		ZipInputStream odfZipInputStream = new ZipInputStream(odfUrl.openStream());
		ZipEntry zipEntry;

		while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
			if (ODFUtil.isSignatureFile(zipEntry)) {
				Document documentSignatures = ODFUtil.loadDocument(odfZipInputStream);
				NodeList signatureNodeList = documentSignatures.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

				for (int idx = 0; idx < signatureNodeList.getLength(); idx++) {
					Node signatureNode = signatureNodeList.item(idx);
					X509Certificate signer = getVerifiedSignatureSigner(odfUrl, signatureNode);
					if (null == signer) {
						LOG.debug("JSR105 says invalid signature");
					} else {
						signers.add(signer);
					}
				}
				return signers;
			}
		}
		LOG.debug("no signature file present");
		return signers;
	}

	private static X509Certificate getVerifiedSignatureSigner(URL odfUrl, Node signatureNode)
			throws MarshalException, XMLSignatureException {
		if (null == odfUrl) {
			throw new IllegalArgumentException("odfUrl is null");
		}
		KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
		DOMValidateContext domValidateContext = new DOMValidateContext(keySelector, signatureNode);
		ODFURIDereferencer dereferencer = new ODFURIDereferencer(odfUrl);
		domValidateContext.setURIDereferencer(dereferencer);

		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance();
		LOG.debug("java version: " + System.getProperty("java.version"));
		/*
		 * Requires Java 6u10 because of a bug. See also:
		 * http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6696582
		 */
		XMLSignature xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);
		boolean validity = xmlSignature.validate(domValidateContext);
		if (!validity) {
			LOG.debug("invalid signature");
			return null;
		}
		// TODO: check what has been signed.

		X509Certificate signer = keySelector.getCertificate();
		if (null == signer) {
			throw new IllegalStateException("signer X509 certificate is null");
		}
		LOG.debug("signer: " + signer.getSubjectX500Principal());
		return signer;
	}

	/**
	 * Checks whether the document available on the given URL is an ODF document
	 * or not.
	 */
	public static boolean isODF(URL url) throws IOException {
		InputStream resStream = ODFUtil.findDataInputStream(url.openStream(), ODFUtil.MIMETYPE_FILE);
		if (null == resStream) {
			/*
			 * Some ODF implementations do not include a mimetype file TODO: try
			 * harder to check if a file is ODF or not
			 */
			LOG.debug("mimetype stream not found in ODF package");
			return false;
		}
		String mimetypeContent = IOUtils.toString(resStream, "UTF-8");
		return mimetypeContent.startsWith(ODFUtil.MIMETYPE_START);
	}
}
