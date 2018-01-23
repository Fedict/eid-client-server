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

import be.bosa.eid.server.service.signer.ooxml.AbstractOOXMLSignatureService;
import be.bosa.eid.server.service.signer.ooxml.OOXMLProvider;
import be.bosa.eid.server.service.signer.ooxml.OOXMLSignatureVerifier;
import be.bosa.eid.server.spi.DigestInfo;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AbstractOOXMLSignatureServiceTest {

	private static final Log LOG = LogFactory.getLog(AbstractOOXMLSignatureServiceTest.class);

	@BeforeClass
	public static void setUp() {
		OOXMLProvider.install();
	}

	private static class OOXMLTestSignatureService extends AbstractOOXMLSignatureService {

		private final URL ooxmlUrl;

		private final TemporaryTestDataStorage temporaryDataStorage;

		private final ByteArrayOutputStream signedOOXMLOutputStream;

		public OOXMLTestSignatureService(URL ooxmlUrl) {
			super(DigestAlgo.SHA1);
			this.temporaryDataStorage = new TemporaryTestDataStorage();
			this.signedOOXMLOutputStream = new ByteArrayOutputStream();
			this.ooxmlUrl = ooxmlUrl;
		}

		@Override
		protected URL getOfficeOpenXMLDocumentURL() {
			return this.ooxmlUrl;
		}

		@Override
		protected OutputStream getSignedOfficeOpenXMLDocumentOutputStream() {
			return this.signedOOXMLOutputStream;
		}

		public byte[] getSignedOfficeOpenXMLDocumentData() {
			return this.signedOOXMLOutputStream.toByteArray();
		}

		@Override
		protected TemporaryDataStorage getTemporaryDataStorage() {
			return this.temporaryDataStorage;
		}
	}

	@Test
	public void testPreSign() throws Exception {
		// setup
		URL ooxmlUrl = AbstractOOXMLSignatureServiceTest.class.getResource("/hello-world-unsigned.docx");
		assertNotNull(ooxmlUrl);

		OOXMLTestSignatureService signatureService = new OOXMLTestSignatureService(ooxmlUrl);

		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		OffsetDateTime notBefore = OffsetDateTime.now();
		OffsetDateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = PkiTestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, new KeyUsage(KeyUsage.nonRepudiation));

		// operate
		DigestInfo digestInfo = signatureService.preSign(null, Collections.singletonList(certificate), null, null,
				null);

		// verify
		assertNotNull(digestInfo);
		LOG.debug("digest algo: " + digestInfo.digestAlgo);
		LOG.debug("digest description: " + digestInfo.description);
		assertEquals("Office OpenXML Document", digestInfo.description);
		assertNotNull(digestInfo.digestAlgo);
		assertNotNull(digestInfo.digestValue);

		TemporaryDataStorage temporaryDataStorage = signatureService.getTemporaryDataStorage();
		String preSignResult = IOUtils.toString(temporaryDataStorage.getTempInputStream(), "UTF-8");
		LOG.debug("pre-sign result: " + preSignResult);
		File tmpFile = File.createTempFile("ooxml-pre-sign-", ".xml");
		FileUtils.writeStringToFile(tmpFile, preSignResult, "UTF-8");
		LOG.debug("tmp pre-sign file: " + tmpFile.getAbsolutePath());
	}

	@Test
	public void testPostSign() throws Exception {
		sign("/hello-world-unsigned.docx");
	}

	@Test
	public void testSignOffice2010TechnicalPreview() throws Exception {
		sign("/hello-world-office-2010-technical-preview-unsigned.docx");
	}

	@Test
	public void testSignOffice2010() throws Exception {
		sign("/ms-office-2010.docx");
	}

	@Test
	public void testHyperlinkExample() throws Exception {
		sign("/hyperlink-example.docx");
	}

	@Test
	public void testSignTwice() throws Exception {
		sign("/hello-world-signed.docx", 2);
	}

	@Test
	public void testSignTwiceHere() throws Exception {
		File tmpFile = sign("/hello-world-unsigned.docx", 1);
		sign(tmpFile.toURI().toURL(), "CN=Test2", 2);
	}

	@Test
	public void testSignPowerpoint() throws Exception {
		sign("/hello-world-unsigned.pptx");
	}

	@Test
	public void testSignSpreadsheet() throws Exception {
		sign("/hello-world-unsigned.xlsx");
	}

	private void sign(String documentResourceName) throws Exception {
		sign(documentResourceName, 1);
	}

	private File sign(String documentResourceName, int signerCount) throws Exception {
		URL ooxmlUrl = AbstractOOXMLSignatureServiceTest.class.getResource(documentResourceName);
		return sign(ooxmlUrl, signerCount);
	}

	private File sign(URL ooxmlUrl, int signerCount) throws Exception {
		return sign(ooxmlUrl, "CN=Test", signerCount);
	}

	private File sign(URL ooxmlUrl, String signerDn, int signerCount) throws Exception {
		// setup
		assertNotNull(ooxmlUrl);

		OOXMLTestSignatureService signatureService = new OOXMLTestSignatureService(ooxmlUrl);

		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		OffsetDateTime notBefore = OffsetDateTime.now();
		OffsetDateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = PkiTestUtils.generateCertificate(keyPair.getPublic(), signerDn, notBefore,
				notAfter, null, keyPair.getPrivate(), true, new KeyUsage(KeyUsage.digitalSignature));

		// operate
		DigestInfo digestInfo = signatureService.preSign(null, Collections.singletonList(certificate), null, null, null);

		// verify
		assertNotNull(digestInfo);
		LOG.debug("digest algo: " + digestInfo.digestAlgo);
		LOG.debug("digest description: " + digestInfo.description);
		assertEquals("Office OpenXML Document", digestInfo.description);
		assertNotNull(digestInfo.digestAlgo);
		assertNotNull(digestInfo.digestValue);

		TemporaryDataStorage temporaryDataStorage = signatureService.getTemporaryDataStorage();
		String preSignResult = IOUtils.toString(temporaryDataStorage.getTempInputStream(), "UTF-8");
		LOG.debug("pre-sign result: " + preSignResult);
		File tmpFile = File.createTempFile("ooxml-pre-sign-", ".xml");
		FileUtils.writeStringToFile(tmpFile, preSignResult, "UTF-8");
		LOG.debug("tmp pre-sign file: " + tmpFile.getAbsolutePath());

		// setup: key material, signature value

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(PkiTestUtils.SHA1_DIGEST_INFO_PREFIX, digestInfo.digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		// operate: postSign
		signatureService.postSign(signatureValue, Collections.singletonList(certificate));

		// verify: signature
		byte[] signedOOXMLData = signatureService.getSignedOfficeOpenXMLDocumentData();
		assertNotNull(signedOOXMLData);
		LOG.debug("signed OOXML size: " + signedOOXMLData.length);
		String extension = FilenameUtils.getExtension(ooxmlUrl.getFile());
		tmpFile = File.createTempFile("ooxml-signed-", "." + extension);
		FileUtils.writeByteArrayToFile(tmpFile, signedOOXMLData);
		LOG.debug("signed OOXML file: " + tmpFile.getAbsolutePath());
		OOXMLSignatureVerifier verifier = new OOXMLSignatureVerifier();
		List<X509Certificate> signers = verifier.getSigners(tmpFile.toURI().toURL());
		assertEquals(signerCount, signers.size());
		// assertEquals(certificate, signers.get(0));
		LOG.debug("signed OOXML file: " + tmpFile.getAbsolutePath());
		return tmpFile;
	}
}
