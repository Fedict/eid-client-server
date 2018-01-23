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

import be.bosa.eid.server.service.signer.asic.ASiCSignatureVerifier;
import be.bosa.eid.server.service.signer.asic.AbstractASiCSignatureService;
import be.bosa.eid.server.service.signer.facets.RevocationData;
import be.bosa.eid.server.service.signer.facets.RevocationDataService;
import be.bosa.eid.server.service.signer.time.TimeStampService;
import be.bosa.eid.server.spi.AddressDTO;
import be.bosa.eid.server.spi.DigestInfo;
import be.bosa.eid.server.spi.IdentityDTO;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class ASiCSignatureServiceTest {

	private static final Log LOG = LogFactory.getLog(ASiCSignatureServiceTest.class);

	private final static class ASiCSignatureService extends AbstractASiCSignatureService {

		public ASiCSignatureService(InputStream documentInputStream, DigestAlgo digestAlgo,
									RevocationDataService revocationDataService, TimeStampService timeStampService,
									TemporaryDataStorage temporaryDataStorage, IdentityDTO identity, byte[] photo,
									OutputStream documentOutputStream) throws IOException {
			super(documentInputStream, digestAlgo, revocationDataService, timeStampService, "ClaimedRole", identity,
					photo, temporaryDataStorage, documentOutputStream);
			setSignatureNamespacePrefix("ds");
		}
	}

	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testCreateSignature() throws Exception {
		// setup
		KeyPair caKeyPair = PkiTestUtils.generateKeyPair();
		OffsetDateTime caNotBefore = OffsetDateTime.now();
		OffsetDateTime caNotAfter = caNotBefore.plusYears(1);
		X509Certificate caCertificate = PkiTestUtils.generateCertificate(caKeyPair.getPublic(), "CN=TestCA",
				caNotBefore, caNotAfter, null, caKeyPair.getPrivate(), true,
				new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign));

		final X509CRL crl = PkiTestUtils.generateCrl(caCertificate, caKeyPair.getPrivate());

		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		OffsetDateTime notBefore = OffsetDateTime.now();
		OffsetDateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = PkiTestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, caCertificate, caKeyPair.getPrivate(), false,
				new KeyUsage(KeyUsage.nonRepudiation));

		ByteArrayOutputStream asicOutputStream = new ByteArrayOutputStream();
		ZipOutputStream asicZipOutputStream = new ZipOutputStream(asicOutputStream);

		ZipEntry fileZipEntry = new ZipEntry("file.txt");
		asicZipOutputStream.putNextEntry(fileZipEntry);
		asicZipOutputStream.write("hello world".getBytes());
		asicZipOutputStream.closeEntry();
		asicZipOutputStream.close();

		ByteArrayInputStream asicInputStream = new ByteArrayInputStream(asicOutputStream.toByteArray());

		ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

		TemporaryTestDataStorage temporaryDataStorage = new TemporaryTestDataStorage();

		IdentityDTO identity = new IdentityDTO();
		identity.name = "Cornelis";
		identity.firstName = "Frank";
		identity.male = true;

		byte[] photo = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
		AddressDTO address = new AddressDTO();
		address.city = "Brussels";

		RevocationDataService revocationDataService = certificateChain -> {
			RevocationData revocationData = new RevocationData();
			revocationData.addCRL(crl);
			return revocationData;
		};
		TimeStampService timeStampService = (data, revocationData) -> "encoded time-stamp token".getBytes();

		ASiCSignatureService testedInstance = new ASiCSignatureService(asicInputStream, DigestAlgo.SHA256,
				revocationDataService, timeStampService, temporaryDataStorage, identity, photo, resultOutputStream);

		List<X509Certificate> signingCertificateChain = new LinkedList<>();
		signingCertificateChain.add(certificate);
		signingCertificateChain.add(caCertificate);

		// operate: preSign
		DigestInfo digestInfo = testedInstance.preSign(null, signingCertificateChain, identity, address, photo);

		// verify
		assertNotNull(digestInfo);
		LOG.debug("digest info description: " + digestInfo.description);
		assertEquals("Associated Signature Container", digestInfo.description);
		LOG.debug("digest info algo: " + digestInfo.digestAlgo);
		assertEquals("SHA-256", digestInfo.digestAlgo);

		// sign the digest value
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(PkiTestUtils.SHA256_DIGEST_INFO_PREFIX, digestInfo.digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		// operate: postSign
		testedInstance.postSign(signatureValue, signingCertificateChain);

		// verify
		File tmpFile = File.createTempFile("signed-container-", ".asice");
		byte[] asicResult = resultOutputStream.toByteArray();
		FileUtils.writeByteArrayToFile(tmpFile, asicResult);
		LOG.debug("ASiC file: " + tmpFile.getAbsolutePath());

		List<X509Certificate> signers = ASiCSignatureVerifier.verifySignatures(asicResult);
		assertNotNull(signers);
		assertEquals(1, signers.size());
		assertEquals(certificate, signers.get(0));
	}
}
