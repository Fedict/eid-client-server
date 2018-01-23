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

import be.fedict.eid.applet.service.signer.cms.CMSProvider;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CMSTest {

	private static final Log LOG = LogFactory.getLog(CMSTest.class);
	private static final String SUBJECT_DN = "CN=Test";

	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testPkcs1Signature() throws Exception {
		// setup
		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();

		// verify
		signature.initVerify(keyPair.getPublic());
		signature.update(toBeSigned);
		boolean signatureResult = signature.verify(signatureValue);
		assertTrue(signatureResult);
	}

	/**
	 * CMS signature with external data and external certificate. The CMS only
	 * contains the signature and some certificate selector.
	 */
	@Test
	public void testBasicCmsSignature() throws Exception {
		// setup
		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		OffsetDateTime notBefore = OffsetDateTime.now();
		OffsetDateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair, notBefore, notAfter);
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		CMSSignedDataGenerator generator = createCMSSignedDataGenerator(keyPair.getPrivate(), certificate);
		CMSProcessableByteArray content = new CMSProcessableByteArray(toBeSigned);
		CMSSignedData signedData = generator.generate(content, false);

		byte[] cmsSignature = signedData.getEncoded();
		LOG.debug("CMS signature: " + ASN1Dump.dumpAsString(new ASN1StreamParser(cmsSignature).readObject()));

		// verify
		signedData = new CMSSignedData(content, cmsSignature);
		SignerInformationStore signers = signedData.getSignerInfos();
		PkiTestUtils.verifySignatures(certificate, signers);
		LOG.debug("content type: " + signedData.getSignedContentTypeOID());
	}

	/**
	 * CMS signature with embedded data and external certificate. The CMS only
	 * contains the original content, signature and some certificate selector.
	 */
	@Test
	public void testCmsSignatureWithContent() throws Exception {
		// setup
		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		OffsetDateTime notBefore = OffsetDateTime.now();
		OffsetDateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair, notBefore, notAfter);
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		CMSSignedDataGenerator generator = createCMSSignedDataGenerator(keyPair.getPrivate(), certificate);
		CMSProcessableByteArray content = new CMSProcessableByteArray(toBeSigned);
		CMSSignedData signedData = generator.generate(content, true);

		byte[] cmsSignature = signedData.getEncoded();
		LOG.debug("CMS signature: " + ASN1Dump.dumpAsString(new ASN1StreamParser(cmsSignature).readObject()));

		// verify
		signedData = new CMSSignedData(cmsSignature);
		SignerInformationStore signers = signedData.getSignerInfos();
		PkiTestUtils.verifySignatures(certificate, signers);

		byte[] data = (byte[]) signedData.getSignedContent().getContent();
		assertArrayEquals(toBeSigned, data);
		LOG.debug("content type: " + signedData.getSignedContentTypeOID());
	}

	/**
	 * CMS signature with external data and embedded certificate. The CMS only
	 * contains the signature, signing certificate and some certificate
	 * selector.
	 */
	@Test
	public void testCmsSignatureWithCertificate() throws Exception {
		// setup
		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		OffsetDateTime notBefore = OffsetDateTime.now();
		OffsetDateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair, notBefore, notAfter);
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		CMSSignedDataGenerator generator = createCMSSignedDataGenerator(keyPair.getPrivate(), certificate);
		CMSProcessableByteArray content = new CMSProcessableByteArray(toBeSigned);
		CMSSignedData signedData = generator.generate(content, false);

		byte[] cmsSignature = signedData.getEncoded();
		LOG.debug("CMS signature: " + ASN1Dump.dumpAsString(new ASN1StreamParser(cmsSignature).readObject()));

		// verify
		signedData = new CMSSignedData(content, cmsSignature);
		SignerInformationStore signers = signedData.getSignerInfos();
		PkiTestUtils.verifySignatures(certificate, signers);
		LOG.debug("content type: " + signedData.getSignedContentTypeOID());
	}

	public static class SHA1WithRSASignature extends Signature {

		private static final Log LOG = LogFactory.getLog(SHA1WithRSASignature.class);

		private static final ThreadLocal<byte[]> digestValues = new ThreadLocal<>();

		private static final ThreadLocal<byte[]> signatureValues = new ThreadLocal<>();

		private final MessageDigest messageDigest;

		public SHA1WithRSASignature() throws NoSuchAlgorithmException {
			super("SHA1withRSA");
			LOG.debug("constructor");
			this.messageDigest = MessageDigest.getInstance("SHA1");
		}

		@Override
		@Deprecated
		protected Object engineGetParameter(String param) throws InvalidParameterException {
			throw new UnsupportedOperationException();
		}

		@Override
		protected void engineInitSign(PrivateKey privateKey) {
			LOG.debug("engineInitSign: " + privateKey.getAlgorithm());
		}

		@Override
		protected void engineInitVerify(PublicKey publicKey) {
			throw new UnsupportedOperationException();
		}

		@Override
		@Deprecated
		protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
			throw new UnsupportedOperationException();
		}

		@Override
		protected byte[] engineSign() {
			LOG.debug("engineSign");
			byte[] signatureValue = SHA1WithRSASignature.signatureValues.get();
			if (null != signatureValue) {
				SHA1WithRSASignature.signatureValues.set(null);
				return signatureValue;
			}
			return "dummy".getBytes();
		}

		public static void setSignatureValue(byte[] signatureValue) {
			SHA1WithRSASignature.signatureValues.set(signatureValue);
		}

		@Override
		protected void engineUpdate(byte b) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected void engineUpdate(byte[] b, int off, int len) {
			LOG.debug("engineUpdate(b,off,len): off=" + off + "; len=" + len);
			this.messageDigest.update(b, off, len);
			byte[] digestValue = this.messageDigest.digest();
			SHA1WithRSASignature.digestValues.set(digestValue);
		}

		@Override
		protected boolean engineVerify(byte[] sigBytes) {
			throw new UnsupportedOperationException();
		}

		public static byte[] getDigestValue() {
			return SHA1WithRSASignature.digestValues.get();
		}
	}

	@Test
	public void testRetrieveCMSDigestValue() throws Exception {
		// setup
		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		OffsetDateTime notBefore = OffsetDateTime.now();
		OffsetDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair, notBefore, notAfter);
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		CMSSignedDataGenerator generator = createCMSSignedDataGenerator(keyPair.getPrivate(), certificate);
		CMSProcessableByteArray content = new CMSProcessableByteArray(toBeSigned);
		generator.generate(content, false);

		byte[] digestValue = SHA1WithRSASignature.getDigestValue();
		assertNotNull(digestValue);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(PkiTestUtils.SHA1_DIGEST_INFO_PREFIX, digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);
		SHA1WithRSASignature.setSignatureValue(signatureValue);

		generator = createCMSSignedDataGenerator(keyPair.getPrivate(), certificate);
		content = new CMSProcessableByteArray(toBeSigned);
		CMSSignedData signedData = generator.generate(content, false);

		byte[] cmsSignature = signedData.getEncoded();
		LOG.debug("CMS signature: " + ASN1Dump.dumpAsString(new ASN1StreamParser(cmsSignature).readObject()));

		// verify
		content = new CMSProcessableByteArray(toBeSigned);
		signedData = new CMSSignedData(content, cmsSignature);
		SignerInformationStore signers = signedData.getSignerInfos();
		PkiTestUtils.verifySignatures(certificate, signers);
		LOG.debug("content type: " + signedData.getSignedContentTypeOID());
	}

	private X509Certificate generateSelfSignedCertificate(KeyPair keyPair, OffsetDateTime notBefore, OffsetDateTime notAfter)
			throws IllegalStateException, CertificateException, CertIOException, OperatorCreationException, NoSuchAlgorithmException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();

		X509CertificateHolder certificateHolder = new X509v3CertificateBuilder(
				new X500Name(SUBJECT_DN),
				new BigInteger(128, new SecureRandom()),
				Date.from(notBefore.toInstant()),
				Date.from(notAfter.toInstant()),
				new X500Name(SUBJECT_DN),
				SubjectPublicKeyInfo.getInstance(keyPair.getPublic()))
				.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKey))
				.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(subjectPublicKey))
				.addExtension(Extension.basicConstraints, false, new BasicConstraints(true))
				.build(new JcaContentSignerBuilder(BouncyCastleProvider.PROVIDER_NAME).build(issuerPrivateKey));

		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
	}

	private CMSSignedDataGenerator createCMSSignedDataGenerator(PrivateKey privateKey, X509Certificate signingCertificate) throws CertificateEncodingException, OperatorCreationException, CMSException {
		JcaCertStore certStore = new JcaCertStore(Collections.singletonList(signingCertificate));

		ContentSigner sha1Signer = new JcaContentSignerBuilder(CMSSignedDataGenerator.DIGEST_SHA1)
				.setProvider(new CMSProvider())
				.build(privateKey);
		SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
				.build(sha1Signer, signingCertificate);

		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		generator.addSignerInfoGenerator(signerInfoGenerator);
		generator.addCertificates(certStore);

		return generator;
	}
}
