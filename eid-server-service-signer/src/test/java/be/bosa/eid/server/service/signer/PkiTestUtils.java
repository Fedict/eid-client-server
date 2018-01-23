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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.w3c.dom.Node;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.OffsetDateTime;
import java.util.Date;

import static org.junit.Assert.assertTrue;

public class PkiTestUtils {

	private static final Log LOG = LogFactory.getLog(PkiTestUtils.class);

	public static final byte[] SHA1_DIGEST_INFO_PREFIX = new byte[]{0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e,
			0x03, 0x02, 0x1a, 0x04, 0x14};

	public static final byte[] SHA256_DIGEST_INFO_PREFIX = new byte[]{0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60,
			(byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20};

	private PkiTestUtils() {
		super();
	}

	static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4), random);
		return keyPairGenerator.generateKeyPair();
	}

	static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn, OffsetDateTime notBefore,
											   OffsetDateTime notAfter, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey,
											   boolean caFlag, KeyUsage keyUsage)
			throws IllegalStateException, CertificateException, CertIOException, OperatorCreationException {
		String signatureAlgorithm = "SHA1withRSA";

		X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
				issuerCertificate != null ? new X500Name(issuerCertificate.getSubjectX500Principal().toString()) : new X500Name(subjectDn),
				new BigInteger(128, new SecureRandom()),
				Date.from(notBefore.toInstant()),
				Date.from(notAfter.toInstant()),
				new X500Name(subjectDn),
				SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded())
		);

		certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectPublicKey.getEncoded());
		certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, subjectPublicKey.getEncoded());

		if (caFlag) {
			certificateBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(0));
		}

		if (keyUsage != null) {
			certificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		}

		X509CertificateHolder certificateHolder = certificateBuilder.build(new JcaContentSignerBuilder(signatureAlgorithm).build(issuerPrivateKey));
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
	}

	static String toString(Node dom) throws TransformerException {
		Source source = new DOMSource(dom);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		/*
		 * We have to omit the ?xml declaration if we want to embed the
		 * document.
		 */
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		return stringWriter.getBuffer().toString();
	}

	public static X509CRL generateCrl(X509Certificate issuer, PrivateKey issuerPrivateKey) throws IllegalStateException, CertificateEncodingException, CertIOException, OperatorCreationException, CRLException {
		Date now = new Date();
		X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
				new JcaX509CertificateHolder(issuer).getSubject(),
				now
		);
		crlBuilder.setNextUpdate(new Date(now.getTime() + 100000));
		crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(new BigInteger("1234")));

		X509CRLHolder crlHolder = crlBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").build(issuerPrivateKey));
		return new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);
	}

	public static OCSPResp createOcspResp(X509Certificate certificate, boolean revoked,
										  X509Certificate issuerCertificate, X509Certificate ocspResponderCertificate,
										  PrivateKey ocspResponderPrivateKey, String signatureAlgorithm)
			throws CertificateEncodingException, OCSPException, OperatorCreationException {
		JcaX509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuerCertificate);
		JcaX509CertificateHolder ocspResponderHolder = new JcaX509CertificateHolder(ocspResponderCertificate);
		BasicOCSPRespBuilder ocspResponseBuilder = new BasicOCSPRespBuilder(new RespID(issuerHolder.getSubject()));

		DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
		CertificateID certId = new CertificateID(digestCalculator, issuerHolder, certificate.getSerialNumber());
		if (revoked) {
			ocspResponseBuilder.addResponse(certId, new RevokedStatus(new Date(), CRLReason.unspecified));
		} else {
			ocspResponseBuilder.addResponse(certId, RevokedStatus.GOOD);
		}

		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ocspResponderPrivateKey);
		BasicOCSPResp basicOcspResponse = ocspResponseBuilder.build(contentSigner, new X509CertificateHolder[]{ocspResponderHolder, issuerHolder}, new Date());
		return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicOcspResponse);
	}

	public static void verifySignatures(X509Certificate certificate, SignerInformationStore signers) throws OperatorCreationException, CMSException {
		for (SignerInformation signer : signers.getSigners()) {
			SignerId signerId = signer.getSID();
			LOG.debug("signer: " + signerId);
			assertTrue(signerId.match(certificate));

			SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(certificate);
			assertTrue(signer.verify(signerInformationVerifier));
		}
	}
}
