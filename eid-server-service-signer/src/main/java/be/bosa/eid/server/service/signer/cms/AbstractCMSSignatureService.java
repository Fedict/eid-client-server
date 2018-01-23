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

package be.bosa.eid.server.service.signer.cms;

import be.bosa.eid.server.service.signer.SHA1WithRSAProxySignature;
import be.bosa.eid.server.service.signer.util.DummyPrivateKey;
import be.bosa.eid.server.spi.AddressDTO;
import be.bosa.eid.server.spi.DigestInfo;
import be.bosa.eid.server.spi.IdentityDTO;
import be.bosa.eid.server.spi.SignatureService;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Abstract CMS Signature Service class. The content and signing certificate are
 * included in the CMS signature.
 *
 * @author Frank Cornelis
 */
public abstract class AbstractCMSSignatureService implements SignatureService {

	public String getFilesDigestAlgorithm() {
		return null;
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos, List<X509Certificate> signingCertificateChain,
							  IdentityDTO identity, AddressDTO address, byte[] photo) {
		SHA1WithRSAProxySignature.reset();

		try {
			createCMSSignedDataGenerator(signingCertificateChain)
					.generate(new CMSProcessableByteArray(getToBeSigned()), true);
		} catch (CMSException e) {
			throw new RuntimeException(e);
		}

		byte[] digestValue = SHA1WithRSAProxySignature.getDigestValue();
		String description = getSignatureDescription();
		return new DigestInfo(digestValue, "SHA1", description);
	}

	public void postSign(byte[] signatureValue, List<X509Certificate> signingCertificateChain) {
		CMSSignedData signedData;
		try {
			signedData = createCMSSignedDataGenerator(signingCertificateChain)
					.generate(new CMSProcessableByteArray(getToBeSigned()), true);
		} catch (CMSException e) {
			throw new RuntimeException(e);
		}

		SHA1WithRSAProxySignature.reset();
		SHA1WithRSAProxySignature.setSignatureValue(signatureValue);

		try {
			byte[] cmsSignature = signedData.getEncoded();
			this.storeCMSSignature(cmsSignature);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private CMSSignedDataGenerator createCMSSignedDataGenerator(List<X509Certificate> signingCertificateChain) {
		if (signingCertificateChain == null) {
			return new CMSSignedDataGenerator();
		}

		try {
			X509Certificate signingCertificate = signingCertificateChain.get(0);
			JcaCertStore certs = new JcaCertStore(Collections.singletonList(signingCertificate));

			ContentSigner sha1Signer = new JcaContentSignerBuilder(CMSSignedDataGenerator.DIGEST_SHA1)
					.setProvider(new CMSProvider())
					.build(new DummyPrivateKey());
			SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
					.build(sha1Signer, signingCertificate);

			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
			generator.addSignerInfoGenerator(signerInfoGenerator);
			generator.addCertificates(certs);
			return generator;
		} catch (CMSException | OperatorCreationException | CertificateEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	abstract protected byte[] getToBeSigned();

	abstract protected String getSignatureDescription();

	abstract protected void storeCMSSignature(byte[] cmsSignature);
}
