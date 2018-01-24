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

package be.bosa.eid.server.demo;

import be.bosa.eid.server.spi.AddressDTO;
import be.bosa.eid.server.spi.AuthorizationException;
import be.bosa.eid.server.spi.DigestInfo;
import be.bosa.eid.server.spi.IdentityDTO;
import be.bosa.eid.server.spi.SignatureService;
import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SignatureServiceImpl implements SignatureService {

	public static final String STRING_TO_SIGN = "Hello Digital Sign Service";
	private static final String DIGEST_ALGORITHM = "SHA-256";

	public static SignatureServiceImpl INSTANCE;

	private Map<String, String> signatureValues = new HashMap<>();

	public SignatureServiceImpl() {
		INSTANCE = this;
	}

	@Override
	public String getFilesDigestAlgorithm() {
		return null;
	}

	@Override
	public DigestInfo preSign(String requestId, List<DigestInfo> digestInfos, List<X509Certificate> signingCertificateChain, IdentityDTO identity, AddressDTO address, byte[] photo) throws NoSuchAlgorithmException, AuthorizationException {
		MessageDigest digester = MessageDigest.getInstance(DIGEST_ALGORITHM);
		byte[] digest = digester.digest(STRING_TO_SIGN.getBytes());
		return new DigestInfo(digest, DIGEST_ALGORITHM, "Sample digital signature");
	}

	@Override
	public void postSign(String requestId, byte[] signatureValue, List<X509Certificate> signingCertificateChain) throws SecurityException {
		signatureValues.put(requestId, Hex.encodeHexString(signatureValue));
	}

	public String getSignatureValue(String requestId) {
		return signatureValues.get(requestId);
	}
}
