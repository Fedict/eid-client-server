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

package be.fedict.eid.applet.service.signer;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.Arrays;

import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * A signature proxy implementation for SHA1withRSA signatures.
 *
 * @author Frank Cornelis
 */
public class SHA1WithRSAProxySignature extends Signature {

	private static final Log LOG = LogFactory.getLog(SHA1WithRSAProxySignature.class);

	private static final ThreadLocal<byte[]> digestValues = new ThreadLocal<byte[]>();

	private static final ThreadLocal<byte[]> signatureValues = new ThreadLocal<byte[]>();

	private final MessageDigest messageDigest;

	public SHA1WithRSAProxySignature() throws NoSuchAlgorithmException {
		super("SHA1withRSA");
		LOG.debug("constructor");
		this.messageDigest = MessageDigest.getInstance("SHA1");
	}

	public static void reset() {
		SHA1WithRSAProxySignature.digestValues.set(null);
		SHA1WithRSAProxySignature.signatureValues.set(null);
	}

	@Override
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
	protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected byte[] engineSign() {
		LOG.debug("engineSign");
		byte[] signatureValue = SHA1WithRSAProxySignature.signatureValues.get();
		if (null != signatureValue) {
			LOG.debug("injecting signature value: " + Hex.encodeHexString(signatureValue));
			reset();
			return signatureValue;
		}
		LOG.debug("returning a dummy signature value");
		return "dummy".getBytes();
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
		byte[] expectedDigestValue = SHA1WithRSAProxySignature.digestValues.get();
		if (null == expectedDigestValue) {
			SHA1WithRSAProxySignature.digestValues.set(digestValue);
		} else {
			if (false == Arrays.areEqual(expectedDigestValue, digestValue)) {
				throw new IllegalStateException("digest value has changed");
			}
		}
		LOG.debug("digest value: " + Hex.encodeHexString(digestValue));
	}

	@Override
	protected boolean engineVerify(byte[] sigBytes) {
		throw new UnsupportedOperationException();
	}

	public static byte[] getDigestValue() {
		return SHA1WithRSAProxySignature.digestValues.get();
	}

	public static void setSignatureValue(byte[] signatureValue) {
		SHA1WithRSAProxySignature.signatureValues.set(signatureValue);
	}

	public static void setDigestSignatureValue(byte[] digestValue, byte[] signatureValue) {
		SHA1WithRSAProxySignature.digestValues.set(digestValue);
		SHA1WithRSAProxySignature.signatureValues.set(signatureValue);
	}
}
