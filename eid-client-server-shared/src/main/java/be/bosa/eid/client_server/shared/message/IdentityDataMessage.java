/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 */

package be.bosa.eid.client_server.shared.message;

import be.bosa.eid.client_server.shared.annotation.HttpBody;
import be.bosa.eid.client_server.shared.annotation.HttpHeader;
import be.bosa.eid.client_server.shared.annotation.MessageDiscriminator;
import be.bosa.eid.client_server.shared.annotation.NotNull;
import be.bosa.eid.client_server.shared.annotation.PostConstruct;
import be.bosa.eid.client_server.shared.annotation.ProtocolStateAllowed;
import be.bosa.eid.client_server.shared.annotation.ResponsesAllowed;
import be.bosa.eid.client_server.shared.annotation.ValidateSemanticalIntegrity;
import be.bosa.eid.client_server.shared.protocol.ProtocolState;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Identity Data Transfer Object.
 *
 * @author Frank Cornelis
 */
@ValidateSemanticalIntegrity(IdentityDataMessageSemanticValidator.class)
@ResponsesAllowed(FinishedMessage.class)
@ProtocolStateAllowed(ProtocolState.IDENTIFY)
public class IdentityDataMessage extends AbstractProtocolMessage {

	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = IdentityDataMessage.class.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "IdentityFileSize")
	@NotNull
	public Integer identityFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AddressFileSize")
	public Integer addressFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "PhotoFileSize")
	public Integer photoFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "IdentitySignatureFileSize")
	public Integer identitySignatureFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AddressSignatureFileSize")
	public Integer addressSignatureFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "RrnCertFileSize")
	public Integer rrnCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "RootCertFileSize")
	public Integer rootCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AuthnCertFileSize")
	public Integer authnCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "SignCertFileSize")
	public Integer signCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "CaCertFileSize")
	public Integer caCertFileSize;

	@HttpBody
	@NotNull
	public byte[] body;

	public IdentityDataMessage() {
	}

	/**
	 * Main constructor.
	 */
	public IdentityDataMessage(byte[] idFile, byte[] addressFile, byte[] photoFile, byte[] identitySignatureFile,
							   byte[] addressSignatureFile, byte[] rrnCertFile, byte[] rootCertFile, byte[] authnCertFile,
							   byte[] signCertFile, byte[] caCertFile) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		this.identityFileSize = idFile.length;
		baos.write(idFile);
		if (addressFile != null) {
			baos.write(addressFile);
			this.addressFileSize = addressFile.length;
		}
		if (photoFile != null) {
			baos.write(photoFile);
			this.photoFileSize = photoFile.length;
		}
		if (identitySignatureFile != null) {
			baos.write(identitySignatureFile);
			this.identitySignatureFileSize = identitySignatureFile.length;
		}
		if (addressSignatureFile != null) {
			baos.write(addressSignatureFile);
			this.addressSignatureFileSize = addressSignatureFile.length;
		}
		if (authnCertFile != null) {
			baos.write(authnCertFile);
			this.authnCertFileSize = authnCertFile.length;
		}
		if (signCertFile != null) {
			baos.write(signCertFile);
			this.signCertFileSize = signCertFile.length;
		}
		if (caCertFile != null) {
			baos.write(caCertFile);
			this.caCertFileSize = caCertFile.length;
		}
		if (rrnCertFile != null) {
			baos.write(rrnCertFile);
			this.rrnCertFileSize = rrnCertFile.length;
		}
		if (rootCertFile != null) {
			baos.write(rootCertFile);
			this.rootCertFileSize = rootCertFile.length;
		}
		this.body = baos.toByteArray();
	}

	private byte[] copy(byte[] source, int idx, int count) {
		byte[] result = new byte[count];
		System.arraycopy(source, idx, result, 0, count);
		return result;
	}

	@PostConstruct
	public void postConstruct() {
		int idx = 0;
		this.idFile = copy(this.body, 0, this.identityFileSize);
		idx += this.identityFileSize;

		if (this.addressFileSize != null) {
			this.addressFile = copy(this.body, idx, this.addressFileSize);
			idx += this.addressFileSize;
		}

		if (this.photoFileSize != null) {
			this.photoFile = copy(this.body, idx, this.photoFileSize);
			idx += this.photoFileSize;
		}

		if (this.identitySignatureFileSize != null) {
			this.identitySignatureFile = copy(this.body, idx, this.identitySignatureFileSize);
			idx += this.identitySignatureFileSize;
		}

		if (this.addressSignatureFileSize != null) {
			this.addressSignatureFile = copy(this.body, idx, this.addressSignatureFileSize);
			idx += this.addressSignatureFileSize;
		}

		if (this.authnCertFileSize != null) {
			this.authnCertFile = copy(this.body, idx, this.authnCertFileSize);
			idx += this.authnCertFileSize;
		}

		if (this.signCertFileSize != null) {
			this.signCertFile = copy(this.body, idx, this.signCertFileSize);
			idx += this.signCertFileSize;
		}

		if (this.caCertFileSize != null) {
			this.caCertFile = copy(this.body, idx, this.caCertFileSize);
			idx += this.caCertFileSize;
		}

		if (this.rrnCertFileSize != null) {
			this.rrnCertFile = copy(this.body, idx, this.rrnCertFileSize);
			idx += this.rrnCertFileSize;
		}

		if (this.rootCertFileSize != null) {
			this.rootCertFile = copy(this.body, idx, this.rootCertFileSize);
			idx += this.rootCertFileSize;
		}
	}

	public byte[] idFile;
	public byte[] addressFile;
	public byte[] photoFile;
	public byte[] identitySignatureFile;
	public byte[] addressSignatureFile;
	public byte[] rrnCertFile;
	public byte[] rootCertFile;
	public byte[] authnCertFile;
	public byte[] signCertFile;
	public byte[] caCertFile;
}
