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

import be.bosa.eid.client_server.shared.protocol.SemanticValidator;
import be.bosa.eid.client_server.shared.protocol.SemanticValidatorException;

/**
 * Semantic validator implementation of the IdentityDataMessage.
 *
 * @author Frank Cornelis
 */
public class IdentityDataMessageSemanticValidator implements SemanticValidator<IdentityDataMessage> {

	public void validate(IdentityDataMessage object) throws SemanticValidatorException {
		int expectedSize = object.identityFileSize;
		if (object.addressFileSize != null) {
			expectedSize += object.addressFileSize;
		}
		if (object.photoFileSize != null) {
			expectedSize += object.photoFileSize;
		}
		if (object.identitySignatureFileSize != null) {
			expectedSize += object.identitySignatureFileSize;
		}
		if (object.addressSignatureFileSize != null) {
			expectedSize += object.addressSignatureFileSize;
		}
		if (object.authnCertFileSize != null) {
			expectedSize += object.authnCertFileSize;
		}
		if (object.signCertFileSize != null) {
			expectedSize += object.signCertFileSize;
		}
		if (object.caCertFileSize != null) {
			expectedSize += object.caCertFileSize;
		}
		if (object.rrnCertFileSize != null) {
			expectedSize += object.rrnCertFileSize;
		}
		if (object.rootCertFileSize != null) {
			expectedSize += object.rootCertFileSize;
		}
		if (expectedSize != object.body.length) {
			// throw new SemanticValidatorException(
			// "body size incorrect. expected: " + expectedSize
			// + "; actual: " + object.body.length);
		}
	}
}
