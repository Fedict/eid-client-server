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

package be.bosa.eid.server.spi;

import java.security.cert.X509Certificate;

/**
 * Interface for identity services. An identity service allows for run-time
 * selected of required identity data like address, photo.
 *
 * @author Frank Cornelis
 */
public interface IdentityService {

	/**
	 * Gives back an identity request object that indicates what eID identity
	 * data we exactly want to retrieve from the user.
	 *
	 * @return the identity request object.
	 */
	IdentityRequest getIdentityRequest();

	/**
	 * Callback that supplies the identity of a specific client. This should be cached for later usage.
	 */
	void setIdentity(String requestId, IdentityDTO identity);

	/**
	 * Callback that supplies the address of a specific client. This should be cached for later usage.
	 */
	void setAddress(String requestId, AddressDTO address);

	/**
	 * Callback that supplies the photo of a specific client. This should be cached for later usage.
	 */
	void setPhoto(String requestId, byte[] photo);

	/**
	 * Callback that supplies the certificates of a specific client. This should be cached for later usage.
	 */
	void setCertificates(String sessionId, X509Certificate authnCert, X509Certificate signCert, X509Certificate caCert, X509Certificate rootCert);
}
