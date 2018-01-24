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
import be.bosa.eid.server.spi.IdentityConsumerService;
import be.bosa.eid.server.spi.IdentityDTO;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class IdentityConsumerServiceImpl implements IdentityConsumerService {

	static IdentityConsumerServiceImpl INSTANCE;

	// TODO Use caches that clean up after a while
	private Map<String, String> userIds = new HashMap<>();
	private Map<String, IdentityDTO> identities = new HashMap<>();
	private Map<String, AddressDTO> addresses = new HashMap<>();
	private Map<String, byte[]> photos= new HashMap<>();

	public IdentityConsumerServiceImpl() {
		IdentityConsumerServiceImpl.INSTANCE = this;
	}

	@Override
	public void setUserId(String requestId, String userId) {
		userIds.put(requestId, userId);
	}

	@Override
	public void setIdentity(String requestId, IdentityDTO identity) {
		identities.put(requestId, identity);
	}

	@Override
	public void setAddress(String requestId, AddressDTO address) {
		addresses.put(requestId, address);
	}

	@Override
	public void setPhoto(String requestId, byte[] photo) {
		photos.put(requestId, photo);
	}

	@Override
	public void setCertificates(String requestId, X509Certificate authnCert, X509Certificate signCert, X509Certificate caCert, X509Certificate rootCert) {
		// Not used
	}

	public String getUserId(String requestId) {
		return userIds.get(requestId);
	}

	public IdentityDTO getIdentity(String requestId) {
		return identities.get(requestId);
	}

	public AddressDTO getAddress(String requestId) {
		return addresses.get(requestId);
	}

	public byte[] getPhoto(String requestId) {
		return photos.get(requestId);
	}
}
