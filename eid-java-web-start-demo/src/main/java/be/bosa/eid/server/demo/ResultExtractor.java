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
import be.bosa.eid.server.spi.IdentityDTO;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.function.BiFunction;

public class ResultExtractor {

	public static Optional<IdentityDTO> getIdentity(HttpServletRequest request) {
		return getFromIdentityService(request, IdentityServiceImpl::getIdentity);
	}

	public static Optional<AddressDTO> getAddress(HttpServletRequest request) {
		return getFromIdentityService(request, IdentityServiceImpl::getAddress);

	}

	public static Optional<byte[]> getPhoto(HttpServletRequest request) {
		return getFromIdentityService(request, IdentityServiceImpl::getPhoto);
	}

	private static <T> Optional<T> getFromIdentityService(HttpServletRequest request, BiFunction<IdentityServiceImpl, String, T> extractor) {
		String requestId = request.getParameter("requestId");
		IdentityServiceImpl identityService = IdentityServiceImpl.INSTANCE;
		if (requestId == null || identityService == null) {
			return Optional.empty();
		}

		return Optional.ofNullable(extractor.apply(identityService, requestId));
	}
}
