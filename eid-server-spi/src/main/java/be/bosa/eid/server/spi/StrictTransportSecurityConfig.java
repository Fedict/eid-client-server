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

import java.io.Serializable;

/**
 * Configuration for HSTS transport.
 *
 * @author Frank Cornelis
 */
public class StrictTransportSecurityConfig implements Serializable {

	private final long maxAge;

	private final boolean includeSubdomains;

	public StrictTransportSecurityConfig(long maxAge, boolean includeSubdomains) {
		this.maxAge = maxAge;
		this.includeSubdomains = includeSubdomains;
	}

	public long getMaxAge() {
		return this.maxAge;
	}

	public boolean isIncludeSubdomains() {
		return this.includeSubdomains;
	}
}
