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

/**
 * SPI for transport service component.
 *
 * @author Frank Cornelis
 */
public interface TransportService {

	/**
	 * Gives back the desired configuration of HSTS. <code>null</code> if no
	 * HSTS should be used.
	 *
	 * @return the HSTS config.
	 */
	StrictTransportSecurityConfig getStrictTransportSecurityConfig();
}
