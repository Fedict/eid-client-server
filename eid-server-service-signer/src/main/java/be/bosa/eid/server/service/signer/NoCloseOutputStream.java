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

package be.bosa.eid.server.service.signer;

import org.apache.commons.io.output.ProxyOutputStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.OutputStream;

/**
 * Output Stream proxy that doesn't close the underlying stream.
 *
 * @author Frank Cornelis
 */
public class NoCloseOutputStream extends ProxyOutputStream {

	private static final Log LOG = LogFactory.getLog(NoCloseOutputStream.class);

	/**
	 * Main constructor.
	 */
	public NoCloseOutputStream(OutputStream proxy) {
		super(proxy);
	}

	@Override
	public void close() {
		LOG.debug("close");
		// empty
	}
}