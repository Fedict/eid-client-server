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

package be.bosa.eid.client.core.io;

import be.bosa.eid.client.core.EidClientFrame;
import be.bosa.eid.client_server.shared.protocol.ProtocolContext;
import be.bosa.eid.client_server.shared.protocol.ProtocolState;

/**
 * Local memory protocol context implementation.
 *
 * @author Frank Cornelis
 */
public class LocalProtocolContext implements ProtocolContext {

	private final EidClientFrame view;

	private ProtocolState protocolState;

	public LocalProtocolContext(EidClientFrame view) {
		this.view = view;
	}

	@Override
	public ProtocolState getProtocolState() {
		view.addDetailMessage("Current protocol state: " + this.protocolState);
		return this.protocolState;
	}

	@Override
	public void removeProtocolState() {
		view.addDetailMessage("Removing protocol state");
		this.protocolState = null;
	}

	@Override
	public void setProtocolState(ProtocolState protocolState) {
		view.addDetailMessage("Protocol state transition: " + protocolState);
		this.protocolState = protocolState;
	}
}
