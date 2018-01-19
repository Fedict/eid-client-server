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

package be.bosa.eid.client_server.shared.message;

import be.bosa.eid.client_server.shared.protocol.ProtocolMessageCatalog;

import java.util.LinkedList;
import java.util.List;

/**
 * eID Applet Protocol Message Catalog.
 *
 * @author Frank Cornelis
 */
public class ClientServerProtocolMessageCatalog implements ProtocolMessageCatalog {

	public List<Class<?>> getCatalogClasses() {
		List<Class<?>> catalog = new LinkedList<>();
		catalog.add(HelloMessage.class);
		catalog.add(IdentificationRequestMessage.class);
		catalog.add(CheckClientMessage.class);
		catalog.add(ClientEnvironmentMessage.class);
		catalog.add(InsecureClientMessage.class);
		catalog.add(AuthenticationRequestMessage.class);
		catalog.add(AuthenticationDataMessage.class);
		catalog.add(AuthSignRequestMessage.class);
		catalog.add(AuthSignResponseMessage.class);
		catalog.add(AdministrationMessage.class);
		catalog.add(SignRequestMessage.class);
		catalog.add(SignatureDataMessage.class);
		catalog.add(FilesDigestRequestMessage.class);
		catalog.add(FileDigestsDataMessage.class);
		catalog.add(ContinueInsecureMessage.class);
		catalog.add(SignCertificatesRequestMessage.class);
		catalog.add(SignCertificatesDataMessage.class);

		catalog.add(IdentityDataMessage.class);
		catalog.add(FinishedMessage.class);
		return catalog;
	}
}
