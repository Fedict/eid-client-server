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

import be.bosa.eid.client_server.shared.annotation.HttpBody;
import be.bosa.eid.client_server.shared.annotation.HttpHeader;
import be.bosa.eid.client_server.shared.annotation.MessageDiscriminator;
import be.bosa.eid.client_server.shared.annotation.NotNull;
import be.bosa.eid.client_server.shared.annotation.StateTransition;
import be.bosa.eid.client_server.shared.protocol.ProtocolState;

/**
 * Sign request message transfer object.
 *
 * @author Frank Cornelis
 */
@StateTransition(ProtocolState.SIGN)
public class SignRequestMessage extends AbstractProtocolMessage {

	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = SignRequestMessage.class.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "DigestAlgo")
	@NotNull
	public String digestAlgo;

	@HttpHeader(HTTP_HEADER_PREFIX + "Description")
	public String description;

	@HttpHeader(HTTP_HEADER_PREFIX + "RemoveCard")
	public boolean removeCard;

	@HttpHeader(HTTP_HEADER_PREFIX + "Logoff")
	public boolean logoff;

	@HttpHeader(HTTP_HEADER_PREFIX + "RequireSecureReader")
	public boolean requireSecureReader;

	@HttpHeader(HTTP_HEADER_PREFIX + "NoPKCS11")
	public boolean noPkcs11;

	@HttpBody
	@NotNull
	public byte[] digestValue;

	public SignRequestMessage() {
	}

	public SignRequestMessage(byte[] digestValue, String digestAlgo, String description, boolean logoff,
							  boolean removeCard, boolean requireSecureReader) {
		this.digestValue = digestValue;
		this.digestAlgo = digestAlgo;
		this.description = description;
		this.logoff = logoff;
		this.removeCard = removeCard;
		this.requireSecureReader = requireSecureReader;
		this.noPkcs11 = true;
	}
}
