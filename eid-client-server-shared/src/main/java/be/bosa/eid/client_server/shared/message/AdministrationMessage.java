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

import be.bosa.eid.client_server.shared.annotation.HttpHeader;
import be.bosa.eid.client_server.shared.annotation.MessageDiscriminator;
import be.bosa.eid.client_server.shared.annotation.StopResponseMessage;

/**
 * Administration transfer object.
 *
 * @author Frank Cornelis
 */
@StopResponseMessage
public class AdministrationMessage extends AbstractProtocolMessage {

	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = AdministrationMessage.class.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "ChangePin")
	public boolean changePin;

	@HttpHeader(HTTP_HEADER_PREFIX + "UnblockPin")
	public boolean unblockPin;

	@HttpHeader(HTTP_HEADER_PREFIX + "RemoveCard")
	public boolean removeCard;

	@HttpHeader(HTTP_HEADER_PREFIX + "Logoff")
	public boolean logoff;

	@HttpHeader(HTTP_HEADER_PREFIX + "RequireSecureReader")
	public boolean requireSecureReader;

	public AdministrationMessage() {
	}

	public AdministrationMessage(boolean changePin, boolean unblockPin, boolean logoff, boolean removeCard, boolean requireSecureReader) {
		this.changePin = changePin;
		this.unblockPin = unblockPin;
		this.logoff = logoff;
		this.removeCard = removeCard;
		this.requireSecureReader = requireSecureReader;
	}
}
