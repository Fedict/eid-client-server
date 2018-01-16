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

package be.bosa.eid.client_server.shared;

import be.bosa.eid.client_server.shared.message.ClientEnvironmentMessage;
import be.bosa.eid.client_server.shared.message.ErrorCode;
import be.bosa.eid.client_server.shared.message.FinishedMessage;
import be.bosa.eid.client_server.shared.message.IdentificationRequestMessage;
import be.bosa.eid.client_server.shared.message.IdentityDataMessage;
import be.bosa.eid.client_server.shared.protocol.HttpTransmitter;
import be.bosa.eid.client_server.shared.protocol.Transport;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.LinkedList;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class TransportTest {

	private static final String MESSAGE = "hello world";

	@Mock
	private HttpTransmitter mockHttpTransmitter;

	@Test
	public void transmitIdentityDataMessage() {
		IdentityDataMessage identityDataMessage = new IdentityDataMessage();
		identityDataMessage.identityFileSize = 20;
		identityDataMessage.addressFileSize = 10;
		identityDataMessage.body = MESSAGE.getBytes();

		when(mockHttpTransmitter.isSecure()).thenReturn(true);

		Transport.transfer(identityDataMessage, mockHttpTransmitter);

		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Version", "1");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Type", "IdentityDataMessage");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-IdentityFileSize", "20");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-AddressFileSize", "10");
		verify(mockHttpTransmitter).setBody(MESSAGE.getBytes());
		verify(mockHttpTransmitter).addHeader("Content-Length", Integer.toString(MESSAGE.getBytes().length));
	}

	@Test
	public void transmitFinishedMessage() {
		FinishedMessage finishedMessage = new FinishedMessage();
		when(mockHttpTransmitter.isSecure()).thenReturn(true);

		Transport.transfer(finishedMessage, mockHttpTransmitter);

		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Version", "1");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Type", "FinishedMessage");
		verify(mockHttpTransmitter).addHeader("Content-Length", "0");
	}

	@Test
	public void transmitFinishedMessageWithErrorCode() {
		FinishedMessage finishedMessage = new FinishedMessage(ErrorCode.CERTIFICATE_EXPIRED);
		when(mockHttpTransmitter.isSecure()).thenReturn(true);

		Transport.transfer(finishedMessage, mockHttpTransmitter);

		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Version", "1");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Type", "FinishedMessage");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-ErrorCode", ErrorCode.CERTIFICATE_EXPIRED.name());
		verify(mockHttpTransmitter).addHeader("Content-Length", "0");
	}

	@Test
	public void transmitIdentificationRequestMessage() {
		IdentificationRequestMessage message = new IdentificationRequestMessage();
		message.includePhoto = true;
		when(mockHttpTransmitter.isSecure()).thenReturn(true);

		Transport.transfer(message, mockHttpTransmitter);

		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Version", "1");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Type", "IdentificationRequestMessage");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-IncludeAddress", "false");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-IncludePhoto", "true");
		// TODO: protocol optimization: next could be omitted
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-IncludeIntegrityData", "false");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-IncludeCertificates", "false");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-RemoveCard", "false");
		verify(mockHttpTransmitter).addHeader("Content-Length", "0");
	}

	@Test
	public void transmitClientEnvironmentMessage() {
		ClientEnvironmentMessage message = new ClientEnvironmentMessage();
		message.javaVersion = "1.6";
		message.javaVendor = "Sun";
		message.osName = "Linux";
		message.osArch = "i386";
		message.osVersion = "2.6";
		message.readerList = new LinkedList<>();
		message.readerList.add("Reader 1");
		message.readerList.add("Reader 2");

		when(mockHttpTransmitter.isSecure()).thenReturn(true);

		Transport.transfer(message, mockHttpTransmitter);

		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Version", "1");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-Type", "ClientEnvironmentMessage");

		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-JavaVersion", "1.6");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-JavaVendor", "Sun");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-OSName", "Linux");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-OSArch", "i386");
		verify(mockHttpTransmitter).addHeader("X-AppletProtocol-OSVersion", "2.6");
		byte[] body = ("Reader 1" + System.getProperty("line.separator") + "Reader 2" + System.getProperty("line.separator")).getBytes();
		verify(mockHttpTransmitter).setBody(body);
		verify(mockHttpTransmitter).addHeader("Content-Length", Integer.toString(body.length));
	}

	@Test(expected = SecurityException.class)
	public void insecureChannelFails() {
		IdentityDataMessage identityDataMessage = new IdentityDataMessage();
		when(mockHttpTransmitter.isSecure()).thenReturn(false);

		Transport.transfer(identityDataMessage, mockHttpTransmitter);
	}

	@Test(expected = IllegalArgumentException.class)
	public void inputValidationFailure() {
		IdentityDataMessage identityDataMessage = new IdentityDataMessage();
		when(mockHttpTransmitter.isSecure()).thenReturn(true);

		Transport.transfer(identityDataMessage, mockHttpTransmitter);
	}
}
