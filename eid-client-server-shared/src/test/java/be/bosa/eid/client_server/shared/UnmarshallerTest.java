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

import be.bosa.eid.client_server.shared.annotation.HttpHeader;
import be.bosa.eid.client_server.shared.annotation.MessageDiscriminator;
import be.bosa.eid.client_server.shared.annotation.PostConstruct;
import be.bosa.eid.client_server.shared.message.AbstractProtocolMessage;
import be.bosa.eid.client_server.shared.message.ClientEnvironmentMessage;
import be.bosa.eid.client_server.shared.message.ClientServerProtocolMessageCatalog;
import be.bosa.eid.client_server.shared.message.ErrorCode;
import be.bosa.eid.client_server.shared.message.FinishedMessage;
import be.bosa.eid.client_server.shared.message.IdentificationRequestMessage;
import be.bosa.eid.client_server.shared.message.IdentityDataMessage;
import be.bosa.eid.client_server.shared.protocol.HttpReceiver;
import be.bosa.eid.client_server.shared.protocol.ProtocolMessageCatalog;
import be.bosa.eid.client_server.shared.protocol.Unmarshaller;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class UnmarshallerTest {

	private static final Log LOG = LogFactory.getLog(UnmarshallerTest.class);

	@Mock
	private HttpReceiver mockHttpReceiver;

	@Test(expected = RuntimeException.class)
	public void receiveIdentityDataMessageWithoutRequiredHeaders() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn("IdentityDataMessage");
		when(mockHttpReceiver.getHeaderNames()).thenReturn(new LinkedList<>());
		when(mockHttpReceiver.getBody()).thenReturn("hello world".getBytes());

		unmarshaller.receive(mockHttpReceiver);
	}

	@Test(expected = RuntimeException.class)
	public void receiveNoHeadersAtAll() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn(null);

		unmarshaller.receive(mockHttpReceiver);
	}

	@Test
	public void receiveIdentityDataMessage() {
		// setup
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderNames()).thenReturn(
				Arrays.asList("foo-bar", "X-EIdServerProtocol-Version", "X-EIdServerProtocol-Type", "X-EIdServerProtocol-IdentityFileSize", "X-EIdServerProtocol-AddressFileSize")
		);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn("IdentityDataMessage");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-IdentityFileSize")).thenReturn("10");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-AddressFileSize")).thenReturn("1");
		when(mockHttpReceiver.getBody()).thenReturn("hello world".getBytes());

		Object result = unmarshaller.receive(mockHttpReceiver);

		Assert.assertNotNull(result);
		Assert.assertTrue(result instanceof IdentityDataMessage);

		IdentityDataMessage identityDataMessageResult = (IdentityDataMessage) result;
		Assert.assertNotNull(identityDataMessageResult.body);
		Assert.assertArrayEquals("hello world".getBytes(), identityDataMessageResult.body);
		Assert.assertEquals((Integer) 10, identityDataMessageResult.identityFileSize);
		Assert.assertEquals((Integer) 1, identityDataMessageResult.addressFileSize);
		Assert.assertArrayEquals("hello worl".getBytes(), identityDataMessageResult.idFile);
		Assert.assertArrayEquals("d".getBytes(), identityDataMessageResult.addressFile);
	}

	@Test
	public void receiveIdentificationRequestMessage() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderNames()).thenReturn(
				Arrays.asList("foo-bar", "X-EIdServerProtocol-Version", "X-EIdServerProtocol-Type", "X-EIdServerProtocol-IncludePhoto")
		);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn("IdentificationRequestMessage");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-IncludePhoto")).thenReturn("true");

		Object result = unmarshaller.receive(mockHttpReceiver);

		Assert.assertNotNull(result);
		Assert.assertTrue(result instanceof IdentificationRequestMessage);

		IdentificationRequestMessage message = (IdentificationRequestMessage) result;
		Assert.assertTrue(message.includePhoto);
	}

	@Test
	public void receiveFinishedMessage() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderNames()).thenReturn(Arrays.asList("X-EIdServerProtocol-Version", "X-EIdServerProtocol-Type"));
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn("FinishedMessage");

		Object result = unmarshaller.receive(mockHttpReceiver);

		Assert.assertNotNull(result);
		Assert.assertTrue(result instanceof FinishedMessage);

		FinishedMessage message = (FinishedMessage) result;
		Assert.assertNull(message.errorCode);
	}

	@Test
	public void receiveFinishedMessageWithErrorCode() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		// stubs
		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderNames()).thenReturn(
				Arrays.asList("X-EIdServerProtocol-Version", "X-EIdServerProtocol-Type", "X-EIdServerProtocol-ErrorCode")
		);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn("FinishedMessage");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-ErrorCode"))
				.thenReturn(ErrorCode.CERTIFICATE_EXPIRED.name());

		Object result = unmarshaller.receive(mockHttpReceiver);

		Assert.assertNotNull(result);
		Assert.assertTrue(result instanceof FinishedMessage);

		FinishedMessage message = (FinishedMessage) result;
		Assert.assertEquals(ErrorCode.CERTIFICATE_EXPIRED, message.errorCode);
	}

	@Test(expected = MyRuntimeException.class)
	public void testFailingPostConstructStackTrace() {
		ProtocolMessageCatalog catalog = () -> {
			List<Class<?>> catalogClasses = new LinkedList<>();
			catalogClasses.add(TestMessage.class);
			return catalogClasses;
		};
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderNames()).thenReturn(
				Arrays.asList("foo-bar", "X-EIdServerProtocol-Version", "X-EIdServerProtocol-Type")
		);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn(TestMessage.class.getSimpleName());

		unmarshaller.receive(mockHttpReceiver);
	}

	@Test
	public void receiveClientEnvironmentMessage() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderNames()).thenReturn(Arrays.asList(
				"foo-bar", "X-EIdServerProtocol-Version", "X-EIdServerProtocol-Type", "X-EIdServerProtocol-JavaVersion",
				"X-EIdServerProtocol-JavaVendor", "X-EIdServerProtocol-OSName", "X-EIdServerProtocol-OSArch",
				"X-EIdServerProtocol-OSVersion"
		));
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn("ClientEnvironmentMessage");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-JavaVersion")).thenReturn("1.6");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-JavaVendor")).thenReturn("Sun");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-OSName")).thenReturn("Linux");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-OSArch")).thenReturn("i386");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-OSVersion")).thenReturn("2.6");
		when(mockHttpReceiver.getBody()).thenReturn("Reader 1\nReader 2\n".getBytes());

		Object result = unmarshaller.receive(mockHttpReceiver);

		Assert.assertNotNull(result);
		Assert.assertTrue(result instanceof ClientEnvironmentMessage);

		ClientEnvironmentMessage message = (ClientEnvironmentMessage) result;
		Assert.assertEquals("1.6", message.javaVersion);
		Assert.assertEquals("Sun", message.javaVendor);
		Assert.assertEquals("Linux", message.osName);
		Assert.assertEquals("i386", message.osArch);
		Assert.assertEquals("2.6", message.osVersion);
		// TODO body test
	}

	@Test
	public void receiveIdentityDataMessageCaseInsensitiveHeaders() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn("IdentityDataMessage");

		when(mockHttpReceiver.getHeaderNames()).thenReturn(Arrays.asList(
				"foo-bar", "X-EIdServerProtocol-version", "X-EIdServerProtocol-type", "X-EIdServerProtocol-identityfilesize",
				"X-EIdServerProtocol-addressfilesize"
		));
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-type")).thenReturn("IdentityDataMessage");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-identityfilesize")).thenReturn("10");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-addressfilesize")).thenReturn("1");
		when(mockHttpReceiver.getBody()).thenReturn("hello world".getBytes());

		Object result = unmarshaller.receive(mockHttpReceiver);

		Assert.assertNotNull(result);
		Assert.assertTrue(result instanceof IdentityDataMessage);

		IdentityDataMessage identityDataMessageResult = (IdentityDataMessage) result;
		Assert.assertNotNull(identityDataMessageResult.body);
		Assert.assertArrayEquals("hello world".getBytes(), identityDataMessageResult.body);
		Assert.assertEquals((Integer) 10, identityDataMessageResult.identityFileSize);
		Assert.assertEquals((Integer) 1, identityDataMessageResult.addressFileSize);
	}

	@Test(expected = RuntimeException.class)
	public void receiveUnknownMessage() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("1");
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Type")).thenReturn("foo-bar");

		unmarshaller.receive(mockHttpReceiver);
	}

	@Test(expected = SecurityException.class)
	public void unsecureHttpReceiver() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(false);

		unmarshaller.receive(mockHttpReceiver);
	}

	@Test(expected = RuntimeException.class)
	public void protocolVersion() {
		ProtocolMessageCatalog catalog = new ClientServerProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		when(mockHttpReceiver.isSecure()).thenReturn(true);
		when(mockHttpReceiver.getHeaderValue("X-EIdServerProtocol-Version")).thenReturn("007");

		unmarshaller.receive(mockHttpReceiver);
	}

	// TODO: test semantical validator

	public static final class MyRuntimeException extends RuntimeException {
		public MyRuntimeException(String message) {
			super(message);
		}
	}

	public static final class TestMessage extends AbstractProtocolMessage {
		@HttpHeader(TYPE_HTTP_HEADER)
		@MessageDiscriminator
		public static final String TYPE = TestMessage.class.getSimpleName();

		@PostConstruct
		public void postConstruct() {
			LOG.debug("postConstruct method invoked");
			throw new MyRuntimeException("failing post construct method");
		}
	}

}