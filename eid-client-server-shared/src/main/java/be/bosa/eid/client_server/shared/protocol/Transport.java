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

package be.bosa.eid.client_server.shared.protocol;

import be.bosa.eid.client_server.shared.annotation.HttpBody;
import be.bosa.eid.client_server.shared.annotation.HttpHeader;
import be.bosa.eid.client_server.shared.annotation.NotNull;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.List;

/**
 * Transport component is responsible for governing the process of converting
 * Java objects into data streams using a HTTP transport component.
 *
 * @author Frank Cornelis
 */
public class Transport {

	private Transport() {
	}

	/**
	 * Transfers the given data objects over the HTTP transport component.
	 *
	 * @param dataObject      the data objects to transfer.
	 * @param httpTransmitter the transport component.
	 */
	public static void transfer(Object dataObject, HttpTransmitter httpTransmitter) {
		if (!httpTransmitter.isSecure()) {
			throw new SecurityException("applet service connection not trusted");
		}

		// TODO: semantic integrity validation
		Class<?> dataClass = dataObject.getClass();
		Field[] fields = dataClass.getFields();
		try {
			inputValidation(dataObject, fields);
		} catch (Exception e) {
			throw new IllegalArgumentException("error: " + e.getMessage(), e);
		}

		Field bodyField = addHeaders(dataObject, httpTransmitter, fields);
		addBody(dataObject, httpTransmitter, bodyField);
	}

	@SuppressWarnings("unchecked")
	private static void addBody(Object dataObject, HttpTransmitter httpTransmitter, Field bodyField) {
		if (bodyField == null) {
			httpTransmitter.addHeader("Content-Length", "0");
			return;
		}

		Object bodyValue;
		try {
			bodyValue = bodyField.get(dataObject);
		} catch (IllegalArgumentException | IllegalAccessException e) {
			throw new RuntimeException("error reading field: " + bodyField.getName());
		}

		byte[] body;
		if (bodyValue instanceof List<?>) {
			List<String> bodyList = (List<String>) bodyValue;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PrintStream printStream = new PrintStream(baos);
			for (String bodyStr : bodyList) {
				printStream.println(bodyStr);
			}
			body = baos.toByteArray();
		} else {
			body = (byte[]) bodyValue;
		}

		httpTransmitter.addHeader("Content-Length", Integer.toString(body.length));
		httpTransmitter.setBody(body);
	}

	private static Field addHeaders(Object dataObject, HttpTransmitter httpTransmitter, Field[] fields) {
		Field bodyField = null;
		for (Field field : fields) {
			HttpBody httpBodyAnnotation = field.getAnnotation(HttpBody.class);
			if (httpBodyAnnotation != null) {
				if (bodyField == null) {
					bodyField = field;
				} else {
					throw new RuntimeException("multiple @HttpBody fields detected");
				}
			}

			HttpHeader httpHeaderAnnotation = field.getAnnotation(HttpHeader.class);
			if (null == httpHeaderAnnotation) {
				continue;
			}

			Object fieldValue;
			try {
				fieldValue = field.get(dataObject);
			} catch (Exception e) {
				throw new RuntimeException("error reading field: " + field.getName());
			}

			if (fieldValue != null) {
				String httpHeaderName = httpHeaderAnnotation.value();
				String httpHeaderValue;
				if (String.class.equals(field.getType())) {
					httpHeaderValue = (String) fieldValue;
				} else if (Integer.TYPE.equals(field.getType()) || Integer.class.equals(field.getType())) {
					httpHeaderValue = ((Integer) fieldValue).toString();
					// TODO: make this more generic
				} else if (Boolean.TYPE.equals(field.getType()) || Boolean.class.equals(field.getType())) {
					httpHeaderValue = ((Boolean) fieldValue).toString();
				} else if (field.getType().isEnum()) {
					httpHeaderValue = ((Enum<?>) fieldValue).name();
				} else {
					throw new RuntimeException("unsupported field type: " + field.getType().getName());
				}
				httpTransmitter.addHeader(httpHeaderName, httpHeaderValue);
			}
		}

		return bodyField;
	}

	private static void inputValidation(Object dataObject, Field[] fields) throws IllegalArgumentException, IllegalAccessException {
		for (Field field : fields) {
			NotNull notEmptyAnnotation = field.getAnnotation(NotNull.class);
			if (null == notEmptyAnnotation) {
				continue;
			}

			Object fieldValue = field.get(dataObject);
			if (null == fieldValue) {
				throw new IllegalArgumentException("input validation error: empty field: " + field.getName());
			}
		}
	}
}
