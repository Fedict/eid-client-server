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
import be.bosa.eid.client_server.shared.annotation.MessageDiscriminator;
import be.bosa.eid.client_server.shared.annotation.NotNull;
import be.bosa.eid.client_server.shared.annotation.PostConstruct;
import be.bosa.eid.client_server.shared.annotation.ProtocolVersion;
import be.bosa.eid.client_server.shared.annotation.ValidateSemanticalIntegrity;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Unmarshaller component is responsible for governing the process of converting
 * HTTP transported data streams to Java objects.
 * <p>
 * <p>
 * Keep this class stateless as it can be shared across different HTTP requests
 * inside the server service servlet.
 * </p>
 *
 * @author Frank Cornelis
 */
public class Unmarshaller {

	private String protocolMessageDiscriminatorHeaderName;
	private Map<String, Class<?>> protocolMessageClasses;
	private String protocolVersionHeaderName;
	private Integer protocolVersion;

	/**
	 * Main constructor.
	 */
	public Unmarshaller(ProtocolMessageCatalog catalog) {
		processMessageCatalog(catalog);
	}

	private void processMessageCatalog(ProtocolMessageCatalog catalog) {
		this.protocolMessageClasses = new HashMap<>();

		for (Class<?> messageClass : catalog.getCatalogClasses()) {
			Field discriminatorField = findDiscriminatorField(messageClass);

			HttpHeader httpHeaderAnnotation = discriminatorField.getAnnotation(HttpHeader.class);
			String discriminatorHttpHeaderName = httpHeaderAnnotation.value();
			if (this.protocolMessageDiscriminatorHeaderName == null) {
				this.protocolMessageDiscriminatorHeaderName = discriminatorHttpHeaderName;
			} else {
				if (!this.protocolMessageDiscriminatorHeaderName.equals(discriminatorHttpHeaderName)) {
					throw new RuntimeException("discriminator field not the same over all message classes");
				}
			}

			String discriminatorValue;
			try {
				discriminatorValue = (String) discriminatorField.get(null);
			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new RuntimeException("error reading field: " + e.getMessage());
			}
			if (this.protocolMessageClasses.containsKey(discriminatorValue)) {
				throw new RuntimeException("discriminator field not unique for: " + messageClass.getName());
			}
			this.protocolMessageClasses.put(discriminatorValue, messageClass);

			Field protocolVersionField = findProtocolVersionField(messageClass);
			httpHeaderAnnotation = protocolVersionField.getAnnotation(HttpHeader.class);
			String protocolVersionHttpHeaderName = httpHeaderAnnotation.value();
			if (this.protocolVersionHeaderName == null) {
				this.protocolVersionHeaderName = protocolVersionHttpHeaderName;
			} else {
				if (!this.protocolVersionHeaderName.equals(protocolVersionHttpHeaderName)) {
					throw new RuntimeException("protocol version field not the same over all message classes");
				}
			}

			Integer protocolVersion;
			try {
				protocolVersion = (Integer) protocolVersionField.get(null);
			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new RuntimeException("error reading field: " + e.getMessage());
			}
			if (this.protocolVersion == null) {
				this.protocolVersion = protocolVersion;
			} else {
				if (!this.protocolVersion.equals(protocolVersion)) {
					throw new RuntimeException("protocol version not the same over all message classes");
				}
			}
		}
	}

	private Field findDiscriminatorField(Class<?> messageClass) {
		for (Field field : messageClass.getFields()) {
			MessageDiscriminator messageDiscriminatorAnnotation = field.getAnnotation(MessageDiscriminator.class);
			if (messageDiscriminatorAnnotation == null) {
				continue;
			}

			if ((field.getModifiers() & Modifier.FINAL) != Modifier.FINAL) {
				throw new RuntimeException("message discriminator should be final");
			}
			if ((field.getModifiers() & Modifier.STATIC) != Modifier.STATIC) {
				throw new RuntimeException("message discriminator should be static");
			}
			if (!String.class.equals(field.getType())) {
				throw new RuntimeException("message discriminator should be a String");
			}

			HttpHeader httpHeaderAnnotation = field.getAnnotation(HttpHeader.class);
			if (null == httpHeaderAnnotation) {
				throw new RuntimeException("message discriminator should be a HTTP header");
			}

			return field;
		}

		throw new RuntimeException("no message discriminator field found on " + messageClass.getName());
	}

	private Field findProtocolVersionField(Class<?> messageClass) {
		for (Field field : messageClass.getFields()) {
			ProtocolVersion protocolVersionAnnotation = field.getAnnotation(ProtocolVersion.class);
			if (null == protocolVersionAnnotation) {
				continue;
			}

			if ((field.getModifiers() & Modifier.FINAL) != Modifier.FINAL) {
				throw new RuntimeException("protocol version field should be final");
			}
			if ((field.getModifiers() & Modifier.STATIC) != Modifier.STATIC) {
				throw new RuntimeException("protocol version field should be static");
			}
			if (!Integer.TYPE.equals(field.getType())) {
				throw new RuntimeException("protocol version field should be an int");
			}

			HttpHeader httpHeaderAnnotation = field.getAnnotation(HttpHeader.class);
			if (null == httpHeaderAnnotation) {
				throw new RuntimeException("protocol version field should be a HTTP header");
			}

			return field;
		}
		throw new RuntimeException("no protocol version field field found on " + messageClass.getName());
	}

	/**
	 * Receive a certain transfer object from the given HTTP receiver component.
	 */
	public Object receive(HttpReceiver httpReceiver) {
		verifySecureChannel(httpReceiver);
		verifyProtocolVersion(httpReceiver);

		Class<?> protocolMessageClass = getProtocolMessageClass(httpReceiver);
		Object transferObject;
		try {
			transferObject = protocolMessageClass.newInstance();
		} catch (InstantiationException | IllegalAccessException e) {
			throw new RuntimeException("error: " + e.getMessage(), e);
		}

		injectHttpHeaderFields(httpReceiver, protocolMessageClass, transferObject);
		injectHttpBody(httpReceiver, transferObject, protocolMessageClass.getFields());

		inputValidation(transferObject, protocolMessageClass.getFields());
		semanticValidation(protocolMessageClass, transferObject);

		postConstructSemantics(protocolMessageClass, transferObject);

		return transferObject;
	}

	private void verifySecureChannel(HttpReceiver httpReceiver) {
		if (!httpReceiver.isSecure()) {
			throw new SecurityException("HTTP receiver over unsecure channel");
		}
	}

	private void verifyProtocolVersion(HttpReceiver httpReceiver) {
		String protocolVersionHeader = httpReceiver.getHeaderValue(this.protocolVersionHeaderName);
		if (null == protocolVersionHeader) {
			throw new RuntimeException("no protocol version header");
		}

		Integer protocolVersion = Integer.parseInt(protocolVersionHeader);
		if (!this.protocolVersion.equals(protocolVersion)) {
			throw new RuntimeException("protocol version mismatch");
		}
	}

	private Class<?> getProtocolMessageClass(HttpReceiver httpReceiver) {
		String discriminatorValue = httpReceiver.getHeaderValue(this.protocolMessageDiscriminatorHeaderName);
		Class<?> protocolMessageClass = this.protocolMessageClasses.get(discriminatorValue);
		if (protocolMessageClass == null) {
			throw new RuntimeException("unsupported message: " + discriminatorValue);
		}
		return protocolMessageClass;
	}

	private void injectHttpBody(HttpReceiver httpReceiver, Object transferObject, Field[] fields) {
		Field bodyField = null;
		for (Field field : fields) {
			HttpBody httpBodyAnnotation = field.getAnnotation(HttpBody.class);
			if (httpBodyAnnotation != null) {
				if (bodyField == null) {
					bodyField = field;
				} else {
					throw new RuntimeException("multiple body fields detected");
				}
			}
		}

		if (bodyField != null) {
			byte[] body = httpReceiver.getBody();
			Object bodyValue;
			if (List.class.equals(bodyField.getType())) {
				List<String> bodyList = new LinkedList<>();
				BufferedReader reader = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body)));
				String line;
				try {
					while (null != (line = reader.readLine())) {
						bodyList.add(line);
					}
				} catch (IOException e) {
					throw new RuntimeException("IO error: " + e.getMessage());
				}
				bodyValue = bodyList;
			} else {
				bodyValue = body;
			}
			try {
				bodyField.set(transferObject, bodyValue);
			} catch (Exception e) {
				throw new RuntimeException("error: " + e.getMessage(), e);
			}
		}
	}

	private void postConstructSemantics(Class<?> protocolMessageClass, Object transferObject) {
		Method[] methods = protocolMessageClass.getMethods();
		for (Method method : methods) {
			PostConstruct postConstructAnnotation = method.getAnnotation(PostConstruct.class);
			if (null != postConstructAnnotation) {
				try {
					method.invoke(transferObject);
				} catch (InvocationTargetException e) {
					Throwable methodException = e.getTargetException();
					if (methodException instanceof RuntimeException) {
						throw (RuntimeException) methodException;
					}
					throw new RuntimeException("@PostConstruct method invocation error: " + methodException.getMessage(), methodException);
				} catch (IllegalAccessException e) {
					throw new RuntimeException("@PostConstruct error: " + e.getMessage(), e);
				}
			}
		}
	}

	@SuppressWarnings("unchecked")
	private void semanticValidation(Class<?> protocolMessageClass, Object transferObject) {
		ValidateSemanticalIntegrity validateSemanticalIntegrity = protocolMessageClass.getAnnotation(ValidateSemanticalIntegrity.class);
		if (validateSemanticalIntegrity == null) {
			return;
		}

		SemanticValidator validator;
		try {
			validator = validateSemanticalIntegrity.value().newInstance();
		} catch (InstantiationException | IllegalAccessException e) {
			throw new RuntimeException("error: " + e.getMessage(), e);
		}

		try {
			validator.validate(transferObject);
		} catch (SemanticValidatorException e) {
			throw new RuntimeException("semantic validation error: " + e.getMessage());
		}
	}

	private void inputValidation(Object transferObject, Field[] fields) {
		for (Field field : fields) {
			NotNull notNullAnnotation = field.getAnnotation(NotNull.class);
			if (null == notNullAnnotation) {
				continue;
			}

			// XXX: doesn't make sense for primitive fields
			Object fieldValue;
			try {
				fieldValue = field.get(transferObject);
			} catch (Exception e) {
				throw new RuntimeException("error: " + e.getMessage(), e);
			}
			if (fieldValue == null) {
				throw new RuntimeException("field should not be null: " + field.getName());
			}
		}
	}

	private void injectHttpHeaderFields(HttpReceiver httpReceiver, Class<?> protocolMessageClass, Object transferObject) {
		try {
			for (String headerName : httpReceiver.getHeaderNames()) {
				Field httpHeaderField = findHttpHeaderField(protocolMessageClass, headerName);
				if (httpHeaderField == null) continue;

				String headerValue = httpReceiver.getHeaderValue(headerName);
				if ((httpHeaderField.getModifiers() & Modifier.FINAL) != 0) {
					String constantValue;
					if (String.class.equals(httpHeaderField.getType())) {
						constantValue = (String) httpHeaderField.get(transferObject);
					} else if (Integer.TYPE.equals(httpHeaderField.getType())) {
						constantValue = ((Integer) httpHeaderField.get(transferObject)).toString();
					} else {
						throw new RuntimeException("unsupported type: " + httpHeaderField.getType().getName());
					}

					if (!constantValue.equals(headerValue)) {
						throw new RuntimeException("constant value mismatch: " + httpHeaderField.getName() + "; expected value: " + constantValue + "; actual value: " + headerValue);
					}
				} else {
					if (String.class.equals(httpHeaderField.getType())) {
						httpHeaderField.set(transferObject, headerValue);
					} else if (Integer.TYPE.equals(httpHeaderField.getType()) || Integer.class.equals(httpHeaderField.getType())) {
						Integer intValue = Integer.parseInt(headerValue);
						httpHeaderField.set(transferObject, intValue);
						// TODO make this type handling more generic
					} else if (Boolean.TYPE.equals(httpHeaderField.getType()) || Boolean.class.equals(httpHeaderField.getType())) {
						Boolean boolValue = Boolean.parseBoolean(headerValue);
						httpHeaderField.set(transferObject, boolValue);
					} else if (httpHeaderField.getType().isEnum()) {
						Enum<?> e = (Enum<?>) httpHeaderField.getType().getEnumConstants()[0];
						Object value = Enum.valueOf(e.getClass(), headerValue);
						httpHeaderField.set(transferObject, value);
					} else {
						throw new RuntimeException("unsupported http header field type: " + httpHeaderField.getType());
					}
				}
			}
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	private Field findHttpHeaderField(Class<?> protocolMessageClass, String headerName) {
		if (null == headerName) {
			throw new RuntimeException("header name should not be null");
		}

		Field[] fields = protocolMessageClass.getFields();
		for (Field field : fields) {
			HttpHeader httpHeaderAnnotation = field.getAnnotation(HttpHeader.class);
			if (httpHeaderAnnotation == null) {
				continue;
			}
			String fieldHttpHeaderName = httpHeaderAnnotation.value();
			if (headerName.equalsIgnoreCase(fieldHttpHeaderName)) {
				return field;
			}
		}

		return null;
	}
}
