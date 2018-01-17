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

package be.bosa.eid.server.impl.tlv;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Tag-Length-Value parser. The TLV-format is used in the eID card for encoding
 * of the identity and address files.
 *
 * @author Frank Cornelis
 */
public class TlvParser {

	private static final Log LOG = LogFactory.getLog(TlvParser.class);

	private TlvParser() {
		super();
	}

	/**
	 * Parses the given file using the meta-data annotations within the tlvClass
	 * parameter.
	 */
	public static <T> T parse(byte[] file, Class<T> tlvClass) {
		T t;
		try {
			t = parseThrowing(file, tlvClass);
		} catch (Exception e) {
			throw new RuntimeException("error parsing file: " + tlvClass.getName(), e);
		}
		return t;
	}

	private static byte[] copy(byte[] source, int idx, int count) {
		byte[] result = new byte[count];
		System.arraycopy(source, idx, result, 0, count);
		return result;
	}

	private static <T> T parseThrowing(byte[] file, Class<T> tlvClass) throws InstantiationException,
			IllegalAccessException, DataConvertorException, UnsupportedEncodingException {
		Field[] fields = tlvClass.getDeclaredFields();
		Map<Integer, Set<Field>> tlvFields = new HashMap<>();
		for (Field field : fields) {
			TlvField tlvFieldAnnotation = field.getAnnotation(TlvField.class);
			if (tlvFieldAnnotation == null) {
				continue;
			}
			Set<Field> fieldSet = tlvFields.computeIfAbsent(tlvFieldAnnotation.value(), k -> new HashSet<>());
			fieldSet.add(field);
		}
		T tlvObject = tlvClass.newInstance();

		int idx = 0;
		while (idx < file.length - 1) {
			byte tag = file[idx];
			idx++;
			byte lengthByte = file[idx];
			int length = lengthByte & 0x7f;
			while ((lengthByte & 0x80) == 0x80) {
				idx++;
				lengthByte = file[idx];
				length = (length << 7) + (lengthByte & 0x7f);
			}
			idx++;
			if (0 == tag) {
				idx += length;
				continue;
			}
			if (tlvFields.containsKey((int) tag)) {
				Set<Field> tlvFieldSet = tlvFields.get((int) tag);
				for (Field tlvField : tlvFieldSet) {
					Class<?> tlvType = tlvField.getType();
					ConvertData convertDataAnnotation = tlvField.getAnnotation(ConvertData.class);
					byte[] tlvValue = copy(file, idx, length);
					Object fieldValue;
					if (convertDataAnnotation != null) {
						Class<? extends DataConvertor<?>> dataConvertorClass = convertDataAnnotation.value();
						DataConvertor<?> dataConvertor = dataConvertorClass.newInstance();
						fieldValue = dataConvertor.convert(tlvValue);
					} else if (String.class == tlvType) {
						fieldValue = new String(tlvValue, "UTF-8");
					} else if (Boolean.TYPE == tlvType) {
						fieldValue = true;
					} else if (tlvType.isArray() && Byte.TYPE == tlvType.getComponentType()) {
						fieldValue = tlvValue;
					} else {
						throw new IllegalArgumentException("unsupported field type: " + tlvType.getName());
					}
					LOG.debug("setting field: " + tlvField.getName());
					if (tlvField.get(tlvObject) != null && !tlvField.getType().isPrimitive()) {
						throw new RuntimeException("field was already set: " + tlvField.getName());
					}
					tlvField.setAccessible(true);
					tlvField.set(tlvObject, fieldValue);
				}
			} else {
				LOG.debug("unknown tag: " + (tag & 0xff) + ", length: " + length);
			}
			idx += length;
		}
		return tlvObject;
	}
}
