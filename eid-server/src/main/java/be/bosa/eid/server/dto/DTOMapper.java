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

package be.bosa.eid.server.dto;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Data Transfer Object Mapper.
 *
 * @author Frank Cornelis
 */
public class DTOMapper {

	/**
	 * Maps an object to an object of the given class.
	 *
	 * @param <T>     the type of the class to map to.
	 * @param fromObject    the object to map from.
	 * @param toClass the class to map to.
	 * @return the mapped object.
	 */
	public <T> T map(Object fromObject, Class<T> toClass) {
		if (fromObject == null) return null;

		T to = instantiateClass(toClass);
		Arrays.stream(fromObject.getClass().getDeclaredFields())
				.forEach(fromField -> mapField(fromObject, toClass, to, fromField));
		return to;
	}

	private <T> void mapField(Object from, Class<T> toClass, T to, Field fromField) {
		findMatchingMapsToAnnotations(fromField, toClass).forEach(mapsToAnnotation -> {
			String toFieldName = mapsToAnnotation.field().isEmpty() ? fromField.getName() : mapsToAnnotation.field();
			try {
				getField(toClass, toFieldName).set(to, getAndConvertFieldValue(from, fromField, mapsToAnnotation));
			} catch (IllegalAccessException e) {
				throw new RuntimeException("could not write field " + toFieldName + ": " + e.getMessage(), e);
			}
		});
	}

	@SuppressWarnings("unchecked")
	private Object getAndConvertFieldValue(Object from, Field fromField, MapsTo mapsToAnnotation) {
		Object value;
		try {
			value = fromField.get(from);
		} catch (IllegalAccessException e1) {
			throw new RuntimeException("could not read field: " + fromField.getName());
		}

		Class<? extends ValueConvertor<?, ?>> valueConvertorClass = mapsToAnnotation.convertor();
		if (IdenticalValueConvertor.class.equals(valueConvertorClass)) return value;

		ValueConvertor<Object, Object> valueConvertor = (ValueConvertor<Object, Object>) instantiateClass(valueConvertorClass);

		try {
			value = valueConvertor.convert(value);
		} catch (ValueConvertorException e) {
			throw new RuntimeException("could not convert value of field: " + fromField.getName());
		}

		return value;
	}

	private <T> T instantiateClass(Class<T> clazz) {
		try {
			return clazz.newInstance();
		} catch (InstantiationException | IllegalAccessException e) {
			throw new RuntimeException("could not create new instance of " + clazz.getName());
		}
	}

	private <T> Field getField(Class<T> clazz, String fieldName) {
		try {
			return clazz.getDeclaredField(fieldName);
		} catch (NoSuchFieldException e) {
			throw new RuntimeException("no such target field: " + fieldName);
		}
	}

	private Stream<MapsTo> findMatchingMapsToAnnotations(Field field, Class<?> toClass) {
		Mapping mappingAnnotation = field.getAnnotation(Mapping.class);
		if (mappingAnnotation == null) return Stream.empty();

		return Arrays.stream(mappingAnnotation.value())
				.filter(mapsToAnnotation -> toClass.equals(mapsToAnnotation.value()));
	}
}
