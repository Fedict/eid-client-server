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

/**
 * Interface for a value convertor component.
 *
 * @param <TO>   the type to which to convert to.
 * @param <FROM> the type from which to convert.
 * @author Frank Cornelis
 */
public interface ValueConvertor<FROM, TO> {

	/**
	 * Convert the given object to the convertor data type.
	 *
	 * @param value the object to convert.
	 * @return an object of the data convertor data type type.
	 * @throws ValueConvertorException in case the conversion failed.
	 */
	TO convert(FROM value) throws ValueConvertorException;
}