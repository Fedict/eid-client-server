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

package be.bosa.eid.server.impl.handler;

import be.bosa.eid.server.dto.DTOMapper;

public class Util {

	static String getDigestAlgo(int hashSize) {
		switch (hashSize) {
			case 20:
				return "SHA-1";
			case 28:
				return "SHA-224";
			case 32:
				return "SHA-256";
			case 48:
				return "SHA-384";
			case 64:
				return "SHA-512";
		}

		throw new RuntimeException("Failed to find guess algorithm for hash size of " + hashSize + " bytes");
	}

	static byte[] trimRight(byte[] addressFile) {
		int idx;
		for (idx = 0; idx < addressFile.length; idx++) {
			if (0 == addressFile[idx]) {
				break;
			}
		}
		byte[] result = new byte[idx];
		System.arraycopy(addressFile, 0, result, 0, idx);
		return result;
	}

	static <T> T map(Object object, Class<T> toClass) {
		return new DTOMapper().map(object, toClass);
	}
}
