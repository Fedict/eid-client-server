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

package be.bosa.eid.server;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * eID Special Status.
 *
 * @author Frank Cornelis
 */
public enum SpecialStatus implements Serializable {
	NO_STATUS("0", false, false, false),

	WHITE_CANE("1", true, false, false),

	EXTENDED_MINORITY("2", false, true, false),

	WHITE_CANE_EXTENDED_MINORITY("3", true, true, false),

	YELLOW_CANE("4", false, false, true),

	YELLOW_CANE_EXTENDED_MINORITY("5", false, true, true);

	private final String strValue;

	private final boolean whiteCane;

	private final boolean extendedMinority;

	private final boolean yellowCane;

	private static final Map<String, SpecialStatus> map = getSpecialStatuses();

	private static Map<String, SpecialStatus> getSpecialStatuses() {
		Map<String, SpecialStatus> map = new HashMap<>();
		for (SpecialStatus specialStatus : SpecialStatus.values()) {
			String value = specialStatus.strValue;
			if (map.containsKey(value)) {
				throw new RuntimeException("duplicate special status: " + value);
			}
			map.put(value, specialStatus);
		}
		return map;
	}

	SpecialStatus(String strValue, boolean whiteCane, boolean extendedMinority, boolean yellowCane) {
		this.strValue = strValue;
		this.whiteCane = whiteCane;
		this.extendedMinority = extendedMinority;
		this.yellowCane = yellowCane;
	}

	/**
	 * Returns whether the citizen has a white cane. Blind people.
	 */
	public boolean hasWhiteCane() {
		return this.whiteCane;
	}

	/**
	 * Extended Minority.
	 */
	public boolean hasExtendedMinority() {
		return this.extendedMinority;
	}

	/**
	 * Returns whether the citizen has a yellow cane. Partially sighted people.
	 */
	public boolean hasYellowCane() {
		return this.yellowCane;
	}

	/**
	 * Return whether the citizen has a bad sight. This means the citizen has
	 * either a while cane or a yellow cane.
	 */
	public boolean hasBadSight() {
		return this.whiteCane || this.yellowCane;
	}

	/**
	 * Converts the given string to the corresponding special status enum.
	 */
	public static SpecialStatus toSpecialStatus(String value) {
		return SpecialStatus.map.get(value);
	}
}
