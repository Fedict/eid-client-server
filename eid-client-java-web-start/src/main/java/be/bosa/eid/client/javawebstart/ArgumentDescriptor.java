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

package be.bosa.eid.client.javawebstart;

import org.apache.commons.cli.Option;

public enum ArgumentDescriptor {

	EID_SERVER_URL("eidServerUrl", true),
	LANGUAGE("language", false),
	TARGET_PAGE("targetPage", false),
	CANCEL_PAGE("cancelPage", false),
	AUTHORIZATION_ERROR_PAGE("authorizationErrorPage", false),
	BACKGROUND_COLOR("backgroundColor", false),
	FOREGROUND_COLOR("foregroundColor", false);

	private final String name;
	private final boolean required;

	ArgumentDescriptor(String name, boolean required) {
		this.name = name;
		this.required = required;
	}

	public String getName() {
		return name;
	}

	public boolean isRequired() {
		return required;
	}

	public Option toOption() {
		return Option.builder(null)
				.hasArg()
				.longOpt(name)
				.required(required)
				.build();
	}
}
