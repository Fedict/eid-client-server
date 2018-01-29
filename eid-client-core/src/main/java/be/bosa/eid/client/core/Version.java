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

package be.bosa.eid.client.core;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * eID Client Version class.
 *
 * @author Frank Cornelis
 */
public class Version {

	public static final String VERSION_PROPERTY = "be.fedict.eid.client.version";

	private final String version;

	public Version() {
		version = loadVersion();
	}

	public String getVersion() {
		return version;
	}

	private String loadVersion() {
		if (this.version != null) {
			return null;
		}

		InputStream applicationPropertiesInputStream = Version.class.getResourceAsStream("application.properties");
		if (applicationPropertiesInputStream == null) {
			return "Application properties resource not found";
		}

		Properties properties = new Properties();
		try {
			properties.load(applicationPropertiesInputStream);
		} catch (IOException e) {
			return "Error loading application properties";
		}

		return (String) properties.get(VERSION_PROPERTY);
	}
}
