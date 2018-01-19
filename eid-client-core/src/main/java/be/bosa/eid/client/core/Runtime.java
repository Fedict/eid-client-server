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

import java.net.URL;
import java.util.Optional;

public interface Runtime {

	Optional<String> getLanguage();

	URL getEidServerUrl();

	Optional<String> getBackgroundColor();

	Optional<String> getForegroundColor();

	void gotoTargetPage();

	void gotoCancelPage();

	void gotoAuthorizationErrorPage();

	URL getCodeBase();

	void copyToClipboard(String text);

}
