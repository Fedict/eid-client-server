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

import be.bosa.eid.client.core.Controller;
import be.bosa.eid.client.core.EidClientFrame;

public class JavaWebStartApplication {

	private final Controller controller;
	private final EidClientFrame eidClientFrame;

	public static void main(String[] args) {
		new JavaWebStartApplication(args).run();
	}

	public JavaWebStartApplication(String[] args) {
		RuntimeImpl runtime = new RuntimeImpl(args);
		eidClientFrame = new EidClientFrame(runtime);
		controller = new Controller(eidClientFrame, runtime);
	}

	private void run() {
		eidClientFrame.setVisible(true);
		controller.run();
	}
}
