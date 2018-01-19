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

import javax.accessibility.AccessibleContext;
import javax.accessibility.AccessibleRole;
import javax.swing.*;
import java.awt.*;

/**
 * JLabel with accessible role "alert", used by the client to provide feedback
 * like "Insert eid card"
 *
 * @author Bart Hanssens
 */
public class JStatusLabel extends JLabel {

	public JStatusLabel(String msg) {
		super(msg);
		Font font = this.getFont();
		font = font.deriveFont((float) font.getSize() * 2);
		font = font.deriveFont(Font.BOLD);
		this.setFont(font);
	}

	@Override
	public AccessibleContext getAccessibleContext() {
		if (accessibleContext == null) {
			accessibleContext = new AccessibleJStatusLabel();
		}
		return accessibleContext;
	}

	protected class AccessibleJStatusLabel extends AccessibleJLabel {
		@Override
		public AccessibleRole getAccessibleRole() {
			return AccessibleRole.ALERT;
		}
	}
}
