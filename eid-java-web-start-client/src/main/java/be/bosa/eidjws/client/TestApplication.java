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

package be.bosa.eidjws.client;

import be.bosa.commons.eid.client.BeIDCard;
import be.bosa.commons.eid.client.BeIDCards;
import be.bosa.commons.eid.client.CancelledException;
import be.bosa.commons.eid.client.FileType;
import be.bosa.commons.eid.consumer.Identity;
import be.bosa.commons.eid.consumer.tlv.TlvParser;

import javax.smartcardio.CardException;
import javax.swing.*;
import java.awt.*;
import java.io.IOException;

public class TestApplication {

	private final JFrame frame;

	public static void main(String[] args) {
		new TestApplication();
	}

	private TestApplication() {
		frame = new JFrame("eID Test Application");
		frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

		JButton readEIdButton = new JButton("Read eID info");
		frame.getContentPane().add(readEIdButton, BorderLayout.CENTER);
		readEIdButton.addActionListener(event -> readEId());

		frame.pack();
		frame.setVisible(true);
	}

	private void readEId() {
		// TODO Handle this in a new thread
		// TODO Translations
		try (BeIDCards beIDCards = new BeIDCards()) {
			try (BeIDCard card = beIDCards.getOneBeIDCard()) {
				byte[] idData = card.readFile(FileType.Identity);
				Identity identity = TlvParser.parse(idData, Identity.class);
				JOptionPane.showMessageDialog(frame, String.format("This is %s's card.", identity.firstName));
			}
		} catch (InterruptedException|CardException|IOException e) {
			throw new RuntimeException(e);
		} catch (CancelledException e) {
			JOptionPane.showMessageDialog(frame, "User cancelled");
		}
	}

}
