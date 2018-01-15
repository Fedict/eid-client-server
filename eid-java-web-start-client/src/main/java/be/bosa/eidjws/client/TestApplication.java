package be.bosa.eidjws.client;

import be.fedict.commons.eid.client.*;
import be.fedict.commons.eid.consumer.Identity;
import be.fedict.commons.eid.consumer.tlv.TlvParser;

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
