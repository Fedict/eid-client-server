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

import be.bosa.commons.eid.client.BeIDCard;
import be.bosa.commons.eid.client.exception.BeIDException;
import be.bosa.commons.eid.dialogs.Messages;
import be.bosa.commons.eid.dialogs.Messages.MESSAGE_ID;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.util.Locale;

/**
 * The main application frame.
 */
public class EidClientFrame extends JFrame implements View {

	private final be.bosa.eid.client.core.Runtime runtime;

	private JStatusLabel statusLabel;
	private JTextArea detailMessages;
	private Messages messages;
	private JProgressBar progressBar;
	private int progress;

	public EidClientFrame(be.bosa.eid.client.core.Runtime runtime) {
		this.runtime = runtime;
		invokeAndWait(this::initUI);
	}

	private void initUI() {
		setupLocale();
		loadMessages();
		initStyle();

		createComponents();
		setupColors();
	}

	private void setupLocale() {
		Locale locale = runtime.getLanguage()
				.map(Locale::new)
				.orElse(Locale.getDefault());

		setLocale(locale);
	}

	private void loadMessages() {
		Locale locale = getLocale();
		JRootPane.setDefaultLocale(locale);
		messages = Messages.getInstance(locale);
	}

	private void initStyle() {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException e) {
			throw new RuntimeException(e);
		}
	}

	private void createComponents() {
		Container contentPane = getContentPane();
		contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.PAGE_AXIS));
		contentPane.add(createStatusPanel());
		contentPane.add(Box.createVerticalStrut(10));
		contentPane.add(createProgressBar());
		contentPane.add(Box.createVerticalStrut(10));
		contentPane.add(createDetailPanel());

		pack();
	}

	private JProgressBar createProgressBar() {
		progressBar = new JProgressBar();
		progressBar.setIndeterminate(true);
		return progressBar;
	}

	private JPanel createStatusPanel() {
		JPanel statusPanel = new JPanel();
		statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.LINE_AXIS));

		String msg = messages.getMessage(MESSAGE_ID.LOADING);
		statusLabel = new JStatusLabel(msg);
		statusLabel.getAccessibleContext().setAccessibleName(msg);

		statusPanel.add(statusLabel);
		statusPanel.add(Box.createHorizontalGlue());
		return statusPanel;
	}

	private JPanel createDetailPanel() {
		CardLayout cardLayout = new CardLayout();
		JPanel detailPanel = new JPanel(cardLayout);
		detailPanel.add(createDetailsButton(actionEvent -> cardLayout.next(detailPanel)), "button");
		detailPanel.add(createDetailMessages(), "details");

		return detailPanel;
	}

	private JPanel createDetailsButton(ActionListener buttonClicked) {
		String detailsButtonTitle = messages.getMessage(MESSAGE_ID.DETAILS_BUTTON);
		JButton detailButton = new JButton(String.format("%s >>", detailsButtonTitle));
		detailButton.getAccessibleContext().setAccessibleName(detailsButtonTitle);
		detailButton.addActionListener(buttonClicked);

		JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		panel.add(detailButton);
		return panel;
	}

	private JScrollPane createDetailMessages() {
		JMenuItem copyMenuItem = new JMenuItem(messages.getMessage(MESSAGE_ID.COPY_ALL));
		copyMenuItem.addActionListener(e -> runtime.copyToClipboard(detailMessages.getText()));

		JPopupMenu popupMenu = new JPopupMenu();
		popupMenu.add(copyMenuItem);

		detailMessages = new JTextArea(10, 80);
		detailMessages.setEditable(false);
		detailMessages.setLocale(Locale.ENGLISH);
		detailMessages.getAccessibleContext().setAccessibleDescription("Detailed log messages");
		detailMessages.setComponentPopupMenu(popupMenu);

		return new JScrollPane(detailMessages, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	}

	public void setStatusMessage(Status status, MESSAGE_ID messageId) {
		String statusMessage = messages.getMessage(messageId);
		invokeAndWait(() -> {
			statusLabel.setText(statusMessage);
			statusLabel.getAccessibleContext().setAccessibleName(statusMessage);
			statusLabel.invalidate();

			if (status == Status.ERROR) {
				statusLabel.setForeground(Color.RED);
				progressBar.setIndeterminate(false);
			}

			detailMessages.append(statusMessage + "\n");
			detailMessages.setCaretPosition(detailMessages.getDocument().getLength());
		});
	}

	public void addDetailMessage(String detailMessage) {
		invokeAndWait(() -> {
			detailMessages.append(detailMessage + "\n");
			detailMessages.setCaretPosition(detailMessages.getDocument().getLength());
		});
	}

	private void setupColors() {
		runtime.getBackgroundColor().ifPresent(backgroundColorParam -> {
			Color backgroundColor = Color.decode(backgroundColorParam);
			setBackgroundColor(getContentPane(), backgroundColor);
		});

		runtime.getForegroundColor().ifPresent(foregroundColorParam -> {
			Color foregroundColor = Color.decode(foregroundColorParam);
			statusLabel.setForeground(foregroundColor);
			detailMessages.setForeground(foregroundColor);
		});
	}

	private void setBackgroundColor(Container container, Color backgroundColor) {
		for (Component component : container.getComponents()) {
			component.setBackground(backgroundColor);
			if (component instanceof Container) {
				setBackgroundColor((Container) component, backgroundColor);
			}
		}
		container.setBackground(backgroundColor);
	}

	@Override
	public boolean askPrivacyQuestion(BeIDCard beIDCard, boolean includeAddress, boolean includePhoto, String identityDataUsage) {
		String message = String.format("%s\n%s: $%s",
				messages.getMessage(MESSAGE_ID.PRIVACY_QUESTION),
				messages.getMessage(MESSAGE_ID.IDENTITY_INFO),
				messages.getMessage(MESSAGE_ID.IDENTITY_IDENTITY));
		if (includeAddress) message += ", " + messages.getMessage(MESSAGE_ID.IDENTITY_ADDRESS);
		if (includePhoto) message += ", " + messages.getMessage(MESSAGE_ID.IDENTITY_PHOTO);
		if (identityDataUsage != null) message += "\n" + messages.getMessage(MESSAGE_ID.USAGE) + ": " + identityDataUsage;

		return showConfirmDialogWithoutExclusiveAccess(beIDCard, message, "Privacy");
	}

	@Override
	public Component getParentComponent() {
		return this;
	}

	@Override
	public boolean confirmAuthenticationSignature(BeIDCard card, String detailMessage) {
		String message = this.messages.getMessage(MESSAGE_ID.PROTOCOL_SIGNATURE) + "\n" + detailMessage;
		return showConfirmDialogWithoutExclusiveAccess(card, message, "eID Authentication Signature");
	}

	@Override
	public boolean confirmSigning(BeIDCard card, String description, String digestAlgo) {
		String signatureCreationLabel = messages.getMessage(MESSAGE_ID.SIGNATURE_CREATION);
		String signQuestionLabel = messages.getMessage(MESSAGE_ID.SIGN_QUESTION);
		String signatureAlgoLabel = messages.getMessage(MESSAGE_ID.SIGNATURE_ALGO);
		String message = String.format("%s \"%s\"?\n%s: %s with RSA", signQuestionLabel, description, signatureAlgoLabel, digestAlgo);

		return showConfirmDialogWithoutExclusiveAccess(card, message, signatureCreationLabel);
	}

	@Override
	public File[] selectFilesToSign() {
		setStatusMessage(Status.NORMAL, MESSAGE_ID.SELECT_FILES);

		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setMultiSelectionEnabled(true);
		int returnCode = fileChooser.showDialog(getParentComponent(), this.messages.getMessage(MESSAGE_ID.SELECT_FILES));
		if (returnCode != JFileChooser.APPROVE_OPTION) {
			throw new RuntimeException("File selection aborted");
		}

		return fileChooser.getSelectedFiles();
	}

	private boolean showConfirmDialogWithoutExclusiveAccess(BeIDCard card, Object message, String title) {
		try {
			card.endExclusive();
		} catch (BeIDException e) {
			addDetailMessage("Could not end exclusive card access");
			return false;
		}

		try {
			int dialogResult = JOptionPane.showConfirmDialog(this, message, title, JOptionPane.YES_NO_OPTION);
			return dialogResult == JOptionPane.YES_OPTION;
		} finally {
			try {
				card.beginExclusive();
			} catch (BeIDException e) {
				addDetailMessage("Could not acquire exclusive card access");

				//noinspection ReturnInsideFinallyBlock
				return false;
			}
		}
	}

	public void resetProgress(int max) {
		progressBar.setMinimum(0);
		progressBar.setMaximum(max);
		progressBar.setIndeterminate(false);
		progressBar.setValue(0);
		progress = 0;
	}

	public void setProgressIndeterminate() {
		progressBar.setIndeterminate(true);
	}

	public void increaseProgress() {
		progress++;
		progressBar.setValue(progress);
	}

	private void invokeAndWait(Runnable action) {
		try {
			SwingUtilities.invokeAndWait(action);
		} catch (InterruptedException e) {
			throw new RuntimeException("Interrupted", e);
		} catch (InvocationTargetException e) {
			if (e.getCause() instanceof RuntimeException) {
				throw (RuntimeException) e.getCause();
			}
			throw new RuntimeException(e.getCause());
		}
	}
}
