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
import be.bosa.commons.eid.client.BeIDCards;
import be.bosa.commons.eid.client.CancelledException;
import be.bosa.commons.eid.client.FileType;
import be.bosa.commons.eid.client.event.BeIDCardListener;
import be.bosa.commons.eid.client.exception.BeIDException;
import be.bosa.commons.eid.client.impl.BeIDDigest;
import be.bosa.commons.eid.dialogs.DefaultBeIDCardsUI;
import be.bosa.commons.eid.dialogs.Messages;
import be.bosa.commons.eid.dialogs.Messages.MESSAGE_ID;
import be.bosa.eid.client.core.io.EIdClientSSLSocketFactory;
import be.bosa.eid.client.core.io.HttpURLConnectionHttpReceiver;
import be.bosa.eid.client.core.io.HttpURLConnectionHttpTransmitter;
import be.bosa.eid.client.core.io.LocalProtocolContext;
import be.bosa.eid.client.core.sc.TaskRunner;
import be.bosa.eid.client_server.shared.message.AdministrationMessage;
import be.bosa.eid.client_server.shared.message.AuthSignRequestMessage;
import be.bosa.eid.client_server.shared.message.AuthSignResponseMessage;
import be.bosa.eid.client_server.shared.message.AuthenticationContract;
import be.bosa.eid.client_server.shared.message.AuthenticationDataMessage;
import be.bosa.eid.client_server.shared.message.AuthenticationRequestMessage;
import be.bosa.eid.client_server.shared.message.CheckClientMessage;
import be.bosa.eid.client_server.shared.message.ClientEnvironmentMessage;
import be.bosa.eid.client_server.shared.message.ClientServerProtocolMessageCatalog;
import be.bosa.eid.client_server.shared.message.ContinueInsecureMessage;
import be.bosa.eid.client_server.shared.message.FileDigestsDataMessage;
import be.bosa.eid.client_server.shared.message.FilesDigestRequestMessage;
import be.bosa.eid.client_server.shared.message.FinishedMessage;
import be.bosa.eid.client_server.shared.message.HelloMessage;
import be.bosa.eid.client_server.shared.message.IdentificationRequestMessage;
import be.bosa.eid.client_server.shared.message.IdentityDataMessage;
import be.bosa.eid.client_server.shared.message.InsecureClientMessage;
import be.bosa.eid.client_server.shared.message.SignCertificatesDataMessage;
import be.bosa.eid.client_server.shared.message.SignCertificatesRequestMessage;
import be.bosa.eid.client_server.shared.message.SignRequestMessage;
import be.bosa.eid.client_server.shared.message.SignatureDataMessage;
import be.bosa.eid.client_server.shared.protocol.ProtocolException;
import be.bosa.eid.client_server.shared.protocol.ProtocolStateMachine;
import be.bosa.eid.client_server.shared.protocol.Transport;
import be.bosa.eid.client_server.shared.protocol.Unmarshaller;

import javax.smartcardio.CardPermission;
import javax.swing.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.security.AccessController;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * Controller component. Contains the eID logic. Interacts with {@link View} and
 * {@link Runtime} for outside world communication.
 *
 * @author Frank Cornelis
 */
public class Controller {

	private final List<String> SUPPORTED_FILES_DIGEST_ALGOS = Arrays.asList("SHA-256", "SHA-384", "SHA-512");


	private final EidClientFrame view;
	private final Runtime runtime;
	private final BeIDCards beIDCards;
	private final ProtocolStateMachine protocolStateMachine;
	private static final int BUFFER_SIZE = 1024 * 10;
	private final String requestId;

	public Controller(EidClientFrame view, Runtime runtime) {
		this.view = view;
		this.runtime = runtime;

		this.beIDCards = new BeIDCards(new DefaultBeIDCardsUI());
		this.protocolStateMachine = new ProtocolStateMachine(new LocalProtocolContext(view));
		this.requestId = UUID.randomUUID().toString();
	}

	private Object sendMessage(Object message) throws IOException, ProtocolException {
		addDetailMessage("Sending message: " + message.getClass().getSimpleName());
		protocolStateMachine.checkRequestMessage(message);

		Object responseObject = exchangeMessageWithBackend(message);

		addDetailMessage("Response message: " + responseObject.getClass().getSimpleName());
		this.protocolStateMachine.checkResponseMessage(message, responseObject);
		return responseObject;
	}

	private Object exchangeMessageWithBackend(Object message) throws IOException {
		HttpURLConnection connection = getServerConnection();
		HttpURLConnectionHttpTransmitter httpTransmitter = new HttpURLConnectionHttpTransmitter(connection);
		Transport.transfer(message, httpTransmitter);

		int responseCode = connection.getResponseCode();
		if (responseCode != HttpURLConnection.HTTP_OK) {
			String msg;
			if (HttpURLConnection.HTTP_NOT_FOUND == responseCode) {
				msg = "HTTP NOT FOUND! eID Server not running?";
			} else {
				msg = Integer.toString(responseCode);
			}
			view.addDetailMessage("HTTP response code: " + msg);
			printHttpResponseContent(connection);
			throw new IOException("Error sending message to service. HTTP status code: " + msg);
		}

		Unmarshaller unmarshaller = new Unmarshaller(new ClientServerProtocolMessageCatalog());
		HttpURLConnectionHttpReceiver httpReceiver = new HttpURLConnectionHttpReceiver(connection);
		return unmarshaller.receive(httpReceiver);
	}

	private void printHttpResponseContent(HttpURLConnection connection) {
		InputStream errorStream = connection.getErrorStream();
		if (errorStream == null) {
			return;
		}
		BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream));
		String line;
		try {
			while ((line = reader.readLine()) != null) {
				this.view.addDetailMessage(line);
			}
		} catch (IOException e) {
			this.view.addDetailMessage("I/O error: " + e.getMessage());
		}
	}

	public void run() {
		addDetailMessage("eID Client - Copyright (C) 2018 - 2018 BOSA.");
		addDetailMessage("Released under GNU LGPL version 3.0 license.");
		addDetailMessage("More info: https://github.com/Fedict/eid-client-server");

		try {
			if (!hasSmartCardPermission()) return;
			if (!isCodeBaseSecure()) return;

			AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
				addDetailMessage("Running privileged code...");
				runPrivileged();
				return null;
			});
		} catch (Throwable t) {
			showError(t);
		}

		delayedClose();
	}

	private boolean hasSmartCardPermission() {
		addDetailMessage("Checking smart card access...");

		SecurityManager securityManager = System.getSecurityManager();
		if (securityManager == null) {
			addDetailMessage("No security manager found.");
			return true;
		}

		try {
			securityManager.checkPermission(new CardPermission("*", "*"));
		} catch (SecurityException e) {
			setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
			addDetailMessage("eID Client is not authorized to access smart cards. Make sure your code is signed!");
			return false;
		}

		return true;
	}

	private boolean isCodeBaseSecure() {
		addDetailMessage("Checking web application trust...");
		URL codeBase = runtime.getCodeBase();
		boolean isHttps = "https".equals(codeBase.getProtocol());
		boolean isLocalHost = "localhost".equals(codeBase.getHost());

		if (!isHttps && !isLocalHost) {
			setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
			addDetailMessage("Web application not trusted.");
			addDetailMessage("Use the web application via \"https\" instead of \"http\"");
			return false;
		}

		if (!isHttps) {
			addDetailMessage("Trusting localhost web applications");
		}

		return true;
	}

	private void runPrivileged() {
		printEnvironment();

		try {
			String language = runtime.getLanguage().orElse("en");
			HelloMessage helloMessage = new HelloMessage(language, requestId);
			Object resultMessage = sendMessage(helloMessage);
			if (resultMessage instanceof CheckClientMessage) {
				addDetailMessage("Need to check the client secure environment...");
				ClientEnvironmentMessage clientEnvMessage = new ClientEnvironmentMessage();
				clientEnvMessage.javaVersion = System.getProperty("java.version");
				clientEnvMessage.javaVendor = System.getProperty("java.vendor");
				clientEnvMessage.osName = System.getProperty("os.name");
				clientEnvMessage.osArch = System.getProperty("os.arch");
				clientEnvMessage.osVersion = System.getProperty("os.version");

				resultMessage = sendMessage(clientEnvMessage);
				if (resultMessage instanceof InsecureClientMessage) {
					InsecureClientMessage insecureClientMessage = (InsecureClientMessage) resultMessage;
					if (insecureClientMessage.warnOnly) {
						int result = JOptionPane.showConfirmDialog(view,
								"Your system has been marked as insecure client environment.\n"
										+ "Do you want to continue the eID operation?",
								"Insecure Client Environment", JOptionPane.OK_CANCEL_OPTION,
								JOptionPane.WARNING_MESSAGE);
						if (JOptionPane.OK_OPTION != result) {
							setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
							addDetailMessage("insecure client environment");
							return;
						}
						resultMessage = sendMessage(new ContinueInsecureMessage());
					} else {
						JOptionPane.showMessageDialog(view,
								"Your system has been marked as insecure client environment.",
								"Insecure Client Environment", JOptionPane.ERROR_MESSAGE);
						setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
						addDetailMessage("received an insecure client environment message");
						return;
					}
				}
			}

			if (resultMessage instanceof AdministrationMessage) {
				AdministrationMessage administrationMessage = (AdministrationMessage) resultMessage;
				boolean changePin = administrationMessage.changePin;
				boolean unblockPin = administrationMessage.unblockPin;
				boolean removeCard = administrationMessage.removeCard;
				boolean logoff = administrationMessage.logoff;
				boolean requireSecureReader = administrationMessage.requireSecureReader;
				addDetailMessage("change pin: " + changePin);
				addDetailMessage("unblock pin: " + unblockPin);
				addDetailMessage("remove card: " + removeCard);
				addDetailMessage("logoff: " + logoff);
				addDetailMessage("require secure reader: " + requireSecureReader);
				administration(unblockPin, changePin, logoff, removeCard, requireSecureReader);
			}

			if (resultMessage instanceof FilesDigestRequestMessage) {
				FilesDigestRequestMessage filesDigestRequestMessage = (FilesDigestRequestMessage) resultMessage;
				resultMessage = performFilesDigestOperation(filesDigestRequestMessage.digestAlgo);
			}

			if (resultMessage instanceof SignCertificatesRequestMessage) {
				SignCertificatesRequestMessage signCertificatesRequestMessage = (SignCertificatesRequestMessage) resultMessage;
				SignCertificatesDataMessage signCertificatesDataMessage = performSignCertificatesOperation(
						signCertificatesRequestMessage);
				resultMessage = sendMessage(signCertificatesDataMessage);
			}

			if (resultMessage instanceof SignRequestMessage) {
				SignRequestMessage signRequestMessage = (SignRequestMessage) resultMessage;
				resultMessage = performEidSignOperation(signRequestMessage);
			}

			if (resultMessage instanceof AuthenticationRequestMessage) {
				AuthenticationRequestMessage authnRequest = (AuthenticationRequestMessage) resultMessage;
				resultMessage = performEidAuthnOperation(authnRequest);
			}

			if (resultMessage instanceof AuthSignRequestMessage) {
				AuthSignRequestMessage authSignRequestMessage = (AuthSignRequestMessage) resultMessage;
				resultMessage = performAuthnSignOperation(authSignRequestMessage);
			}

			if (resultMessage instanceof IdentificationRequestMessage) {
				IdentificationRequestMessage identificationRequestMessage = (IdentificationRequestMessage) resultMessage;
				addDetailMessage("include address: " + identificationRequestMessage.includeAddress);
				addDetailMessage("include photo: " + identificationRequestMessage.includePhoto);
				addDetailMessage("include integrity data: " + identificationRequestMessage.includeIntegrityData);
				addDetailMessage("include certificates: " + identificationRequestMessage.includeCertificates);
				addDetailMessage("remove card: " + identificationRequestMessage.removeCard);
				addDetailMessage("identity data usage: " + identificationRequestMessage.identityDataUsage);

				resultMessage = performEidIdentificationOperation(identificationRequestMessage.includeAddress,
						identificationRequestMessage.includePhoto, identificationRequestMessage.includeIntegrityData,
						identificationRequestMessage.includeCertificates, identificationRequestMessage.removeCard,
						identificationRequestMessage.identityDataUsage);
			}

			if (resultMessage instanceof FinishedMessage) {
				FinishedMessage finishedMessage = (FinishedMessage) resultMessage;
				if (finishedMessage.errorCode != null) {
					switch (finishedMessage.errorCode) {
						case CERTIFICATE:
							addDetailMessage("something wrong with your certificate");
							setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
							return;
						case CERTIFICATE_EXPIRED:
							setStatusMessage(Status.ERROR, MESSAGE_ID.CERTIFICATE_EXPIRED_ERROR);
							return;
						case CERTIFICATE_REVOKED:
							setStatusMessage(Status.ERROR, MESSAGE_ID.CERTIFICATE_REVOKED_ERROR);
							return;
						case CERTIFICATE_NOT_TRUSTED:
							setStatusMessage(Status.ERROR, MESSAGE_ID.CERTIFICATE_NOT_TRUSTED);
							return;
						case AUTHORIZATION:
							setStatusMessage(Status.ERROR, MESSAGE_ID.AUTHORIZATION_ERROR);
							this.runtime.gotoAuthorizationErrorPage();
							return;
						default:
					}
					setStatusMessage(Status.ERROR, MESSAGE_ID.GENERIC_ERROR);
					addDetailMessage("error code @ finish: " + finishedMessage.errorCode);
					return;
				}
			}
		} catch (SecurityException e) {
			setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
			addDetailMessage("error: " + e.getMessage());
			return;
		} catch (CancelledException e) {
			view.setStatusMessage(Status.ERROR, MESSAGE_ID.GENERIC_ERROR);
			view.addDetailMessage("User cancelled.");
			runtime.gotoCancelPage();
			return;
		} catch (Throwable e) {
			showError(e);
			return;
		}

		setStatusMessage(Status.NORMAL, MESSAGE_ID.DONE);
		this.runtime.gotoTargetPage(requestId);
	}

	private void delayedClose() {
		try {
			Thread.sleep(10000);
		} catch (InterruptedException e) {
			// ignore since we are closing
		}

		runtime.exitApplication();
	}

	private void showError(Throwable e) {
		addDetailMessage("Error: " + e.getMessage());
		addDetailMessage("Error type: " + e.getClass().getName());

		StringWriter stringWriter = new StringWriter();
		e.printStackTrace(new PrintWriter(stringWriter));
		addDetailMessage("Error trace: " + stringWriter.toString());

		if (e instanceof BeIDException) {
			setStatusMessage(Status.ERROR, MESSAGE_ID.CARD_ERROR);
			addDetailMessage("Card error: " + e.getMessage());
		} else {
			setStatusMessage(Status.ERROR, MESSAGE_ID.GENERIC_ERROR);
		}
	}

	private Object performAuthnSignOperation(AuthSignRequestMessage authSignRequestMessage) throws CancelledException, InterruptedException, ProtocolException, BeIDException, IOException {
		setStatusMessage(Status.NORMAL, MESSAGE_ID.DETECTING_CARD);
		try (BeIDCard beidCard = getBeidCard()) {
			addDetailMessage("Auth sign request...");
			setStatusMessage(Status.NORMAL, MESSAGE_ID.AUTHENTICATING);

			if (!view.confirmAuthenticationSignature(beidCard, authSignRequestMessage.message)) {
				throw new CancelledException();
			}

			byte[] digestValue = authSignRequestMessage.computedDigestValue;
			BeIDDigest digest = BeIDDigest.getInstance(authSignRequestMessage.digestAlgo);

			byte[] signatureValue = beidCard.sign(digestValue, digest, FileType.AuthentificationCertificate, false);
			if (authSignRequestMessage.logoff) {
				beidCard.logoff();
			}
			AuthSignResponseMessage authSignResponseMessage = new AuthSignResponseMessage(signatureValue);
			return sendMessage(authSignResponseMessage);
		}
	}

	private SignCertificatesDataMessage performSignCertificatesOperation(SignCertificatesRequestMessage signCertificatesRequestMessage) throws CancelledException, BeIDException, InterruptedException, IOException {
		addDetailMessage("Performing sign certificates retrieval operation...");
		setStatusMessage(Status.NORMAL, MESSAGE_ID.DETECTING_CARD);

		try (BeIDCard beidCard = getBeidCard()) {
			boolean includeIdentity = signCertificatesRequestMessage.includeIdentity;
			boolean includeAddress = signCertificatesRequestMessage.includeAddress;
			boolean includePhoto = signCertificatesRequestMessage.includePhoto;
			boolean includeIntegrityData = signCertificatesRequestMessage.includeIntegrityData;

			setStatusMessage(Status.NORMAL, MESSAGE_ID.READING_IDENTITY);

			if (includeIdentity || includeAddress || includePhoto) {
				boolean response = view.askPrivacyQuestion(beidCard, includeAddress, includePhoto, null);
				if (!response) {
					throw new CancelledException();
				}

				setStatusMessage(Status.NORMAL, MESSAGE_ID.OK);
				setStatusMessage(Status.NORMAL, MESSAGE_ID.READING_IDENTITY);
			}

			byte[] signCertFile = beidCard.readFile(FileType.NonRepudiationCertificate);
			addDetailMessage("Size sign cert file: " + signCertFile.length);

			byte[] citizenCaCertFile = beidCard.readFile(FileType.CACertificate);
			addDetailMessage("Size citizen CA cert file: " + citizenCaCertFile.length);

			byte[] rootCaCertFile = beidCard.readFile(FileType.RootCertificate);
			addDetailMessage("Size root CA cert file: " + rootCaCertFile.length);

			byte[] identityFile = null;
			byte[] identitySignFile = null;
			if (includeIdentity) {
				addDetailMessage("reading identity file");
				identityFile = beidCard.readFile(FileType.Identity);
				if (includeIntegrityData) {
					addDetailMessage("reading identity sign file");
					identitySignFile = beidCard.readFile(FileType.IdentitySignature);
				}
			}

			byte[] addressFile = null;
			byte[] addressSignFile = null;
			if (includeAddress) {
				addDetailMessage("reading address file");
				addressFile = beidCard.readFile(FileType.Address);
				if (includeIntegrityData) {
					addDetailMessage("reading address sign file");
					addressSignFile = beidCard.readFile(FileType.AddressSignature);
				}
			}

			byte[] photoFile = null;
			if (includePhoto) {
				addDetailMessage("reading photo file");
				photoFile = beidCard.readFile(FileType.Photo);
			}

			byte[] nrnCertFile = null;
			if (identitySignFile != null || addressSignFile != null) {
				addDetailMessage("reading NRN certificate file");
				nrnCertFile = beidCard.readFile(FileType.RRNCertificate);
			}

			return new SignCertificatesDataMessage(signCertFile, citizenCaCertFile, rootCaCertFile, identityFile,
					addressFile, photoFile, identitySignFile, addressSignFile, nrnCertFile);
		}
	}

	private Object performFilesDigestOperation(String filesDigestAlgo) throws NoSuchAlgorithmException, IOException, ProtocolException {
		File[] selectedFiles = view.selectFilesToSign();

		setStatusMessage(Status.NORMAL, MESSAGE_ID.DIGESTING_FILES);
		FileDigestsDataMessage fileDigestsDataMessage = new FileDigestsDataMessage();
		fileDigestsDataMessage.fileDigestInfos = new LinkedList<>();
		long totalSize = 0;
		for (File selectedFile : selectedFiles) {
			totalSize += selectedFile.length();
		}
		int progressMax = (int) (totalSize / BUFFER_SIZE);
		view.resetProgress(progressMax);

		addDetailMessage("Total data size to digest: " + (totalSize / 1024) + " KiB");
		for (File selectedFile : selectedFiles) {
			addDetailMessage(selectedFile.getAbsolutePath() + ": " + (selectedFile.length() / 1024) + " KiB");

			MessageDigest messageDigest = getMessageDigest(filesDigestAlgo);
			DigestInputStream digestInputStream = new DigestInputStream(new FileInputStream(selectedFile), messageDigest);
			byte[] buffer = new byte[BUFFER_SIZE];
			while (digestInputStream.read(buffer) != -1) {
				view.increaseProgress();
			}
			digestInputStream.close();

			fileDigestsDataMessage.fileDigestInfos.add(filesDigestAlgo);
			fileDigestsDataMessage.fileDigestInfos.add(toHex(messageDigest.digest()));
			fileDigestsDataMessage.fileDigestInfos.add(selectedFile.getName());
		}
		view.setProgressIndeterminate();

		return sendMessage(fileDigestsDataMessage);
	}

	private MessageDigest getMessageDigest(String filesDigestAlgo) throws NoSuchAlgorithmException {
		addDetailMessage("Files digest algorithm: " + filesDigestAlgo);
		if (!SUPPORTED_FILES_DIGEST_ALGOS.contains(filesDigestAlgo)) {
			throw new SecurityException("files digest algo not supported: " + filesDigestAlgo);
		}

		return MessageDigest.getInstance(filesDigestAlgo);
	}


	public static String toHex(byte[] data) {
		StringBuilder stringBuilder = new StringBuilder();
		for (byte b : data) {
			stringBuilder.append(String.format("%02X", b));
		}

		return stringBuilder.toString();
	}

	private FinishedMessage performEidSignOperation(SignRequestMessage signRequestMessage) throws CancelledException, BeIDException, InterruptedException, IOException, ProtocolException {
		try (BeIDCard beidCard = getBeidCard()) {
			boolean logoff = signRequestMessage.logoff;
			boolean removeCard = signRequestMessage.removeCard;
			boolean requireSecureReader = signRequestMessage.requireSecureReader;
			addDetailMessage("logoff: " + logoff);
			addDetailMessage("remove card: " + removeCard);
			addDetailMessage("require secure smart card reader: " + requireSecureReader);
			setStatusMessage(Status.NORMAL, MESSAGE_ID.DETECTING_CARD);

			setStatusMessage(Status.NORMAL, MESSAGE_ID.SIGNING);
			boolean response = this.view.confirmSigning(beidCard, signRequestMessage.description, signRequestMessage.digestAlgo);
			if (!response) {
				throw new CancelledException();
			}

			byte[] signatureValue = beidCard.sign(signRequestMessage.digestValue, BeIDDigest.getInstance(signRequestMessage.digestAlgo), FileType.NonRepudiationCertificate, requireSecureReader);

			int maxProgress = 0;
			maxProgress += (1050 / 255) + 1; // sign cert file
			maxProgress += (1050 / 255) + 1; // CA cert file
			maxProgress += (1050 / 255) + 1; // Root cert file
			this.view.resetProgress(maxProgress);

			byte[] signCertFile = beidCard.readFile(FileType.NonRepudiationCertificate);
			byte[] citizenCaCertFile = beidCard.readFile(FileType.CACertificate);
			byte[] rootCaCertFile = beidCard.readFile(FileType.RootCertificate);

			this.view.setProgressIndeterminate();

			if (signRequestMessage.logoff && !signRequestMessage.removeCard) {
				beidCard.logoff();
			}
			if (signRequestMessage.removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				beidCard.removeCard();
			}

			SignatureDataMessage signatureDataMessage = new SignatureDataMessage(signatureValue, signCertFile, citizenCaCertFile, rootCaCertFile);
			Object responseMessage = sendMessage(signatureDataMessage);
			if (!(responseMessage instanceof FinishedMessage)) {
				throw new ProtocolException("Finish expected");
			}

			return (FinishedMessage) responseMessage;
		}
	}

	private void administration(boolean unblockPin, boolean changePin, boolean logoff, boolean removeCard, boolean requireSecureReader) throws BeIDException, InterruptedException, CancelledException {
		try (BeIDCard beidCard = getBeidCard()) {
			if (unblockPin) {
				setStatusMessage(Status.NORMAL, Messages.MESSAGE_ID.PIN_UNBLOCK);
				beidCard.unblockPin(requireSecureReader);
			}
			if (changePin) {
				setStatusMessage(Status.NORMAL, Messages.MESSAGE_ID.PIN_CHANGE);
				beidCard.changePin(requireSecureReader);
			}
			if (logoff) {
				beidCard.logoff();
			}
			if (removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				beidCard.removeCard();
			}
		}
	}

	private Object performEidAuthnOperation(AuthenticationRequestMessage authnRequest) throws CancelledException, IOException, BeIDException, InterruptedException, GeneralSecurityException, ProtocolException {
		if (authnRequest.challenge.length < 20) {
			throw new SecurityException("challenge should be at least 20 bytes long.");
		}

		try (BeIDCard beidCard = getBeidCard()) {
			addDetailMessage("Include hostname: " + authnRequest.includeHostname);
			addDetailMessage("Include inet address: " + authnRequest.includeInetAddress);
			addDetailMessage("Remove card after authn: " + authnRequest.removeCard);
			addDetailMessage("Logoff: " + authnRequest.logoff);
			addDetailMessage("Pre-logoff: " + authnRequest.preLogoff);
			addDetailMessage("TLS session Id channel binding: " + authnRequest.sessionIdChannelBinding);
			addDetailMessage("Server certificate channel binding: " + authnRequest.serverCertificateChannelBinding);
			addDetailMessage("Include identity: " + authnRequest.includeIdentity);
			addDetailMessage("Include certificates: " + authnRequest.includeCertificates);
			addDetailMessage("Include address: " + authnRequest.includeAddress);
			addDetailMessage("Include photo: " + authnRequest.includePhoto);

			addDetailMessage("Include integrity data: " + authnRequest.includeIntegrityData);
			addDetailMessage("Require secure smart card reader: " + authnRequest.requireSecureReader);
			addDetailMessage("Transaction message: " + authnRequest.transactionMessage);

			String hostname;
			if (authnRequest.includeHostname) {
				URL documentBase = runtime.getEidServiceUrl();
				hostname = documentBase.getHost();
				addDetailMessage("Hostname: " + hostname);
			} else {
				hostname = null;
			}

			InetAddress inetAddress;
			if (authnRequest.includeInetAddress) {
				URL documentBase = this.runtime.getEidServiceUrl();
				inetAddress = InetAddress.getByName(documentBase.getHost());
				addDetailMessage("Inet address: " + inetAddress.getHostAddress());
			} else {
				inetAddress = null;
			}

			byte[] sessionId = authnRequest.sessionIdChannelBinding ? EIdClientSSLSocketFactory.getActualSessionId() : null;

			byte[] encodedServerCertificate;
			if (authnRequest.serverCertificateChannelBinding) {
				encodedServerCertificate = EIdClientSSLSocketFactory.getActualEncodedServerCertificate();
			} else {
				encodedServerCertificate = null;
			}

			setStatusMessage(Status.NORMAL, MESSAGE_ID.AUTHENTICATING);


			if (authnRequest.includeIdentity || authnRequest.includeAddress || authnRequest.includePhoto) {
				if (!view.askPrivacyQuestion(beidCard, authnRequest.includeAddress, authnRequest.includePhoto, null)) {
					throw new CancelledException();
				}
			}

			if (authnRequest.preLogoff) {
				this.view.addDetailMessage("Performing a pre-logoff");
				beidCard.logoff();
			}

			byte[] salt = beidCard.getChallenge(20);
			AuthenticationContract authenticationContract = new AuthenticationContract(salt, hostname, inetAddress,
					sessionId, encodedServerCertificate, authnRequest.challenge);
			byte[] signatureValue = beidCard.signAuthn(authenticationContract.calculateToBeSigned(), authnRequest.requireSecureReader);

			byte[] signedTransactionMessage = null;
			if (authnRequest.transactionMessage != null) {
				signedTransactionMessage = beidCard.signTransactionMessage(authnRequest.transactionMessage, authnRequest.requireSecureReader);
			}

			int maxProgress = 0;
			maxProgress += (1050 / 255) + 1; // authn cert file
			maxProgress += (1050 / 255) + 1; // CA cert file
			maxProgress += (1050 / 255) + 1; // Root cert file
			if (authnRequest.includeIdentity) {
				maxProgress++;
			}
			if (authnRequest.includeAddress) {
				maxProgress++;
			}
			if (authnRequest.includePhoto) {
				maxProgress += 3000 / 255;
			}
			if (authnRequest.includeIntegrityData) {
				if (authnRequest.includeIdentity) {
					maxProgress++; // identity signature file
				}
				if (authnRequest.includeAddress) {
					maxProgress++; // address signature file
				}
				maxProgress += (1050 / 255) + 1; // RRN certificate file
			}
			this.view.resetProgress(maxProgress);

			TaskRunner taskRunner = new TaskRunner(this.view);
			byte[] authnCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.AuthentificationCertificate));
			byte[] citCaCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.CACertificate));
			byte[] rootCaCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.RootCertificate));
			byte[] signCertFile = null;
			if (authnRequest.includeCertificates) {
				addDetailMessage("Reading sign certificate file...");
				signCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.NonRepudiationCertificate));
				addDetailMessage("Size non-repud cert file: " + signCertFile.length);
			}
			if (authnRequest.includeIdentity || authnRequest.includeAddress || authnRequest.includePhoto) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.READING_IDENTITY);
			}

			byte[] identityData = null;
			if (authnRequest.includeIdentity) {
				identityData = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.Identity));
			}
			byte[] addressData = null;
			if (authnRequest.includeAddress) {
				addressData = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.Address));
			}
			byte[] photoData = null;
			if (authnRequest.includePhoto) {
				photoData = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.Photo));
			}
			byte[] identitySignatureData = null;
			byte[] addressSignatureData = null;
			byte[] rrnCertData = null;
			if (authnRequest.includeIntegrityData) {
				if (authnRequest.includeIdentity) {
					identitySignatureData = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.IdentitySignature));
				}
				if (authnRequest.includeAddress) {
					addressSignatureData = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.AddressSignature));
				}
				rrnCertData = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.RRNCertificate));
			}

			this.view.setProgressIndeterminate();

			if (authnRequest.logoff && !authnRequest.removeCard) {
				beidCard.logoff();
			}
			if (authnRequest.removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				beidCard.removeCard();
			}

			AuthenticationDataMessage authenticationDataMessage = new AuthenticationDataMessage(salt, sessionId,
					signatureValue, authnCertFile, citCaCertFile, rootCaCertFile, signCertFile, identityData, addressData,
					photoData, identitySignatureData, addressSignatureData, rrnCertData, encodedServerCertificate,
					signedTransactionMessage);
			return sendMessage(authenticationDataMessage);
		}
	}

	private void printEnvironment() {
		Version version = new Version();
		addDetailMessage("eID client version: " + version.getVersion());
		addDetailMessage("Java version: " + System.getProperty("java.version"));
		addDetailMessage("Java vendor: " + System.getProperty("java.vendor"));
		addDetailMessage("OS: " + System.getProperty("os.name"));
		addDetailMessage("OS version: " + System.getProperty("os.version"));
		addDetailMessage("OS arch: " + System.getProperty("os.arch"));
		addDetailMessage("Web application URL: " + this.runtime.getEidServiceUrl());
		addDetailMessage("Current time: " + new Date());
	}

	public void addDetailMessage(String detailMessage) {
		this.view.addDetailMessage(detailMessage);
	}

	private FinishedMessage performEidIdentificationOperation(boolean includeAddress, boolean includePhoto,
															  boolean includeIntegrityData, boolean includeCertificates,
															  boolean removeCard, String identityDataUsage)
			throws CancelledException, BeIDException, InterruptedException, IOException, ProtocolException {
		try (BeIDCard beidCard = getBeidCard()) {

			setStatusMessage(Status.NORMAL, MESSAGE_ID.READING_IDENTITY);

			if (!view.askPrivacyQuestion(beidCard, includeAddress, includePhoto, identityDataUsage)) {
				throw new CancelledException();
			}

			addDetailMessage("Reading identity file...");

			int maxProgress = 1; // identity file
			if (includeAddress) {
				maxProgress++;
			}
			if (includePhoto) {
				maxProgress += 3000 / 255;
			}
			if (includeIntegrityData) {
				maxProgress++; // identity signature file
				if (includeAddress) {
					maxProgress++; // address signature file
				}
				maxProgress += (1050 / 255) + 1; // RRN certificate file
				maxProgress += (1050 / 255) + 1; // Root certificate file
			}
			if (includeCertificates) {
				maxProgress += (1050 / 255) + 1; // authn cert file
				maxProgress += (1050 / 255) + 1; // sign cert file
				maxProgress += (1050 / 255) + 1; // citizen CA cert file
				if (!includeIntegrityData) {
					maxProgress += (1050 / 255) + 1; // root CA cert file
				}
			}
			this.view.resetProgress(maxProgress);

			TaskRunner taskRunner = new TaskRunner(this.view);

			byte[] idFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.Identity));
			addDetailMessage("Size identity file: " + idFile.length);

			byte[] addressFile = null;
			if (includeAddress) {
				addDetailMessage("Read address file...");
				addressFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.Address));
				addDetailMessage("Size address file: " + addressFile.length);
			}

			byte[] photoFile = null;
			if (includePhoto) {
				addDetailMessage("Read photo file...");
				photoFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.Photo));
			}

			byte[] identitySignatureFile = null;
			byte[] addressSignatureFile = null;
			byte[] rrnCertFile = null;
			byte[] rootCertFile = null;
			if (includeIntegrityData) {
				addDetailMessage("Read identity signature file...");
				identitySignatureFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.IdentitySignature));
				if (includeAddress) {
					addDetailMessage("Read address signature file...");
					addressSignatureFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.AddressSignature));
				}
				addDetailMessage("Read national registry certificate file...");
				rrnCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.RRNCertificate));
				addDetailMessage("size RRN cert file: " + rrnCertFile.length);
				addDetailMessage("reading root certificate file...");
				rootCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.RootCertificate));
				addDetailMessage("size Root CA cert file: " + rootCertFile.length);
			}

			byte[] authnCertFile = null;
			byte[] signCertFile = null;
			byte[] caCertFile = null;
			if (includeCertificates) {
				addDetailMessage("reading authn certificate file...");
				authnCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.AuthentificationCertificate));
				addDetailMessage("size authn cert file: " + authnCertFile.length);

				addDetailMessage("reading sign certificate file...");
				signCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.NonRepudiationCertificate));
				addDetailMessage("size non-repud cert file: " + signCertFile.length);

				addDetailMessage("reading citizen CA certificate file...");
				caCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.CACertificate));
				addDetailMessage("size Cit CA cert file: " + caCertFile.length);

				if (rootCertFile == null) {
					addDetailMessage("reading root certificate file...");
					rootCertFile = taskRunner.runWithRetry(beidCard, () -> beidCard.readFile(FileType.RootCertificate));
					addDetailMessage("size Root CA cert file: " + rootCertFile.length);
				}
			}

			this.view.setProgressIndeterminate();

			if (removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				beidCard.removeCard();
			}

			setStatusMessage(Status.NORMAL, MESSAGE_ID.TRANSMITTING_IDENTITY);

			IdentityDataMessage identityData = new IdentityDataMessage(idFile, addressFile, photoFile,
					identitySignatureFile, addressSignatureFile, rrnCertFile, rootCertFile, authnCertFile, signCertFile,
					caCertFile);
			return sendMessage(identityData, FinishedMessage.class);
		}
	}

	private <T> T sendMessage(Object message, Class<T> responseClass) throws IOException, ProtocolException {
		Object responseObject = sendMessage(message);
		if (!responseClass.equals(responseObject.getClass())) {
			throw new RuntimeException("response message not of type: " + responseClass.getName());
		}
		@SuppressWarnings("unchecked")
		T response = (T) responseObject;
		return response;
	}

	private BeIDCard getBeidCard() throws CancelledException {
		setStatusMessage(Status.NORMAL, MESSAGE_ID.DETECTING_CARD);

		BeIDCard card = beIDCards.getOneBeIDCard();
		card.addCardListener(new ProgressBeIDCardListener());
		return card;
	}


	private HttpURLConnection getServerConnection() throws IOException {
		EIdClientSSLSocketFactory.installSocketFactory(this.view);
		return (HttpURLConnection) runtime.getEidServiceUrl().openConnection();
	}

	private void setStatusMessage(Status status, Messages.MESSAGE_ID messageId) {
		this.view.setStatusMessage(status, messageId);
	}

	private class ProgressBeIDCardListener implements BeIDCardListener {
		@Override
		public void notifyReadProgress(FileType fileType, int offset, int estimatedMaxSize) {
			view.increaseProgress();
		}

		@Override
		public void notifySigningBegin(FileType fileType) {
			view.increaseProgress();
		}

		@Override
		public void notifySigningEnd(FileType fileType) {
			view.increaseProgress();
		}
	}

}


