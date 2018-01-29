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

package be.bosa.eid.client.core.io;

import be.bosa.eid.client.core.View;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;

/**
 * eID Client specific implementation of an SSL Socket Factory. This is actually
 * a decorator component over the original SSL socket factory object.
 * <p>
 * <p>
 * Makes sure that the SSL session doesn't change during eID Client operations.
 * Gives us access to the SSL session identifier and SSL server certificate so
 * we can implement secure tunnel binding as part of our authentication
 * protocol.
 * </p>
 *
 * @author Frank Cornelis
 */
public class EIdClientSSLSocketFactory extends SSLSocketFactory implements HandshakeCompletedListener {

	/**
	 * Installs this socket factory within the JRE.
	 */
	public static void installSocketFactory(View view) {
		SSLSocketFactory sslSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
		if (!(sslSocketFactory instanceof EIdClientSSLSocketFactory)) {
			EIdClientSSLSocketFactory eidClientSslSocketFactory = new EIdClientSSLSocketFactory(sslSocketFactory, view);
			HttpsURLConnection.setDefaultSSLSocketFactory(eidClientSslSocketFactory);
		} else {
			EIdClientSSLSocketFactory eidClientSslSocketFactory = (EIdClientSSLSocketFactory) sslSocketFactory;
			eidClientSslSocketFactory.setView(view);
		}
	}

	/**
	 * Returns the actual SSL session identifier.
	 */
	public static byte[] getActualSessionId() {
		return getEidClientSSLSocketFactory().getSessionId();
	}

	/**
	 * Gives back the actual DER encoded SSL server certificate.
	 */
	public static byte[] getActualEncodedServerCertificate() {
		return getEidClientSSLSocketFactory().getEncodedPeerCertificate();
	}

	private static EIdClientSSLSocketFactory getEidClientSSLSocketFactory() {
		SSLSocketFactory sslSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
		if (!(sslSocketFactory instanceof EIdClientSSLSocketFactory)) {
			throw new SecurityException("wrong SSL socket factory");
		}
		return (EIdClientSSLSocketFactory) sslSocketFactory;
	}

	private final SSLSocketFactory originalSslSocketFactory;
	private View view;
	private byte[] sslSessionId;

	/**
	 * Main constructor.
	 */
	public EIdClientSSLSocketFactory(SSLSocketFactory originalSslSocketFactory, View view) {
		setView(view);
		this.originalSslSocketFactory = originalSslSocketFactory;
	}

	private byte[] encodedPeerCertificate;

	private void setView(View view) {
		this.view = view;
	}

	@Override
	public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket(s, host, port, autoClose);

		/*
		 * Important here not to try to access the SSL session identifier via getSession.
		 * This can cause problems when sitting behind an HTTP proxy.
		 * The only way to get access to the SSL session identifier is via the TLS handshake completed listener.
		 */
		installHandshakeCompletedListener(socket);
		return socket;
	}

	private void installHandshakeCompletedListener(Socket socket) {
		SSLSocket sslSocket = (SSLSocket) socket;
		sslSocket.addHandshakeCompletedListener(this);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return this.originalSslSocketFactory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return this.originalSslSocketFactory.getSupportedCipherSuites();
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket(host, port);
		installHandshakeCompletedListener(socket);
		return socket;
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket(host, port);
		installHandshakeCompletedListener(socket);
		return socket;
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket(host, port, localHost, localPort);
		installHandshakeCompletedListener(socket);
		return socket;
	}

	@Override
	public Socket createSocket(InetAddress host, int port, InetAddress localHost, int localPort) throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket(host, port, localHost, localPort);
		installHandshakeCompletedListener(socket);
		return socket;
	}

	/**
	 * Gives back the SSL session identifier.
	 */
	public byte[] getSessionId() {
		if (null == this.sslSessionId) {
			throw new IllegalStateException("SSL session identifier unknown");
		}
		return this.sslSessionId;
	}

	/**
	 * Gives back the DER encoded SSL server certificate.
	 */
	public byte[] getEncodedPeerCertificate() {
		if (null == this.encodedPeerCertificate) {
			throw new IllegalStateException("SSL peer certificate unknown");
		}
		return this.encodedPeerCertificate;
	}

	@Override
	public Socket createSocket() throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket();
		installHandshakeCompletedListener(socket);
		return socket;
	}

	@Override
	public void handshakeCompleted(HandshakeCompletedEvent event) {
		String cipherSuite = event.getCipherSuite();
		this.view.addDetailMessage("SSL handshake finish cipher suite: " + cipherSuite);

		SSLSession sslSession = event.getSession();
		byte[] sslSessionId = sslSession.getId();
		if (this.sslSessionId != null && !Arrays.equals(this.sslSessionId, sslSessionId)) {
			/*
			 * This could also be caused by an SSL session renewal.
			 */
			this.view.addDetailMessage("SSL session Id mismatch");
		}
		this.sslSessionId = sslSessionId;

		try {
			Certificate[] peerCertificates = sslSession.getPeerCertificates();
			this.encodedPeerCertificate = peerCertificates[0].getEncoded();
		} catch (SSLPeerUnverifiedException e) {
			this.view.addDetailMessage("SSL peer unverified");
		} catch (CertificateEncodingException e) {
			this.view.addDetailMessage("certificate encoding error: " + e.getMessage());
		}
	}
}
