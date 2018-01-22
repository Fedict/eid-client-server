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

package be.fedict.eid.applet.service.signer.facets;

import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.LinkedList;
import java.util.List;

/**
 * Container class for PKI revocation data.
 *
 * @author Frank Cornelis
 */
public class RevocationData {

	private final List<byte[]> crls;

	private final List<byte[]> ocsps;

	/**
	 * Default constructor.
	 */
	public RevocationData() {
		this.crls = new LinkedList<>();
		this.ocsps = new LinkedList<>();
	}

	/**
	 * Adds a CRL to this revocation data set.
	 */
	public void addCRL(byte[] encodedCrl) {
		this.crls.add(encodedCrl);
	}

	/**
	 * Adds a CRL to this revocation data set.
	 */
	public void addCRL(X509CRL crl) {
		byte[] encodedCrl;
		try {
			encodedCrl = crl.getEncoded();
		} catch (CRLException e) {
			throw new IllegalArgumentException("CRL coding error: " + e.getMessage(), e);
		}
		addCRL(encodedCrl);
	}

	/**
	 * Adds an OCSP response to this revocation data set.
	 */
	public void addOCSP(byte[] encodedOcsp) {
		this.ocsps.add(encodedOcsp);
	}

	/**
	 * Gives back a list of all CRLs.
	 */
	public List<byte[]> getCRLs() {
		return this.crls;
	}

	/**
	 * Gives back a list of all OCSP responses.
	 */
	public List<byte[]> getOCSPs() {
		return this.ocsps;
	}

	/**
	 * Returns <code>true</code> if this revocation data set holds OCSP
	 * responses.
	 */
	public boolean hasOCSPs() {
		return !this.ocsps.isEmpty();
	}

	/**
	 * Returns <code>true</code> if this revocation data set holds CRLs.
	 */
	public boolean hasCRLs() {
		return !this.crls.isEmpty();
	}

	/**
	 * Returns <code>true</code> if this revocation data is not empty.
	 */
	public boolean hasRevocationDataEntries() {
		return hasOCSPs() || hasCRLs();
	}
}
