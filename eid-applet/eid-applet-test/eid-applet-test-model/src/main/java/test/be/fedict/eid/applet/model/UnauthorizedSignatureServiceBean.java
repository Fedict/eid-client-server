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

package test.be.fedict.eid.applet.model;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.bosa.eid.server.spi.AddressDTO;
import be.bosa.eid.server.spi.AuthorizationException;
import be.bosa.eid.server.spi.DigestInfo;
import be.bosa.eid.server.spi.IdentityDTO;
import be.bosa.eid.server.spi.TrustCertificateSecurityException;

@Stateless
@EJB(name = "java:global/test/UnauthorizedSignatureServiceBean", beanInterface = UnauthorizedSignatureService.class)
public class UnauthorizedSignatureServiceBean implements UnauthorizedSignatureService {

	private static final Log LOG = LogFactory.getLog(UnauthorizedSignatureServiceBean.class);

	public void postSign(byte[] signatureValue, List<X509Certificate> signingCertificateChain)
			throws TrustCertificateSecurityException {
		LOG.debug("postSign");
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos, List<X509Certificate> signingCertificateChain,
			IdentityDTO identity, AddressDTO address, byte[] photo)
					throws NoSuchAlgorithmException, AuthorizationException {
		LOG.debug("preSign");
		throw new AuthorizationException();
	}

	public String getFilesDigestAlgorithm() {
		/*
		 * We don't need file digest values.
		 */
		return null;
	}
}
