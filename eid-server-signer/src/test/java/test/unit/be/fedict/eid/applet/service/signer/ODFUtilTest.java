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

package test.unit.be.fedict.eid.applet.service.signer;

import be.fedict.eid.applet.service.signer.odf.ODFUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import java.net.URL;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Bart Hanssens
 */
public class ODFUtilTest {
	private static final Log LOG = LogFactory.getLog(ODFUtilTest.class);

	@Test
	public void testSelfContained() throws Exception {
		// setup
		URL odfUrl = ODFUtilTest.class.getResource("/hello-world.odt");
		assertNotNull(odfUrl);

		// operate
		boolean result = ODFUtil.isSelfContained(odfUrl);

		// verify
		assertTrue(result);
	}

	@Test
	public void testNotSelfContainedLocal() throws Exception {
		testNotSelfContained("/hello-ole-local.odt");
	}

	@Test
	public void testNotSelfContainedPath() throws Exception {
		testNotSelfContained("/hello-ole-path.odt");
	}
	/*
	 * @Test public void testNotSelfContainedNetwork() throws Exception {
	 * testNotSelfContained("/hello-ole-network.odt"); }
	 */

	private void testNotSelfContained(String url) throws Exception {
		// setup
		URL odfUrl = ODFUtilTest.class.getResource(url);
		assertNotNull(odfUrl);

		// operate
		boolean result = ODFUtil.isSelfContained(odfUrl);

		// verify
		assertFalse(result);
	}
}
