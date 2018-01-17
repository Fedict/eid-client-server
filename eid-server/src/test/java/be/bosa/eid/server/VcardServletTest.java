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

package be.bosa.eid.server;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;

import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class VcardServletTest {

	private static final Log LOG = LogFactory.getLog(VcardServletTest.class);

	private ServletTester servletTester;

	private String location;

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		this.servletTester.addServlet(VcardServlet.class, "/");

		this.servletTester.start();
		this.location = this.servletTester.createSocketConnector(true);
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void anonymousResult() throws Exception {
		// setup
		LOG.debug("location: " + this.location);
		HttpClient httpClient = HttpClients.createDefault();
		HttpGet getMethod = new HttpGet(this.location);

		// operate
		HttpResponse response = httpClient.execute(getMethod);

		// verify
		assertEquals(HttpServletResponse.SC_OK, response.getStatusLine().getStatusCode());
		String resultContentType = response.getFirstHeader("content-type").getValue();
		assertEquals("text/directory;profile=vCard", resultContentType);
		assertTrue(EntityUtils.toByteArray(response.getEntity()).length > 0);
	}
}
