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
import org.joda.time.DateTime;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;

import static org.junit.Assert.assertEquals;

public class JSONServletTest {

	private static final Log LOG = LogFactory.getLog(JSONServletTest.class);

	private ServletTester servletTester;

	private String location;

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		this.servletTester.addServlet(JSONServlet.class, "/");

		this.servletTester.start();
		this.location = this.servletTester.createSocketConnector(true);
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void testGetWithoutSessionData() throws Exception {
		LOG.debug("location: " + this.location);
		HttpClient httpClient = HttpClients.createDefault();
		HttpGet getMethod = new HttpGet(this.location);

		HttpResponse response = httpClient.execute(getMethod);

		assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, response.getStatusLine().getStatusCode());
		LOG.debug("result content: " + EntityUtils.toString(response.getEntity()));
	}

	@Test
	public void testJSONOutput() throws Exception {
		EIdData eIdData = new EIdData();
		eIdData.identity = new Identity();
		eIdData.identity.nationalNumber = "123456789";
		eIdData.identity.dateOfBirth = new GregorianCalendar();
		eIdData.identity.cardValidityDateBegin = new GregorianCalendar();
		eIdData.identity.cardValidityDateEnd = new GregorianCalendar();
		eIdData.identity.gender = Gender.FEMALE;
		eIdData.address = new Address();
		eIdData.address.streetAndNumber = "test-street-1234";

		eIdData.certs = new EIdCertsData();
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(5);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), false, 0, null, null);
		eIdData.certs.authn = certificate;
		eIdData.certs.sign = certificate;
		eIdData.certs.ca = certificate;
		eIdData.certs.root = certificate;

		StringWriter stringWriter = new StringWriter();
		PrintWriter printWriter = new PrintWriter(stringWriter);

		JSONServlet.outputJSON(eIdData, printWriter);

		String jsonOutput = stringWriter.toString();
		LOG.debug("JSON output: " + jsonOutput);
	}

	@Test
	public void testJSONSimpleSpike() {
		JSONObject eidJSONObject = new JSONObject();
		JSONObject identityJSONObject = new JSONObject();
		eidJSONObject.put("identity", identityJSONObject);
		identityJSONObject.put("nationalNumber", "12345678");
		identityJSONObject.put("dateOfBirth", new GregorianCalendar().getTime());

		LOG.debug("JSON result: " + eidJSONObject.toString());
	}
}
