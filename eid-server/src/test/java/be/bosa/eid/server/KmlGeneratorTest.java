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

import be.bosa.eid.server.impl.KmlGenerator;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.GregorianCalendar;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class KmlGeneratorTest {

	private static final Log LOG = LogFactory.getLog(KmlGeneratorTest.class);

	private KmlGenerator testedInstance;

	@Before
	public void setUp() {
		this.testedInstance = new KmlGenerator();
	}

	@Test
	public void nullEIdDataGivesEmptyKml() throws Exception {
		byte[] document = this.testedInstance.generateKml(null);

		assertNotNull(document);
		assertTrue(document.length > 0);

		toTmpFile(document);
	}

	@Test
	public void identityKml() throws Exception {
		Identity identity = new Identity();
		identity.name = "Test Name";
		identity.firstName = "Test First name";
		identity.dateOfBirth = new GregorianCalendar();
		identity.gender = Gender.MALE;
		EIdData eIdData = new EIdData();
		eIdData.identity = identity;

		byte[] document = this.testedInstance.generateKml(eIdData);

		assertNotNull(document);
		assertTrue(document.length > 0);

		toTmpFile(document);
	}

	@Test
	public void identityWithAddressKml() throws Exception {
		Identity identity = new Identity();
		identity.name = "Test Name";
		identity.firstName = "Test First name";
		identity.dateOfBirth = new GregorianCalendar();
		identity.gender = Gender.MALE;

		Address address = new Address();
		address.streetAndNumber = "Test Street 1A";
		address.zip = "1234";
		address.municipality = "Test Municipality";

		EIdData eIdData = new EIdData();
		eIdData.identity = identity;
		eIdData.address = address;

		byte[] document = this.testedInstance.generateKml(eIdData);

		assertNotNull(document);
		assertTrue(document.length > 0);

		toTmpFile(document);
	}

	@Test
	public void identityWithAddressAndPhotoKml() throws Exception {
		Identity identity = new Identity();
		identity.name = "Test Name";
		identity.firstName = "Test First name";
		identity.dateOfBirth = new GregorianCalendar();
		identity.gender = Gender.MALE;

		Address address = new Address();
		address.streetAndNumber = "Test Street 1A";
		address.zip = "1234";
		address.municipality = "Test Municipality";

		BufferedImage image = new BufferedImage(140, 200, BufferedImage.TYPE_INT_RGB);
		Graphics2D graphics = (Graphics2D) image.getGraphics();
		RenderingHints renderingHints = new RenderingHints(RenderingHints.KEY_TEXT_ANTIALIASING,
				RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
		graphics.setRenderingHints(renderingHints);
		graphics.setColor(Color.WHITE);
		graphics.fillRect(1, 1, 140 - 1 - 1, 200 - 1 - 1);
		graphics.setFont(new Font("Dialog", Font.BOLD, 20));
		graphics.setColor(Color.BLACK);
		graphics.drawString("Test Photo", 0, 200 / 2);
		graphics.dispose();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ImageIO.write(image, "jpg", baos);
		byte[] photo = baos.toByteArray();

		EIdData eIdData = new EIdData();
		eIdData.identity = identity;
		eIdData.address = address;
		eIdData.photo = photo;

		byte[] document = this.testedInstance.generateKml(eIdData);

		assertNotNull(document);
		assertTrue(document.length > 0);

		toTmpFile(document);
	}

	@Test
	public void identityWithAddressAndPhotoWithErrorsKml() throws Exception {
		Identity identity = new Identity();
		identity.name = "Test Name";
		identity.firstName = "Test First name";
		identity.dateOfBirth = new GregorianCalendar();
		identity.gender = Gender.MALE;

		Address address = new Address();
		address.streetAndNumber = "Test Street 1A";
		address.zip = "1234";
		address.municipality = "Test Municipality";

		byte[] photo = "foobar-photo".getBytes();

		EIdData eIdData = new EIdData();
		eIdData.identity = identity;
		eIdData.address = address;
		eIdData.photo = photo;

		byte[] document = this.testedInstance.generateKml(eIdData);

		assertNotNull(document);
		assertTrue(document.length > 0);

		toTmpFile(document);
	}

	private void toTmpFile(byte[] document) throws IOException {
		File tmpFile = File.createTempFile("eid-", ".kmz");
		FileUtils.writeByteArrayToFile(tmpFile, document);
		LOG.debug("tmp KMZ file: " + tmpFile.getAbsolutePath());
	}
}
