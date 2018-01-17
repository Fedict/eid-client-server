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

import be.bosa.eid.server.impl.handler.IdentityDataMessageHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Servlet to display the citizen's photo that is stored in the HTTP session
 * after a successful eID identification operation via the eID Applet.
 *
 * @author Frank Cornelis
 */
public class PhotoServlet extends HttpServlet {

	private static final Log LOG = LogFactory.getLog(PhotoServlet.class);

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		LOG.debug("doGet");
		response.setContentType("image/jpg");
		response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, max-age=-1"); // http 1.1
		response.setHeader("Pragma", "no-cache, no-store"); // http 1.0
		response.setDateHeader("Expires", -1);

		ServletOutputStream out = response.getOutputStream();
		HttpSession session = request.getSession();
		byte[] photoData = (byte[]) session.getAttribute(IdentityDataMessageHandler.PHOTO_SESSION_ATTRIBUTE);
		if (photoData != null) {
			BufferedImage photo = ImageIO.read(new ByteArrayInputStream(photoData));
			if (photo == null) {
				/*
				 * In this case we render a photo containing some error message.
				 */
				photo = new BufferedImage(140, 200, BufferedImage.TYPE_INT_RGB);
				Graphics2D graphics = (Graphics2D) photo.getGraphics();
				RenderingHints renderingHints = new RenderingHints(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
				graphics.setRenderingHints(renderingHints);
				graphics.setColor(Color.WHITE);
				graphics.fillRect(1, 1, 140 - 1 - 1, 200 - 1 - 1);
				graphics.setColor(Color.RED);
				graphics.setFont(new Font("Dialog", Font.BOLD, 20));
				graphics.drawString("Photo Error", 0, 200 / 2);
				graphics.dispose();
				ImageIO.write(photo, "jpg", out);
			} else {
				out.write(photoData);
			}
		}
		out.close();
	}
}
