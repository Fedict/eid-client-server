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

package be.fedict.eid.applet.service.signer.util;

import org.apache.xml.security.utils.DOMNamespaceContext;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

public class XPathUtil {

	public static NodeList getNodeListByXPath(Node parentNode, Node nsNode, String expression) {
		try {
			XPath xpath = XPathFactory.newInstance().newXPath();
			xpath.setNamespaceContext(new DOMNamespaceContext(nsNode));
			return (NodeList) xpath.evaluate(expression, parentNode, XPathConstants.NODESET);
		} catch (XPathExpressionException e) {
			throw new RuntimeException(e);
		}
	}

	public static Node getNodeByXPath(Node parentNode, String expression, Node nsNode) {
		try {
			XPath xpath = XPathFactory.newInstance().newXPath();
			xpath.setNamespaceContext(new DOMNamespaceContext(nsNode));
			return (Node) xpath.evaluate(expression, parentNode, XPathConstants.NODE);
		} catch (XPathExpressionException e) {
			throw new RuntimeException(e);
		}
	}

}
