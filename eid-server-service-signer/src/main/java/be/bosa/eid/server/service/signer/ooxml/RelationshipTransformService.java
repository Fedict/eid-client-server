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

package be.bosa.eid.server.service.signer.ooxml;

import be.bosa.eid.server.service.signer.util.XPathUtil;
import be.bosa.eid.server.service.signer.util.XmlUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.LinkedList;
import java.util.List;

/**
 * JSR105 implementation of the RelationshipTransform transformation.
 * <p>
 * <p>
 * Specs: http://openiso.org/Ecma/376/Part2/12.2.4#26
 * </p>
 *
 * @author Frank Cornelis
 */
public class RelationshipTransformService extends TransformService {

	public static final String TRANSFORM_URI = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

	private final List<String> sourceIds;

	private final List<String> sourceTypes;

	private static final Log LOG = LogFactory.getLog(RelationshipTransformService.class);

	/**
	 * Default constructor.
	 */
	public RelationshipTransformService() {
		super();
		LOG.debug("constructor");
		this.sourceIds = new LinkedList<>();
		this.sourceTypes = new LinkedList<>();
	}

	@Override
	public void init(TransformParameterSpec params) throws InvalidAlgorithmParameterException {
		LOG.debug("init(params)");
		if (!(params instanceof RelationshipTransformParameterSpec)) {
			throw new InvalidAlgorithmParameterException();
		}
		RelationshipTransformParameterSpec relParams = (RelationshipTransformParameterSpec) params;
		this.sourceIds.addAll(relParams.getSourceIds());
		this.sourceTypes.addAll(relParams.getSourceTypes());
	}

	@Override
	public void init(XMLStructure parent, XMLCryptoContext context) throws InvalidAlgorithmParameterException {
		LOG.debug("init(parent,context)");
		LOG.debug("parent java type: " + parent.getClass().getName());
		DOMStructure domParent = (DOMStructure) parent;
		Node parentNode = domParent.getNode();
		try {
			LOG.debug("parent: " + toString(parentNode));
		} catch (TransformerException e) {
			throw new InvalidAlgorithmParameterException();
		}

		Element nsElement = parentNode.getOwnerDocument().createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds", Constants.SignatureSpecNS);
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:mdssi",
				"http://schemas.openxmlformats.org/package/2006/digital-signature");

		/*
		 * RelationshipReference
		 */
		NodeList nodeList = XPathUtil.getNodeListByXPath(parentNode, nsElement, "mdssi:RelationshipReference/@SourceId");
		for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
			Node node = nodeList.item(nodeIdx);
			String sourceId = node.getTextContent();
			LOG.debug("sourceId: " + sourceId);
			this.sourceIds.add(sourceId);
		}

		/*
		 * RelationshipsGroupReference
		 */
		nodeList = XPathUtil.getNodeListByXPath(parentNode, nsElement, "mdssi:RelationshipsGroupReference/@SourceType");
		for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
			Node node = nodeList.item(nodeIdx);
			String sourceType = node.getTextContent();
			LOG.debug("sourceType: " + sourceType);
			this.sourceTypes.add(sourceType);
		}
	}

	@Override
	public void marshalParams(XMLStructure parent, XMLCryptoContext context) {
		LOG.debug("marshallParams(parent,context)");
		DOMStructure domParent = (DOMStructure) parent;
		Node parentNode = domParent.getNode();
		Element parentElement = (Element) parentNode;
		parentElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:mdssi",
				"http://schemas.openxmlformats.org/package/2006/digital-signature");
		Document document = parentNode.getOwnerDocument();
		for (String sourceId : this.sourceIds) {
			Element relationshipReferenceElement = document.createElementNS(
					"http://schemas.openxmlformats.org/package/2006/digital-signature", "mdssi:RelationshipReference");
			relationshipReferenceElement.setAttribute("SourceId", sourceId);
			parentElement.appendChild(relationshipReferenceElement);
		}
		for (String sourceType : this.sourceTypes) {
			Element relationshipsGroupReferenceElement = document.createElementNS(
					"http://schemas.openxmlformats.org/package/2006/digital-signature",
					"mdssi:RelationshipsGroupReference");
			relationshipsGroupReferenceElement.setAttribute("SourceType", sourceType);
			parentElement.appendChild(relationshipsGroupReferenceElement);
		}
	}

	public AlgorithmParameterSpec getParameterSpec() {
		LOG.debug("getParameterSpec");
		return null;
	}

	public Data transform(Data data, XMLCryptoContext context) throws TransformException {
		LOG.debug("transform(data,context)");
		LOG.debug("data java type: " + data.getClass().getName());
		OctetStreamData octetStreamData = (OctetStreamData) data;
		LOG.debug("URI: " + octetStreamData.getURI());
		InputStream octetStream = octetStreamData.getOctetStream();
		Document relationshipsDocument;
		try {
			relationshipsDocument = XmlUtil.loadDocument(octetStream);
		} catch (Exception e) {
			throw new TransformException(e.getMessage(), e);
		}
		try {
			LOG.debug("relationships document: " + toString(relationshipsDocument));
		} catch (TransformerException e) {
			throw new TransformException(e.getMessage(), e);
		}
		Element nsElement = relationshipsDocument.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
				"http://schemas.openxmlformats.org/package/2006/relationships");
		Element relationshipsElement = relationshipsDocument.getDocumentElement();
		NodeList childNodes = relationshipsElement.getChildNodes();
		for (int nodeIdx = 0; nodeIdx < childNodes.getLength(); nodeIdx++) {
			Node childNode = childNodes.item(nodeIdx);
			if (Node.ELEMENT_NODE != childNode.getNodeType()) {
				LOG.debug("removing node");
				relationshipsElement.removeChild(childNode);
				nodeIdx--;
				continue;
			}
			Element childElement = (Element) childNode;
			String idAttribute = childElement.getAttribute("Id");
			String typeAttribute = childElement.getAttribute("Type");
			LOG.debug("Relationship id attribute: " + idAttribute);
			LOG.debug("Relationship type attribute: " + typeAttribute);
			if (!this.sourceIds.contains(idAttribute) && !this.sourceTypes.contains(typeAttribute)) {
				LOG.debug("removing Relationship element: " + idAttribute);
				relationshipsElement.removeChild(childNode);
				nodeIdx--;
			}
			/*
			 * See: ISO/IEC 29500-2:2008(E) - 13.2.4.24 Relationships Transform
			 * Algorithm.
			 */
			if (null == childElement.getAttributeNode("TargetMode")) {
				childElement.setAttribute("TargetMode", "Internal");
			}
		}
		LOG.debug("# Relationship elements: " + relationshipsElement.getElementsByTagName("*").getLength());
		sortRelationshipElements(relationshipsElement);
		try {
			return toOctetStreamData(relationshipsDocument);
		} catch (TransformerException e) {
			throw new TransformException(e.getMessage(), e);
		}
	}

	private void sortRelationshipElements(Element relationshipsElement) {
		List<Element> relationshipElements = new LinkedList<>();
		NodeList relationshipNodes = relationshipsElement.getElementsByTagName("*");
		int nodeCount = relationshipNodes.getLength();
		for (int nodeIdx = 0; nodeIdx < nodeCount; nodeIdx++) {
			Node relationshipNode = relationshipNodes.item(0);
			Element relationshipElement = (Element) relationshipNode;
			LOG.debug("unsorted Id: " + relationshipElement.getAttribute("Id"));
			relationshipElements.add(relationshipElement);
			relationshipsElement.removeChild(relationshipNode);
		}
		relationshipElements.sort(new RelationshipComparator());
		for (Element relationshipElement : relationshipElements) {
			LOG.debug("sorted Id: " + relationshipElement.getAttribute("Id"));
			relationshipsElement.appendChild(relationshipElement);
		}
	}

	private String toString(Node dom) throws TransformerException {
		Source source = new DOMSource(dom);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		/*
		 * We have to omit the ?xml declaration if we want to embed the
		 * document.
		 */
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		return stringWriter.getBuffer().toString();
	}

	private OctetStreamData toOctetStreamData(Node node) throws TransformerException {
		Source source = new DOMSource(node);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		Result result = new StreamResult(outputStream);
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		LOG.debug("result: " + new String(outputStream.toByteArray()));
		return new OctetStreamData(new ByteArrayInputStream(outputStream.toByteArray()));
	}

	public Data transform(Data data, XMLCryptoContext context, OutputStream os) {
		LOG.debug("transform(data,context,os)");
		return null;
	}

	public boolean isFeatureSupported(String feature) {
		LOG.debug("isFeatureSupported(feature)");
		return false;
	}
}
