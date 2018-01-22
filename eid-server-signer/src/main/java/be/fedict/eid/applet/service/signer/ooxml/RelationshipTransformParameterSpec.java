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

package be.fedict.eid.applet.service.signer.ooxml;

import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.util.LinkedList;
import java.util.List;

/**
 * Relationship Transform parameter specification class.
 * 
 * @author Frank Cornelis
 * 
 */
public class RelationshipTransformParameterSpec implements TransformParameterSpec {

	private final List<String> sourceIds;

	private final List<String> sourceTypes;

	/**
	 * Main constructor.
	 */
	public RelationshipTransformParameterSpec() {
		this.sourceIds = new LinkedList<String>();
		this.sourceTypes = new LinkedList<String>();
	}

	/**
	 * Adds a relationship reference for the given source identifier.
	 * 
	 * @param sourceId
	 */
	public void addRelationshipReference(String sourceId) {
		this.sourceIds.add(sourceId);
	}

	/**
	 * Adds a relationship group reference for the given source type.
	 * 
	 * @param sourceType
	 */
	public void addRelationshipGroupReference(String sourceType) {
		this.sourceTypes.add(sourceType);
	}

	List<String> getSourceIds() {
		return this.sourceIds;
	}

	List<String> getSourceTypes() {
		return this.sourceTypes;
	}
}
