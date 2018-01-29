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

package be.bosa.eid.client.core;

import be.bosa.commons.eid.client.BeIDCard;
import be.bosa.commons.eid.dialogs.Messages;

import java.awt.*;
import java.io.File;

/**
 * Interface for view component.
 *
 * @author Frank Cornelis
 */
public interface View {

	Component getParentComponent();

	void addDetailMessage(String detailMessage);

	void setStatusMessage(Status status, Messages.MESSAGE_ID messageId);

	boolean askPrivacyQuestion(BeIDCard card, boolean includeAddress, boolean includePhoto, String identityDataUsage);

	boolean confirmAuthenticationSignature(BeIDCard card, String detailMessage);

	boolean confirmSigning(BeIDCard card, String description, String digestAlgo);

	void setProgressIndeterminate();

	File[] selectFilesToSign();

	void resetProgress(int max);

	void increaseProgress();
}
