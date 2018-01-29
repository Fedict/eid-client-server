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

package be.bosa.eid.client.core.sc;

import be.bosa.commons.eid.client.BeIDCard;
import be.bosa.commons.eid.client.exception.BeIDException;
import be.bosa.eid.client.core.EidClientFrame;

/**
 * BeIDTask runner for smart card specific operations. Will run a given task using
 * some back-off strategy in case of failure.
 *
 * @author Frank Cornelis
 */
public class TaskRunner {

	private static final int TRIES = 3;
	private static final int BACKOFF_SLEEP = 1000 * 2;

	private final EidClientFrame view;

	public TaskRunner(EidClientFrame view) {
		this.view = view;
	}

	public <T> T runWithRetry(BeIDCard beIDCard, BeIDTask<T> task) throws InterruptedException, BeIDException {
		int tries = TRIES;

		BeIDException lastException = null;
		while (tries != 0) {
			try {
				return task.run();
			} catch (BeIDException e) {
				lastException = e;
				reportException(e);
			}

			Thread.sleep(BACKOFF_SLEEP);
			tries--;

			/*
			 * Because software like ActivClient select the JavaCard card
			 * manager to browse the available JavaCard applets on inserted
			 * smart cards, we risk of not having the Belpic JavaCard applet
			 * selected per default. To circumvent this situation we explicitly
			 * select the Belpic JavaCard applet after a failed eID APDU
			 * sequence.
			 */
			try {
				beIDCard.selectApplet();
			} catch (BeIDException e) {
				// Ignore this; simply retry task.
			}
		}

		throw lastException;
	}

	private void reportException(Exception e) {
		view.addDetailMessage("Task exception detected: " + e.getMessage());
		view.addDetailMessage("Exception type: " + e.getClass().getName());

		Throwable cause = e.getCause();
		if (null != cause) {
			this.view.addDetailMessage("Exception cause: " + cause.getMessage());
			this.view.addDetailMessage("Exception cause type: " + cause.getClass().getName());
		}

		this.view.addDetailMessage("Will sleep and retry...");
	}

}
