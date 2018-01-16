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

package be.bosa.eid.client_server.shared.protocol;

import be.bosa.eid.client_server.shared.annotation.ProtocolStateAllowed;
import be.bosa.eid.client_server.shared.annotation.StartRequestMessage;
import be.bosa.eid.client_server.shared.annotation.StateTransition;
import be.bosa.eid.client_server.shared.annotation.StopResponseMessage;

import java.util.LinkedList;
import java.util.List;

/**
 * Protocol State Machine.
 *
 * @author Frank Cornelis
 */
public class ProtocolStateMachine {

	private final ProtocolContext protocolContext;

	private final List<ProtocolStateListener> protocolStateListeners;

	/**
	 * Main constructor.
	 */
	public ProtocolStateMachine(ProtocolContext protocolContext) {
		this.protocolContext = protocolContext;
		this.protocolStateListeners = new LinkedList<>();
	}

	/**
	 * Adds a protocol state listener.
	 */
	public void addProtocolStateListener(ProtocolStateListener protocolStateListener) {
		protocolStateListeners.add(protocolStateListener);
	}

	/**
	 * Checks the given response message against the protocol state rules.
	 */
	public void checkResponseMessage(Object responseMessage) {
		ProtocolState protocolState = protocolContext.getProtocolState();
		if (protocolState == null) {
			throw new RuntimeException("responding without a protocol state");
		}

		Class<?> responseMessageClass = responseMessage.getClass();
		StopResponseMessage stopResponseMessageAnnotation = responseMessageClass.getAnnotation(StopResponseMessage.class);
		if (stopResponseMessageAnnotation != null) {
			notifyProtocolListenersStopProtocolRun();
			protocolContext.removeProtocolState();
		}

		StateTransition stateTransitionAnnotation = responseMessageClass.getAnnotation(StateTransition.class);
		if (stateTransitionAnnotation != null) {
			ProtocolState newProtocolState = stateTransitionAnnotation.value();
			protocolContext.setProtocolState(newProtocolState);
			notifyProtocolListenersProtocolStateTransition(newProtocolState);
		}
	}

	private void notifyProtocolListenersProtocolStateTransition(ProtocolState newProtocolState) {
		protocolStateListeners.forEach(protocolStateListener -> protocolStateListener.protocolStateTransition(newProtocolState));
	}

	private void notifyProtocolListenersStartProtocolRun() {
		protocolStateListeners.forEach(ProtocolStateListener::startProtocolRun);
	}

	private void notifyProtocolListenersStopProtocolRun() {
		protocolStateListeners.forEach(ProtocolStateListener::startProtocolRun);
	}

	/**
	 * Checks the given request message against protocol state rules.
	 */
	public void checkRequestMessage(Object requestMessage) {
		// TODO throw some non-runtime exception
		ProtocolState protocolState = protocolContext.getProtocolState();
		Class<?> requestMessageClass = requestMessage.getClass();

		StartRequestMessage startRequestMessageAnnotation = requestMessageClass.getAnnotation(StartRequestMessage.class);
		if (startRequestMessageAnnotation == null) {
			if (protocolState == null) {
				throw new RuntimeException("expected a protocol start message");
			}

			ProtocolStateAllowed protocolStateAllowedAnnotation = requestMessageClass.getAnnotation(ProtocolStateAllowed.class);
			if (protocolStateAllowedAnnotation == null) {
				throw new RuntimeException("cannot check protocol state for message: " + requestMessageClass.getSimpleName());
			}

			ProtocolState allowedProtocolState = protocolStateAllowedAnnotation.value();
			if (protocolState != allowedProtocolState) {
				throw new RuntimeException("protocol state incorrect. expected: " + allowedProtocolState + "; actual: " + protocolState);
			}
		} else {
			if (protocolState == null) {
				ProtocolState initialState = startRequestMessageAnnotation.value();
				this.protocolContext.setProtocolState(initialState);
				notifyProtocolListenersStartProtocolRun();
				notifyProtocolListenersProtocolStateTransition(initialState);
			}
			/*
			 * Throwing an exception in the else case might be to strict since we want
			 * to allow easy recovery from a crashed eID Applet. I.e. no
			 * need to restart the web browser.
			 */
		}
	}
}
