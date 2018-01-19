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

package be.bosa.eid.client.javawebstart;

import be.bosa.eid.client.core.Runtime;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import javax.jnlp.BasicService;
import javax.jnlp.ClipboardService;
import javax.jnlp.ServiceManager;
import javax.jnlp.UnavailableServiceException;
import java.awt.datatransfer.StringSelection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static be.bosa.eid.client.javawebstart.ArgumentDescriptor.AUTHORIZATION_ERROR_PAGE;
import static be.bosa.eid.client.javawebstart.ArgumentDescriptor.BACKGROUND_COLOR;
import static be.bosa.eid.client.javawebstart.ArgumentDescriptor.CANCEL_PAGE;
import static be.bosa.eid.client.javawebstart.ArgumentDescriptor.EID_SERVER_URL;
import static be.bosa.eid.client.javawebstart.ArgumentDescriptor.FOREGROUND_COLOR;
import static be.bosa.eid.client.javawebstart.ArgumentDescriptor.LANGUAGE;
import static be.bosa.eid.client.javawebstart.ArgumentDescriptor.TARGET_PAGE;

public class RuntimeImpl implements Runtime {

	private final Map<ArgumentDescriptor, String> arguments;

	RuntimeImpl(String[] commandLineArgs) {
		this.arguments = parseArguments(commandLineArgs);
	}

	private Map<ArgumentDescriptor, String> parseArguments(String[] commandLineArgs) {
		Options options = new Options();
		Arrays.stream(ArgumentDescriptor.values()).map(ArgumentDescriptor::toOption).forEach(options::addOption);

		try {
			CommandLine commandLine = new DefaultParser().parse(options, commandLineArgs);

			return Arrays.stream(ArgumentDescriptor.values())
					.filter(argumentDescriptor1 -> commandLine.hasOption(argumentDescriptor1.getName()))
					.collect(Collectors.toMap(
							Function.identity(),
							argumentDescriptor -> commandLine.getOptionValue(argumentDescriptor.getName())
					));
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public Optional<String> getLanguage() {
		return getOptionalArgument(LANGUAGE);
	}

	@Override
	public URL getEidServerUrl() {
		try {
			return new URL(getRequiredArgument(EID_SERVER_URL));
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("Invalid eID Server URL", e);
		}
	}

	@Override
	public Optional<String> getBackgroundColor() {
		return getOptionalArgument(BACKGROUND_COLOR);
	}

	@Override
	public Optional<String> getForegroundColor() {
		return getOptionalArgument(FOREGROUND_COLOR);
	}

	@Override
	public void gotoTargetPage() {
		getOptionalArgument(TARGET_PAGE).ifPresent(this::goToPage);
	}

	@Override
	public void gotoCancelPage() {
		getOptionalArgument(CANCEL_PAGE).ifPresent(this::goToPage);
	}

	@Override
	public void gotoAuthorizationErrorPage() {
		getOptionalArgument(AUTHORIZATION_ERROR_PAGE).ifPresent(this::goToPage);
	}

	@Override
	public URL getCodeBase() {
		return getBasicService().getCodeBase();
	}

	@Override
	public void copyToClipboard(String text) {
		getClipboardService().setContents(new StringSelection(text));
	}

	private void goToPage(String url) {
		try {
			getBasicService().showDocument(new URL(url));
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("Invalid URL: " + url);
		}
	}

	private Optional<String> getOptionalArgument(ArgumentDescriptor argumentDescriptor) {
		return Optional.ofNullable(arguments.get(argumentDescriptor));
	}

	private String getRequiredArgument(ArgumentDescriptor argumentDescriptor) {
		return getOptionalArgument(argumentDescriptor)
				.orElseThrow(() -> new IllegalArgumentException("No " + argumentDescriptor + " parameter specified"));
	}

	private BasicService getBasicService() {
		return getService(BasicService.class);
	}

	private ClipboardService getClipboardService() {
		return getService(ClipboardService.class);
	}

	public <T> T getService(Class<T> serviceClass) {
		try {
			return serviceClass.cast(ServiceManager.lookup(serviceClass.getName()));
		} catch (UnavailableServiceException e) {
			throw new RuntimeException(String.format("Service %s is not available", serviceClass.getName()), e);
		}
	}
}
