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

// https://www.java.com/js/deployJava.js
// readable version: http://java.com/js/deployJava.txt
var deployJavaEIDApplet = {
	runApplet : function(attributes, parameters) {
		// fix for Mac OS X 64 bit
		var javaArgs = '';
		if (navigator.userAgent.indexOf('Mac OS X 10_6') != -1
				|| navigator.userAgent.indexOf('Mac OS X 10.6') != -1) {
			javaArgs += '-d32';
		}
		parameters.java_arguments = javaArgs;
		// fix for IE 7/8
		var version = '1.6';
		var browser = deployJava.getBrowser();
		if (browser == 'MSIE') {
			version = '1.6.0_27';
		}
		deployJava.runApplet(attributes, parameters, version);
	}
};