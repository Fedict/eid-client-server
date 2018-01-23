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

package be.bosa.eid.server.service.signer.util;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public class DateUtil {

	public static String getNowAsIso8601DateTimeStringWithTimeZoneUtc() {
		return getAsIso8601DateTimeStringWithTimeZoneUtc(new Date());
	}

	public static String getAsIso8601DateTimeStringWithTimeZoneUtc(Date time) {
		ZonedDateTime dateTime = ZonedDateTime.ofInstant(time.toInstant(), ZoneId.systemDefault());
		return DateTimeFormatter.ISO_ZONED_DATE_TIME.format(dateTime);
	}
}
