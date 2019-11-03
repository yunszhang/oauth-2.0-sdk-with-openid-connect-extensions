/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.oauth2.sdk.util.date;


import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Date with timezone offset. Supports ISO 8601 formatting and parsing.
 */
public class DateWithTimeZoneOffset {
	
	
	/**
	 * The date.
	 */
	private final Date date;
	
	
	/**
	 * The time zone offset in minutes relative to UTC.
	 */
	private final int tzOffsetMinutes;
	
	
	/**
	 * Creates a new date with timezone offset.
	 *
	 * @param date            The date. Must not be {@code null}.
	 * @param tzOffsetMinutes The time zone offset in minutes relative to
	 *                        UTC, zero if none. Must be less than
	 *                        {@code +/- 12 x 60}.
	 */
	public DateWithTimeZoneOffset(final Date date, final int tzOffsetMinutes) {
		if (date == null) {
			throw new IllegalArgumentException("The date must not be null");
		}
		this.date = date;
		if (tzOffsetMinutes >= 12*60 || tzOffsetMinutes <= -12*60) {
			throw new IllegalArgumentException("The time zone offset must be less than +/- 12 x 60 minutes");
		}
		this.tzOffsetMinutes = tzOffsetMinutes;
	}
	
	
	/**
	 * Returns the date.
	 *
	 * @return The date.
	 */
	public Date getDate() {
		return date;
	}
	
	
	/**
	 * Returns the time zone offset in minutes relative to UTC.
	 *
	 * @return The time zone offset in minutes relative to UTC, zero if
	 *         none.
	 */
	public int getTimeZoneOffsetMinutes() {
		return tzOffsetMinutes;
	}
	
	
	/**
	 * Returns an ISO 8601 representation in
	 * {@code YYYY-MM-DDThh:mm:ss±hh:mm} format.
	 *
	 * <p>Example: {@code 2019-11-01T18:19:43+03:00}
	 *
	 * @return The ISO 8601 representation.
	 */
	public String toISO8601String() {
		
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
		
		// Hack to format date/time with TZ offset
		TimeZone tz = TimeZone.getTimeZone("UTC");
		sdf.setTimeZone(tz);
		
		long localTimeSeconds = DateUtils.toSecondsSinceEpoch(date);
		localTimeSeconds = localTimeSeconds + (tzOffsetMinutes * 60);
		
		String out = sdf.format(DateUtils.fromSecondsSinceEpoch(localTimeSeconds));
		
		// Append TZ offset
		int tzOffsetWholeHours = tzOffsetMinutes / 60;
		int tzOffsetRemainderMinutes = tzOffsetMinutes - (tzOffsetWholeHours * 60);

		if (tzOffsetMinutes == 0) {
			return out + "+00:00";
		}

		if (tzOffsetWholeHours > 0) {
			out += "+" + (tzOffsetWholeHours < 10 ? "0" : "") + Math.abs(tzOffsetWholeHours);
		} else if (tzOffsetWholeHours < 0) {
			out += "-" + (tzOffsetWholeHours > -10 ? "0" : "") + Math.abs(tzOffsetWholeHours);
		} else {
			if (tzOffsetMinutes > 0) {
				out += "+00";
			} else {
				out += "-00";
			}
		}

		out += ":";

		if (tzOffsetRemainderMinutes > 0) {
			out += (tzOffsetRemainderMinutes < 10 ? "0" : "") + tzOffsetRemainderMinutes;
		} else if (tzOffsetRemainderMinutes < 0) {
			out += (tzOffsetRemainderMinutes > -10 ? "0" : "") + Math.abs(tzOffsetRemainderMinutes);
		} else {
			out += "00";
		}
		
		return out;
	}
	
	
	/**
	 * Parses an ISO 8601 representation in
	 * {@code YYYY-MM-DDThh:mm:ss±hh:mm} format.
	 *
	 * <p>Example: {@code 2019-11-01T18:19:43+03:00}
	 *
	 * @param s The string to parse.
	 *
	 * @return The date with timezone offset.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static DateWithTimeZoneOffset parseISO8601String(final String s)
		throws ParseException  {
		
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
		
		Date date;
		try {
			date = sdf.parse(s);
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage());
		}
		
		int tzOffsetMinutes;
		
		if (s.trim().endsWith("Z") || s.trim().endsWith("z")) {
			tzOffsetMinutes = 0; // UTC
		} else {
			try {
				// E.g. +03:00
				String offsetSpec = s.substring("2019-11-01T06:19:43".length());
				int hoursOffset = Integer.parseInt(offsetSpec.substring(0, 3));
				int minutesOffset = Integer.parseInt(offsetSpec.substring(4));
				if (offsetSpec.startsWith("+")) {
					tzOffsetMinutes = hoursOffset * 60 + minutesOffset;
				} else {
					// E.g. -03:00, -00:30
					tzOffsetMinutes = hoursOffset * 60 - minutesOffset;
				}
			} catch (Exception e) {
				throw new ParseException("Unexpected timezone offset: " + s);
			}
		}
		
		return new DateWithTimeZoneOffset(date, tzOffsetMinutes);
	}
}
