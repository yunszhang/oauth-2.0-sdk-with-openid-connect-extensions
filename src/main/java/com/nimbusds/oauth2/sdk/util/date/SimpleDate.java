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


import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Simple date. Supports ISO 8601 formatting and parsing.
 */
public class SimpleDate {
	
	
	/**
	 * The year.
	 */
	private final int year;
	
	
	/**
	 * The month.
	 */
	private final int month;
	
	
	/**
	 * The day of the month.
	 */
	private final int day;
	
	
	/**
	 * Creates a new simple date. No validation of month and day is
	 * performed.
	 *
	 * @param year  The year.
	 * @param month The month.
	 * @param day   The day of the month.
	 */
	public SimpleDate(final int year, final int month, final int day) {
		this.year = year;
		this.month = month;
		this.day = day;
	}
	
	
	/**
	 * Returns the year.
	 *
	 * @return The year.
	 */
	public int getYear() {
		return year;
	}
	
	
	/**
	 * Returns the month.
	 *
	 * @return The month.
	 */
	public int getMonth() {
		return month;
	}
	
	
	/**
	 * Returns the day of the month.
	 *
	 * @return The day of the month.
	 */
	public int getDay() {
		return day;
	}
	
	
	/**
	 * Returns an ISO 8601 representation in {@code YYYY-MM-DD} format.
	 *
	 * <p>Example: {@code 2019-11-01}
	 *
	 * @return The ISO 8601 representation.
	 */
	public String toISO8601String() {
		
		return getYear() + "-" + (getMonth() < 10 ? "0" : "") + getMonth() + "-" + (getDay() < 10 ? "0" : "") + getDay();
	}
	
	
	/**
	 * Parses an ISO 8601 representation in {@code YYYY-MM-DD} format.
	 *
	 * <p>Example: {@code 2019-11-01}
	 *
	 * @param s The string to parse.
	 *
	 * @return The simple date.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static SimpleDate parseISO8601String(final String s)
		throws ParseException {
		
		Pattern p = Pattern.compile("(\\d{4})-(\\d{2})-(\\d{2})");
		Matcher m = p.matcher(s);
		if (! m.matches()) {
			throw new ParseException("Invalid ISO 8601 date: YYYY-MM-DD");
		}
		return new SimpleDate(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)));
	}
}
