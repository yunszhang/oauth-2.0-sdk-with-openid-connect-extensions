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


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;


public class DateWithTimeZoneOffsetTest extends TestCase {
	
	
	public void testWithNoOffset() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, 0);
		assertEquals(date, dtz.getDate());
		assertEquals(0, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-01T16:19:43+00:00", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(0, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testWithPositiveOffset() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, 3 * 60);
		assertEquals(date, dtz.getDate());
		assertEquals(3 * 60, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-01T19:19:43+03:00", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(3 * 60, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testWithPositiveOffset_minutes() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, 3 * 60 + 30);
		assertEquals(date, dtz.getDate());
		assertEquals(3 * 60 + 30, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-01T19:49:43+03:30", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(3 * 60 + 30, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testWithPositiveOffset_minutesOnly() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, 30);
		assertEquals(date, dtz.getDate());
		assertEquals(30, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-01T16:49:43+00:30", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(30, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testWithPositiveOffset_10h() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, 10 * 60);
		assertEquals(date, dtz.getDate());
		assertEquals(10 * 60, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-02T02:19:43+10:00", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(10 * 60, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testWithNegativeOffset() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, -3 * 60);
		assertEquals(date, dtz.getDate());
		assertEquals(-3 * 60, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-01T13:19:43-03:00", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(-3 * 60, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testWithNegativeOffset_minutes() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, -3 * 60 - 30);
		assertEquals(date, dtz.getDate());
		assertEquals(-3 * 60 - 30, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-01T12:49:43-03:30", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(-3 * 60 - 30, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testWithNegativeOffset_minutesOnly() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, -30);
		assertEquals(date, dtz.getDate());
		assertEquals(-30, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-01T15:49:43-00:30", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(-30, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testWithNegativeOffset_10h() throws ParseException {
		
		// 2019-11-01T16:19:43Z
		Date date = DateUtils.fromSecondsSinceEpoch(1572625183L);
		DateWithTimeZoneOffset dtz = new DateWithTimeZoneOffset(date, -10 * 60);
		assertEquals(date, dtz.getDate());
		assertEquals(-10 * 60, dtz.getTimeZoneOffsetMinutes());
		assertEquals("2019-11-01T06:19:43-10:00", dtz.toISO8601String());
		
		dtz = DateWithTimeZoneOffset.parseISO8601String(dtz.toISO8601String());
		assertEquals(date, dtz.getDate());
		assertEquals(-10 * 60, dtz.getTimeZoneOffsetMinutes());
	}
	
	
	public void testParseUTC_Z() throws ParseException {
		
		DateWithTimeZoneOffset dtz = DateWithTimeZoneOffset.parseISO8601String("2019-11-01T16:19:43Z");
		assertEquals(DateUtils.fromSecondsSinceEpoch(1572625183L), dtz.getDate());
		assertEquals(0, dtz.getTimeZoneOffsetMinutes());
	}
}
