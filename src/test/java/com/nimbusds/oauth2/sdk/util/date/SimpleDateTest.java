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


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class SimpleDateTest extends TestCase {
	
	
	public void testVariant_1() throws ParseException {
		
		SimpleDate simpleDate = new SimpleDate(2019, 11, 1);
		
		assertEquals(2019, simpleDate.getYear());
		assertEquals(11, simpleDate.getMonth());
		assertEquals(1, simpleDate.getDay());
		
		String isoDate = simpleDate.toISO8601String();
		assertEquals("2019-11-01", isoDate);
		
		simpleDate = SimpleDate.parseISO8601String(isoDate);
		
		assertEquals(2019, simpleDate.getYear());
		assertEquals(11, simpleDate.getMonth());
		assertEquals(1, simpleDate.getDay());
	}
	
	
	public void testVariant_2() throws ParseException {
		
		SimpleDate simpleDate = new SimpleDate(2019, 1, 1);
		
		assertEquals(2019, simpleDate.getYear());
		assertEquals(1, simpleDate.getMonth());
		assertEquals(1, simpleDate.getDay());
		
		String isoDate = simpleDate.toISO8601String();
		assertEquals("2019-01-01", isoDate);
		
		simpleDate = SimpleDate.parseISO8601String(isoDate);
		
		assertEquals(2019, simpleDate.getYear());
		assertEquals(1, simpleDate.getMonth());
		assertEquals(1, simpleDate.getDay());
	}
	
	
	public void testVariant_3() throws ParseException {
		
		SimpleDate simpleDate = new SimpleDate(2019, 12, 31);
		
		assertEquals(2019, simpleDate.getYear());
		assertEquals(12, simpleDate.getMonth());
		assertEquals(31, simpleDate.getDay());
		
		String isoDate = simpleDate.toISO8601String();
		assertEquals("2019-12-31", isoDate);
		
		simpleDate = SimpleDate.parseISO8601String(isoDate);
		
		assertEquals(2019, simpleDate.getYear());
		assertEquals(12, simpleDate.getMonth());
		assertEquals(31, simpleDate.getDay());
	}
	
	
	public void testParseException_1() {
		
		try {
			SimpleDate.parseISO8601String("2019-11");
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid ISO 8601 date: YYYY-MM-DD", e.getMessage());
		}
	}
	
	
	public void testParseException_2() {
		
		try {
			SimpleDate.parseISO8601String("2019");
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid ISO 8601 date: YYYY-MM-DD", e.getMessage());
		}
	}
}
