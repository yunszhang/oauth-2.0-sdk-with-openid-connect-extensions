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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class ISO3166_3CountryCodeTest extends TestCase {
	

	public void testConstructor_withSuccessor() throws ParseException {
		
		ISO3166_3CountryCode code = new ISO3166_3CountryCode("BUMM");
		assertEquals("BUMM", code.getValue());
		
		assertEquals(new ISO3166_1Alpha2CountryCode("BU"), code.getFormerCode());
		assertEquals(new ISO3166_1Alpha2CountryCode("MM"), code.getNewCode());
		
		assertEquals("BU", code.getFirstComponentString());
		assertEquals("MM", code.getSecondComponentString());
		
		assertEquals("Burma", code.getCountryName());
		
		code = ISO3166_3CountryCode.parse(code.getValue());
		assertEquals("BUMM", code.getValue());
		
		assertEquals(code, new ISO3166_3CountryCode("BUMM"));
		assertEquals(code, new ISO3166_3CountryCode("bumm"));
	}
	

	public void testConstructor_noSuccessor() throws ParseException {
		
		ISO3166_3CountryCode code = new ISO3166_3CountryCode("CSHH");
		assertEquals("CSHH", code.getValue());
		
		assertEquals(new ISO3166_1Alpha2CountryCode("CS"), code.getFormerCode());
		assertNull(code.getNewCode());
		
		assertEquals("CS", code.getFirstComponentString());
		assertEquals("HH", code.getSecondComponentString());
		
		assertEquals("Czechoslovakia", code.getCountryName());
		
		code = ISO3166_3CountryCode.parse(code.getValue());
		assertEquals("CSHH", code.getValue());
		
		assertEquals(code, new ISO3166_3CountryCode("CSHH"));
		assertEquals(code, new ISO3166_3CountryCode("cshh"));
	}
	

	public void testConstructor_noSuccessor_specialCase() throws ParseException {
		
		ISO3166_3CountryCode code = new ISO3166_3CountryCode("CSXX");
		assertEquals("CSXX", code.getValue());
		
		assertEquals(new ISO3166_1Alpha2CountryCode("CS"), code.getFormerCode());
		assertNull(code.getNewCode());
		
		assertEquals("CS", code.getFirstComponentString());
		assertEquals("XX", code.getSecondComponentString());
		
		assertEquals("Serbia and Montenegro", code.getCountryName());
		
		code = ISO3166_3CountryCode.parse(code.getValue());
		assertEquals("CSXX", code.getValue());
		
		assertEquals(code, new ISO3166_3CountryCode("CSXX"));
		assertEquals(code, new ISO3166_3CountryCode("csxx"));
	}
	
	
	public void testLength() {
		
		try {
			new ISO3166_3CountryCode("A");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ISO 3166-3 country code must be 4 letters", e.getMessage());
		}
		
		try {
			new ISO3166_3CountryCode("AB");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ISO 3166-3 country code must be 4 letters", e.getMessage());
		}
		
		try {
			new ISO3166_3CountryCode("ABC");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ISO 3166-3 country code must be 4 letters", e.getMessage());
		}
		
		try {
			new ISO3166_3CountryCode("ABCDE");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ISO 3166-3 country code must be 4 letters", e.getMessage());
		}
	}
	
	
	public void testParseException_incorrectLength() {
		
		try {
			ISO3166_3CountryCode.parse("ABC");
			fail();
		} catch (ParseException e) {
			assertEquals("The ISO 3166-3 country code must be 4 letters", e.getMessage());
		}
	}
	
	
	public void testParseException_notLetters() {
		
		try {
			ISO3166_3CountryCode.parse("A1");
			fail();
		} catch (ParseException e) {
			assertEquals("The ISO 3166-3 country code must be 4 letters", e.getMessage());
		}
	}
	
	
	public void testNormalization() {
		
		assertEquals("CSHH", new ISO3166_3CountryCode("cshh").getValue());
	}
	
	
	public void testInequality() {
		
		assertNotEquals(new ISO3166_3CountryCode("CSHH"), new ISO3166_3CountryCode("BUMM"));
	}
}
