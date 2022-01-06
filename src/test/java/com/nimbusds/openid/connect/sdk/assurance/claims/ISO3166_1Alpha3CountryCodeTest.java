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


public class ISO3166_1Alpha3CountryCodeTest extends TestCase {
	

	public void testConstructor() throws ParseException {
		
		ISO3166_1Alpha3CountryCode code = new ISO3166_1Alpha3CountryCode("SWE");
		assertEquals("SWE", code.getValue());
		
		code = ISO3166_1Alpha3CountryCode.parse(code.getValue());
		assertEquals("SWE", code.getValue());
		
		assertEquals(code, new ISO3166_1Alpha3CountryCode("SWE"));
		assertEquals(code, new ISO3166_1Alpha3CountryCode("swe"));
	}
	
	
	public void testLength() {
		
		try {
			new ISO3166_1Alpha3CountryCode("A");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ISO 3166-1 alpha-3 country code must be 3 letters", e.getMessage());
		}
		
		try {
			new ISO3166_1Alpha3CountryCode("ABCD");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ISO 3166-1 alpha-3 country code must be 3 letters", e.getMessage());
		}
	}
	
	
	public void testParseException_incorrectLength() {
		
		try {
			ISO3166_1Alpha3CountryCode.parse("AB");
			fail();
		} catch (ParseException e) {
			assertEquals("The ISO 3166-1 alpha-3 country code must be 3 letters", e.getMessage());
		}
	}
	
	
	public void testParseException_notLetters() {
		
		try {
			ISO3166_1Alpha3CountryCode.parse("AB1");
			fail();
		} catch (ParseException e) {
			assertEquals("The ISO 3166-1 alpha country code must consist of letters", e.getMessage());
		}
	}
	
	
	public void testNormalization() {
		
		assertEquals("SWE", new ISO3166_1Alpha3CountryCode("swe").getValue());
	}
	
	
	public void testInequality() {
		
		assertNotEquals(new ISO3166_1Alpha3CountryCode("SWE"), new ISO3166_1Alpha3CountryCode("BUL"));
	}
	
	
	public void testResources() {
		
		assertEquals("Bulgaria", ISO3166_1Alpha3CountryCode.BGR.getCountryName());
		assertEquals(ISO3166_1Alpha2CountryCode.BG, ISO3166_1Alpha3CountryCode.BGR.toAlpha2CountryCode());
	}
	
	
	public void testResources_invalidCode() {
		
		assertNull(new ISO3166_1Alpha3CountryCode("XXX").getCountryName());
		assertNull(new ISO3166_1Alpha3CountryCode("XXX").toAlpha2CountryCode());
	}
}
