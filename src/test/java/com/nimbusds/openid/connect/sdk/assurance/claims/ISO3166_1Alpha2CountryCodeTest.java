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


public class ISO3166_1Alpha2CountryCodeTest extends TestCase {
	

	public void testConstructor() throws ParseException {
		
		ISO3166_1Alpha2CountryCode code = new ISO3166_1Alpha2CountryCode("BG");
		assertEquals("BG", code.getValue());
		
		code = ISO3166_1Alpha2CountryCode.parse(code.getValue());
		assertEquals("BG", code.getValue());
		
		assertEquals(code, new ISO3166_1Alpha2CountryCode("BG"));
		assertEquals(code, new ISO3166_1Alpha2CountryCode("bg"));
	}
	
	
	public void testLength() {
		
		try {
			new ISO3166_1Alpha2CountryCode("A");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ISO 3166-1 alpha-2 country code must be 2 letters", e.getMessage());
		}
		
		try {
			new ISO3166_1Alpha2CountryCode("ABD");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ISO 3166-1 alpha-2 country code must be 2 letters", e.getMessage());
		}
	}
	
	
	public void testParseException_incorrectLength() {
		
		try {
			ISO3166_1Alpha2CountryCode.parse("ABC");
			fail();
		} catch (ParseException e) {
			assertEquals("The ISO 3166-1 alpha-2 country code must be 2 letters", e.getMessage());
		}
	}
	
	
	public void testParseException_notLetters() {
		
		try {
			ISO3166_1Alpha2CountryCode.parse("A1");
			fail();
		} catch (ParseException e) {
			assertEquals("The ISO 3166-1 alpha-2 country code must be 2 letters", e.getMessage());
		}
	}
	
	
	public void testNormalization() {
		
		assertEquals("BG", new ISO3166_1Alpha2CountryCode("bg").getValue());
	}
	
	
	public void testInequality() {
		
		assertNotEquals(new ISO3166_1Alpha2CountryCode("BG"), new ISO3166_1Alpha2CountryCode("GB"));
	}
}
