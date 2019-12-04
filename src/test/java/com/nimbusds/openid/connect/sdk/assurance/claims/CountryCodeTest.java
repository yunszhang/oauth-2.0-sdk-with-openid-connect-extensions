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


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class CountryCodeTest extends TestCase {
	
	
	public void testParse() throws ParseException {
		
		CountryCode countryCode = CountryCode.parse("BG");
		ISO3166_1Alpha2CountryCode iso3166_1Alpha2CountryCode = countryCode.toISO3166_1Alpha2CountryCode();
		assertEquals("BG", iso3166_1Alpha2CountryCode.getValue());
	}
	
	
	public void testParseException() {
		
		try {
			CountryCode.parse("ABC");
			fail();
		} catch (ParseException e) {
			assertEquals("The ISO 3166-1 alpha-2 country code must be two letters", e.getMessage());
		}
	}
}
