/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha3CountryCode;


public class AddressTest extends TestCase {
	
	
	private static final String FORMATTED = "Formatted";
	
	private static final String STREET_ADDRESS = "StreetAddress";
	
	private static final String LOCALITY = "Locality";
	
	private static final String REGION = "Region";
	
	private static final String POSTAL_CODE = "4000";
	
	private static final String COUNTRY = "Country";
	
	private static final CountryCode COUNTRY_CODE = new ISO3166_1Alpha3CountryCode("BUL");
	
	
	public void testEmpty()
		throws ParseException {
		
		Address address = new Address();
		
		assertNull(address.getFormatted());
		assertNull(address.getStreetAddress());
		assertNull(address.getLocality());
		assertNull(address.getRegion());
		assertNull(address.getPostalCode());
		assertNull(address.getCountry());
		assertNull(address.getCountryCode());
		
		assertTrue(address.toJSONObject().isEmpty());
		String json = address.toJSONString();
		assertEquals("{}", json);
		
		address = Address.parse(json);
		
		assertNull(address.getFormatted());
		assertNull(address.getStreetAddress());
		assertNull(address.getLocality());
		assertNull(address.getRegion());
		assertNull(address.getPostalCode());
		assertNull(address.getCountry());
		assertNull(address.getCountryCode());
		
		assertTrue(address.toJSONObject().isEmpty());
	}
	
	
	public void testClaim_formatted() {
		
		Address address = new Address();
		
		assertNull(address.getFormatted());
		address.setFormatted(FORMATTED);
		assertEquals(FORMATTED, address.getFormatted());
		address.setFormatted(null);
		assertNull(address.getFormatted());
		
		assertTrue(address.toJSONObject().isEmpty());
	}
	
	
	public void testClaimJSON_formatted()
		throws ParseException {
		
		Address address = new Address();
		
		address.setFormatted(FORMATTED);
		
		String json = address.toJSONString();
		assertEquals("{\"formatted\":\"" + FORMATTED + "\"}", json);
		
		address = Address.parse(json);
		assertEquals(FORMATTED, address.getFormatted());
	}
	
	
	public void testClaim_streetAddress() {
		
		Address address = new Address();
		
		assertNull(address.getStreetAddress());
		address.setStreetAddress(STREET_ADDRESS);
		assertEquals(STREET_ADDRESS, address.getStreetAddress());
		address.setStreetAddress(null);
		assertNull(address.getStreetAddress());
		
		assertTrue(address.toJSONObject().isEmpty());
	}
	
	
	public void testClaimJSON_streetAddress()
		throws ParseException {
		
		Address address = new Address();
		
		address.setStreetAddress(STREET_ADDRESS);
		
		String json = address.toJSONString();
		assertEquals("{\"street_address\":\"" + STREET_ADDRESS + "\"}", json);
		
		address = Address.parse(json);
		assertEquals(STREET_ADDRESS, address.getStreetAddress());
	}
	
	
	public void testClaim_locality() {
		
		Address address = new Address();
		
		assertNull(address.getLocality());
		address.setLocality(LOCALITY);
		assertEquals(LOCALITY, address.getLocality());
		address.setLocality(null);
		assertNull(address.getLocality());
		
		assertTrue(address.toJSONObject().isEmpty());
	}
	
	
	public void testClaimJSON_locality()
		throws ParseException {
		
		Address address = new Address();
		
		address.setLocality(LOCALITY);
		
		String json = address.toJSONString();
		assertEquals("{\"locality\":\"" + LOCALITY+ "\"}", json);
		
		address = Address.parse(json);
		assertEquals(LOCALITY, address.getLocality());
	}
	
	
	public void testClaim_region() {
		
		Address address = new Address();
		
		assertNull(address.getRegion());
		address.setRegion(REGION);
		assertEquals(REGION, address.getRegion());
		address.setRegion(null);
		assertNull(address.getRegion());
		
		assertTrue(address.toJSONObject().isEmpty());
	}
	
	
	public void testClaimJSON_region()
		throws ParseException {
		
		Address address = new Address();
		
		address.setRegion(REGION);
		
		String json = address.toJSONString();
		assertEquals("{\"region\":\"" + REGION + "\"}", json);
		
		address = Address.parse(json);
		assertEquals(REGION, address.getRegion());
	}
	
	
	public void testClaim_postalCode() {
		
		Address address = new Address();
		
		assertNull(address.getPostalCode());
		address.setPostalCode(POSTAL_CODE);
		assertEquals(POSTAL_CODE, address.getPostalCode());
		address.setPostalCode(null);
		assertNull(address.getPostalCode());
		
		assertTrue(address.toJSONObject().isEmpty());
	}
	
	
	public void testClaimJSON_postalCode()
		throws ParseException {
		
		Address address = new Address();
		
		address.setPostalCode(POSTAL_CODE);
		
		String json = address.toJSONString();
		assertEquals("{\"postal_code\":\"" + POSTAL_CODE + "\"}", json);
		
		address = Address.parse(json);
		assertEquals(POSTAL_CODE, address.getPostalCode());
	}
	
	
	public void testClaim_country() {
		
		Address address = new Address();
		
		assertNull(address.getCountry());
		address.setCountry(COUNTRY);
		assertEquals(COUNTRY, address.getCountry());
		address.setCountry(null);
		assertNull(address.getCountry());
		
		assertTrue(address.toJSONObject().isEmpty());
	}
	
	
	public void testClaimJSON_country()
		throws ParseException {
		
		Address address = new Address();
		
		address.setCountry(COUNTRY);
		
		String json = address.toJSONString();
		assertEquals("{\"country\":\"" + COUNTRY + "\"}", json);
		
		address = Address.parse(json);
		assertEquals(COUNTRY, address.getCountry());
	}
	
	
	public void testClaim_countryCode() {
		
		Address address = new Address();
		
		assertNull(address.getCountryCode());
		address.setCountryCode(COUNTRY_CODE);
		assertEquals(COUNTRY_CODE, address.getCountryCode());
		address.setCountryCode(null);
		assertNull(address.getCountryCode());
		
		assertTrue(address.toJSONObject().isEmpty());
	}
	
	
	public void testClaimJSON_countryCode()
		throws ParseException {
		
		Address address = new Address();
		
		address.setCountryCode(COUNTRY_CODE);
		
		String json = address.toJSONString();
		assertEquals("{\"country_code\":\"" + COUNTRY_CODE + "\"}", json);
		
		address = Address.parse(json);
		assertEquals(COUNTRY_CODE, address.getCountryCode());
	}
	
	
	public void testClaimJSON_countryCodeIllegal()
		throws ParseException {
		
		String illegalCountryCode = "ABCDE";
		
		try {
			CountryCode.parse(illegalCountryCode);
			fail();
		} catch (ParseException e) {
			assertEquals("The country code must be 3, 2 or 4 letters", e.getMessage());
		}
		
		String json = "{\"country_code\":\"" + illegalCountryCode + "\"}";
		
		Address address = Address.parse(json);
		assertNull(address.getCountryCode());
	}
	
	
	public void testParseNull() {
		
		try {
			Address.parse(null);
			fail();
		} catch (ParseException e) {
			assertEquals("The JSON string must not be null", e.getMessage());
		}
	}
	
	
	public void testParseEmpty()
		throws ParseException {
		
		Address address = Address.parse("{}");
		
		assertTrue(address.toJSONObject().isEmpty());
	}
}
