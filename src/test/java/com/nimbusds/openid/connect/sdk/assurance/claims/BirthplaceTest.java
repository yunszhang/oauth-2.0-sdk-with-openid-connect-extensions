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


import java.util.Arrays;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class BirthplaceTest extends TestCase {
	
	
	public void testConstructor_jsonObject_noneSet() {
		
		Birthplace birthplace = new Birthplace(new JSONObject());
		assertNull(birthplace.getCountry());
		assertNull(birthplace.getRegion());
		assertNull(birthplace.getLocality());
		
		assertTrue(birthplace.toJSONObject().isEmpty());
	}
	
	
	public void testParamConstructor_noneSet() {
		
		Birthplace birthplace = new Birthplace(null, null, null);
		assertNull(birthplace.getCountry());
		assertNull(birthplace.getRegion());
		assertNull(birthplace.getLocality());
	}
	
	
	public void testParamConstructor_allSet() {
		
		for (CountryCode countryCode: Arrays.asList(
			ISO3166_1Alpha2CountryCode.DE,
			ISO3166_1Alpha3CountryCode.DEU,
			ISO3166_3CountryCode.DDDE)) {
			
			Birthplace birthplace = new Birthplace(countryCode, "Muster Region", "Musterstadt");
			assertEquals(countryCode.getValue(), birthplace.getCountry().getValue());
			assertEquals("Muster Region", birthplace.getRegion());
			assertEquals("Musterstadt", birthplace.getLocality());
			
			JSONObject jsonObject = birthplace.toJSONObject();
			assertEquals(3, jsonObject.size());
			
			birthplace = new Birthplace(jsonObject);
			assertEquals(countryCode.getValue(), birthplace.getCountry().getValue());
			assertEquals("Muster Region", birthplace.getRegion());
			assertEquals("Musterstadt", birthplace.getLocality());
		}
	}
	
	
	public void testGettersAndSetters() {
		
		for (CountryCode countryCode: Arrays.asList(
			ISO3166_1Alpha2CountryCode.DE,
			ISO3166_1Alpha3CountryCode.DEU,
			ISO3166_3CountryCode.DDDE)) {
			
			Birthplace birthplace = new Birthplace(new JSONObject());
			
			birthplace.setCountry(countryCode);
			assertEquals(countryCode, birthplace.getCountry());
			
			birthplace.setCountry(null);
			assertNull(birthplace.getCountry());
			
			birthplace.setRegion("Muster Region");
			assertEquals("Muster Region", birthplace.getRegion());
			
			birthplace.setRegion(null);
			assertNull(birthplace.getRegion());
			
			birthplace.setLocality("Musterstadt");
			assertEquals("Musterstadt", birthplace.getLocality());
			
			birthplace.setLocality(null);
			assertNull(birthplace.getLocality());
			
			assertTrue(birthplace.toJSONObject().isEmpty());
		}
	}
}
