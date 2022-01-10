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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.util.StringUtils;


public class ISO3166_1CountryCodeResourcesTest extends TestCase {
	
	
	private Properties loadCodes(int len) {
		
		Properties properties = new Properties();
		try {
			
			InputStream is = getClass().getClassLoader().getResourceAsStream("iso3166_1alpha" + len + "-codes.properties");
			properties.load(is);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return properties;
	}


	public void test2LetterCodes() {
		
		Properties codes = loadCodes(2);
		
		assertEquals(249, codes.size());
		
		for (String alpha2Code: codes.stringPropertyNames()) {
			
			assertEquals(2, alpha2Code.length());
			String countryName = codes.getProperty(alpha2Code);
			assertTrue(StringUtils.isNotBlank(countryName));
			
			ISO3166_1Alpha2CountryCode isoAlpha2Code = new ISO3166_1Alpha2CountryCode(alpha2Code);
			assertEquals(countryName, isoAlpha2Code.getCountryName());
			
			ISO3166_1Alpha3CountryCode isoAlpha3Code = isoAlpha2Code.toAlpha3CountryCode();
			assertEquals(countryName, isoAlpha3Code.getCountryName());
		}
	}


	public void test3LetterCodes() {
		
		Properties codes = loadCodes(3);
		
		assertEquals(249, codes.size());
		
		for (String alpha3Code: codes.stringPropertyNames()) {
			
			assertEquals(3, alpha3Code.length());
			String countryName = codes.getProperty(alpha3Code);
			assertTrue(StringUtils.isNotBlank(countryName));
			
			ISO3166_1Alpha3CountryCode isoAlpha3Code = new ISO3166_1Alpha3CountryCode(alpha3Code);
			assertEquals(countryName, isoAlpha3Code.getCountryName());
			
			ISO3166_1Alpha2CountryCode isoAlpha2Code = isoAlpha3Code.toAlpha2CountryCode();
			assertEquals(countryName, isoAlpha2Code.getCountryName());
		}
	}
	
	
	public void testCrossCheck() {
	
		Properties codes2 = loadCodes(2);
		Properties codes3 = loadCodes(3);
		
		for (String code2: codes2.stringPropertyNames()) {
			String countryName = codes2.getProperty(code2);
			assertNotNull(countryName);
			assertTrue(codes3.containsValue(countryName));
		}
	}
}
