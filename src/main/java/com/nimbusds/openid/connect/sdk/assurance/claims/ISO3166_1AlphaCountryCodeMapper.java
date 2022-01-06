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


/**
 * Utility for mapping between ISO 3166-1 alpha-2 and alpha-3 country codes.
 */
public class ISO3166_1AlphaCountryCodeMapper {
	
	
	/**
	 * The map resource.
	 */
	public static final String RESOURCE_FILE_NAME = "iso3166_1alpha-2-3-map.properties";
	
	
	/**
	 * Maps 2 to 3 letter codes.
	 */
	private static final Properties MAP_2_3 = new Properties();
	
	
	/**
	 * Maps 3 to 2 letter codes (reverse map).
	 */
	private static final Properties MAP_3_2 = new Properties();
	
	
	private static void lazyLoadMap_2_3() {
		
		if (! MAP_2_3.isEmpty()) {
			return;
		}
		
		// Resource based on https://en.wikipedia.org/w/index.php?title=ISO_3166-1&action=edit&section=7
		InputStream is = ISO3166_1AlphaCountryCodeMapper.class.getClassLoader().getResourceAsStream(RESOURCE_FILE_NAME);
		try {
			MAP_2_3.load(is);
		} catch (IOException e) {
			// Ignore
		}
	}
	
	
	private static void lazyLoadMap_3_2() {
		
		if (! MAP_3_2.isEmpty()) {
			return;
		}
		
		if (MAP_2_3.isEmpty()) {
			lazyLoadMap_2_3();
		}
		
		for (String code2: MAP_2_3.stringPropertyNames()) {
			String code3 = MAP_2_3.getProperty(code2);
			MAP_3_2.put(code3, code2);
		}
	}
	
	
	/**
	 * Maps the specified ISO 3166-1 alpha-2 (two letter) country code to
	 * its matching alpha-3 code, based on the {@link #RESOURCE_FILE_NAME}
	 * resource.
	 *
	 * @param alpha2Code The ISO 3166-1 alpha-2 country code. Must not be
	 *                   {@code null}.
	 *
	 * @return The matching alpha-3 code, {@code null} if no mapping is
	 *         present.
	 */
	public static ISO3166_1Alpha3CountryCode toAlpha3CountryCode(final ISO3166_1Alpha2CountryCode alpha2Code) {
		
		lazyLoadMap_2_3();
		String alpha3Code = MAP_2_3.getProperty(alpha2Code.getValue());
		return alpha3Code != null ? new ISO3166_1Alpha3CountryCode(alpha3Code) : null;
	}
	
	
	/**
	 * Maps the specified ISO 3166-1 alpha-3 (three letter) country code to
	 * its matching alpha-2 code, based on the {@link #RESOURCE_FILE_NAME}
	 * resource.
	 *
	 * @param alpha3Code The ISO 3166-1 alpha-3 country code. Must not be
	 *                   {@code null}.
	 *
	 * @return The matching alpha-2 code, {@code null} if no mapping is
	 *         present.
	 */
	public static ISO3166_1Alpha2CountryCode toAlpha2CountryCode(final ISO3166_1Alpha3CountryCode alpha3Code) {
		
		lazyLoadMap_3_2();
		String alpha2Code = MAP_3_2.getProperty(alpha3Code.getValue());
		return alpha2Code != null ? new ISO3166_1Alpha2CountryCode(alpha2Code) : null;
	}
}
