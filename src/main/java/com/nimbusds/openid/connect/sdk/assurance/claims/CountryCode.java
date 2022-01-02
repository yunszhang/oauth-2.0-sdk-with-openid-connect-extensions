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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Abstract class for country codes.
 */
public abstract class CountryCode extends Identifier {
	
	
	private static final long serialVersionUID = -6171424661935191539L;
	
	
	/**
	 * Creates a new country code.
	 *
	 * @param value The country code value.
	 */
	protected CountryCode(final String value) {
		super(value);
	}
	
	
	/**
	 * Returns the length of this country code.
	 *
	 * @return The length.
	 */
	public int length() {
		
		return getValue().length();
	}
	
	
	/**
	 * Casts this code to an ISO 3166-1 alpha-2 (two-letter) country code.
	 *
	 * @return The ISO 3166-1 alpha-2 (two-letter) country code.
	 */
	public ISO3166_1Alpha2CountryCode toISO3166_1Alpha2CountryCode() {
		
		return (ISO3166_1Alpha2CountryCode)this;
	}
	
	
	/**
	 * Casts this code to an ISO 3166-1 alpha-3 (three-letter) country
	 * code.
	 *
	 * @return The ISO 3166-1 alpha-3 (three-letter) country code.
	 */
	public ISO3166_1Alpha3CountryCode toISO3166_1Alpha3CountryCode() {
		
		return (ISO3166_1Alpha3CountryCode)this;
	}
	
	
	/**
	 * Casts this code to an ISO 3166-3 country code.
	 *
	 * @return The ISO 3166-3 country code.
	 */
	public ISO3166_3CountryCode toISO3166_3CountryCode() {
		
		return (ISO3166_3CountryCode)this;
	}
	
	
	/**
	 * Parses a country code.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The country code.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CountryCode parse(final String s)
		throws ParseException {
		
		if (3 == s.length()) {
			return ISO3166_1Alpha3CountryCode.parse(s);
		} else if (2 == s.length()) {
			return ISO3166_1Alpha2CountryCode.parse(s);
		} else if (4 == s.length()) {
			return ISO3166_3CountryCode.parse(s);
		} else {
			throw new ParseException("The country code must be 3, 2 or 4 letters");
		}
	}
	
	
	@Override
	public abstract boolean equals(final Object other);
}
