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


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * ISO 3166-1 alpha-2 (two-letter) country code.
 */
@Immutable
public final class ISO3166_1Alpha2CountryCode extends CountryCode {
	
	
	private static final long serialVersionUID = -7659886425656766569L;
	
	
	/**
	 * Creates a new ISO 3166-1 alpha-2 country code. Normalises the code
	 * to upper case.
	 *
	 * @param value The country code value, must be two-letter.
	 */
	public ISO3166_1Alpha2CountryCode(final String value) {
		super(value.toUpperCase());
		if (value.length() != 2) {
			throw new IllegalArgumentException("The ISO 3166-1 alpha-2 country code must be two letters");
		}
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof ISO3166_1Alpha2CountryCode &&
			this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an ISO 3166-1 alpha-2 (two-letter) country code.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The ISO 3166-1 alpha-2 (two-letter) country code.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ISO3166_1Alpha2CountryCode parse(final String s)
		throws ParseException {
		
		try {
			return new ISO3166_1Alpha2CountryCode(s);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}
