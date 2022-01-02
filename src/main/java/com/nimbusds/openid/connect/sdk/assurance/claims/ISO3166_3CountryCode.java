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
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * ISO 3166-3 country code for former countries and territories.
 */
@Immutable
public final class ISO3166_3CountryCode extends CountryCode {
	
	
	private static final long serialVersionUID = 614967184722743546L;
	
	
	/**
	 * Creates a new ISO 3166-3 country code. Normalises the code to upper
	 * case.
	 *
	 * @param value The country code value, must be four-letter.
	 */
	public ISO3166_3CountryCode(final String value) {
		super(value.toUpperCase());
		if (value.length() != 4 || !StringUtils.isAlpha(value)) {
			throw new IllegalArgumentException("The ISO 3166-3 country code must be 4 letters");
		}
	}
	
	
	/**
	 * Returns the former country code (the first component).
	 *
	 * @return The former country code as an ISO 3166-1 alpha-2
	 *         (two-letter) country code.
	 */
	public ISO3166_1Alpha2CountryCode getFormerCode() {
		
		return new ISO3166_1Alpha2CountryCode(getFirstComponentString());
	}
	
	
	/**
	 * Returns the new country code (the second component), unless the
	 * former country is divided and there is no single successor country
	 * (indicated by an "HH" or "XX" code).
	 *
	 * @return The new country code as an ISO 3166-1 alpha-2 (two-letter)
	 *         country code, {@code null} if the former country is divided.
	 *         and there is no single successor country.
	 */
	public ISO3166_1Alpha2CountryCode getNewCode() {
		
		if ("HH".equals(getSecondComponentString()) || "XX".equals(getSecondComponentString())) {
			return null;
		}
		
		return new ISO3166_1Alpha2CountryCode(getSecondComponentString());
	}
	
	
	/**
	 * Returns the first component (the first two letters) representing the
	 * former country code.
	 *
	 * @return The first component as a string.
	 */
	public String getFirstComponentString() {
		
		return getValue().substring(0, 2);
	}
	
	
	/**
	 * Returns the second component (the last two letters).
	 *
	 * @return The second component as a string.
	 */
	public String getSecondComponentString() {
		
		return getValue().substring(2, 4);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof ISO3166_3CountryCode &&
			this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an ISO 3166-3 country code.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The ISO 3166-3 country code.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ISO3166_3CountryCode parse(final String s)
		throws ParseException {
		
		try {
			return new ISO3166_3CountryCode(s);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}
