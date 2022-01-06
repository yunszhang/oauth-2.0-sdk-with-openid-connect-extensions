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


import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * ISO 3166-1 alpha (letter-based) country code.
 */
public abstract class ISO3166_1AlphaCountryCode extends CountryCode {
	
	
	private static final long serialVersionUID = -3383887427716306419L;
	
	
	/**
	 * Creates a new ISO 3166-1 alpha (letter-based) country code.
	 * Normalises the code to upper case.
	 *
	 * @param value The country code value. Must be alphabetic.
	 */
	public ISO3166_1AlphaCountryCode(final String value) {
		super(value.toUpperCase());
		if (! StringUtils.isAlpha(value)) {
			throw new IllegalArgumentException("The ISO 3166-1 alpha country code must consist of letters");
		}
	}
	
	
	/**
	 * Returns the country name.
	 *
	 * @return The country name, {@code null} if not available.
	 */
	public abstract String getCountryName();
}
