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


import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;


/**
 * Birthplace claims set, serialisable to a JSON object.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 3.1.
 * </ul>
 */
@Immutable
public final class Birthplace extends ClaimsSet {
	

	public static final String COUNTRY_CLAIM_NAME = "country";
	
	
	public static final String REGION_CLAIM_NAME = "region";
	
	
	public static final String LOCALITY_CLAIM_NAME = "locality";
	
	
	/**
	 * The names of the standard place of birth claims.
	 */
	private static final Set<String> stdClaimNames = new LinkedHashSet<>();
	
	
	static {
		stdClaimNames.add(LOCALITY_CLAIM_NAME);
		stdClaimNames.add(REGION_CLAIM_NAME);
		stdClaimNames.add(COUNTRY_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the names of the standard birthplace claims.
	 *
	 * @return The names of the standard birthplace claims (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
		
		return Collections.unmodifiableSet(stdClaimNames);
	}
	
	
	/**
	 * Creates a new birthplace claims set.
	 *
	 * @param country  The country, as ISO3166-1 Alpha-2 or ISO3166-3 code.
	 *                 Must not be {@code null}.
	 * @param region   State, province, prefecture, or region component,
	 *                 {@code null} if not specified.
	 * @param locality City or other locality. Must not be {@code null}.
	 */
	public Birthplace(final CountryCode country, final String region, final String locality) {
	
		if (country == null) {
			throw new IllegalArgumentException("The country code must not be null");
		}
		setClaim(COUNTRY_CLAIM_NAME, country);
		
		setClaim(REGION_CLAIM_NAME, region);
		
		if (StringUtils.isNotBlank(locality)) {
			throw new IllegalArgumentException("The locality must not be null");
		}
		setClaim(LOCALITY_CLAIM_NAME, locality);
	}
	
	
	/**
	 * Creates a new birthplace claims set.
	 *
	 * @param country  The country, as ISO3166-1 Alpha-2 or ISO3166-3 code.
	 *                 Must not be {@code null}.
	 * @param locality City or other locality. Must not be {@code null}.
	 */
	public Birthplace(final CountryCode country, final String locality) {
	
		this(country, null, locality);
	}
}
