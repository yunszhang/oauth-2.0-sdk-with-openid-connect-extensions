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

package com.nimbusds.openid.connect.sdk.claims;


import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.id.Subject;


/**
 * Common claims set.
 */
public abstract class CommonClaimsSet extends ClaimsSet {
	
	
	/**
	 * The subject claim name.
	 */
	public static final String SUB_CLAIM_NAME = "sub";
	
	
	/**
	 * The issue time claim name.
	 */
	public static final String IAT_CLAIM_NAME = "iat";
	
	
	/**
	 * The names of the standard top-level claims.
	 */
	private static final Set<String> STD_CLAIM_NAMES;
	
	
	static {
		Set<String> claimNames = new HashSet<>(ClaimsSet.getStandardClaimNames());
		claimNames.add(SUB_CLAIM_NAME);
		claimNames.add(IAT_CLAIM_NAME);
		STD_CLAIM_NAMES = Collections.unmodifiableSet(claimNames);
	}
	
	
	/**
	 * Gets the names of the standard top-level claims.
	 *
	 * @return The names of the standard top-level claims (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
		
		return STD_CLAIM_NAMES;
	}
	
	
	/**
	 * Creates a new empty common claims set.
	 */
	protected CommonClaimsSet() {
		
		super();
	}
	
	
	/**
	 * Creates a new common claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	protected CommonClaimsSet(final JSONObject jsonObject) {
		
		super(jsonObject);
	}
	
	
	/**
	 * Gets the subject. Corresponds to the {@code sub} claim.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {
		
		String val = getStringClaim(SUB_CLAIM_NAME);
		return val != null ? new Subject(val) : null;
	}
	
	
	/**
	 * Gets the issue time. Corresponds to the {@code iss} claim.
	 *
	 * @return The issue time, {@code null} if not specified.
	 */
	public Date getIssueTime() {
		
		return getDateClaim(IAT_CLAIM_NAME);
	}
}
