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


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.assurance.IdentityVerification;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;


/**
 * Verified claims set.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 4.
 * </ul>
 */
public class VerifiedClaimsSet extends ClaimsSet {
	
	
	/**
	 * The verification claim name.
	 */
	public static final String VERIFICATION_CLAIM_NAME = "verification";
	
	
	/**
	 * The claims claim name.
	 */
	public static final String CLAIMS_CLAIM_NAME = "claims";
	

	public VerifiedClaimsSet(final IdentityVerification verification,
				 final ClaimsSet claims) {
		
		setClaim(VERIFICATION_CLAIM_NAME, verification.toJSONObject());
		setClaim(CLAIMS_CLAIM_NAME, claims.toJSONObject());
	}
	
	
	public IdentityVerification getVerification() {
	
	
	}
	
	
	public ClaimsSet getClaimsSet() {
	
	
	}
	
	
	public static VerifiedClaimsSet parse(final JSONObject jsonObject)
		throws ParseException {
		
		
	}
}
