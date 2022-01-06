/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.assurance.request;


import java.util.Collection;
import java.util.Objects;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;


/**
 * OpenID Connect verified claims set request, intended to represent the
 * {@code verified_claims} sub-element within a {@code userinfo} or
 * {@code id_token} element in a
 * {@link com.nimbusds.openid.connect.sdk.OIDCClaimsRequest claims} request
 * parameter.
 *
 * <p>Example:
 *
 * <pre>
 * {
 *   "verification": {
 *      "trust_framework": "eidas_ial"
 *   },
 *   "claims":{
 *      "given_name": null,
 *      "family_name": null,
 *      "birthdate": null
 *   }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.5.
 *     <li>OpenID Connect for Identity Assurance 1.0, section 6.
 * </ul>
 */
@Immutable
public class VerifiedClaimsSetRequest extends ClaimsSetRequest {
	
	
	/**
	 * The verification element.
	 */
	private final VerificationRequest verification;
	
	
	/**
	 * Creates a new empty OpenID Connect verified claims set request.
	 */
	public VerifiedClaimsSetRequest() {
		super();
		verification = new MinimalVerificationRequest();
	}
	
	
	/**
	 * Creates a new OpenID Connect verified claims set request.
	 *
	 * @param entries      The requested entries. Must not be
	 *                     {@code null}.
	 * @param verification The {@code verification} element. Must not be
	 *                     {@code null}.
	 */
	public VerifiedClaimsSetRequest(final Collection<Entry> entries,
					final VerificationRequest verification) {
		super(entries);
		
		if (verification == null) {
			throw new IllegalArgumentException("The verification element must not be null");
		}
		this.verification = verification;
	}
	
	
	/**
	 * Gets the {@code verification} element.
	 *
	 * @return The {@code verification} element, {@code null} if not
	 *         specified.
	 */
	public VerificationRequest getVerification() {
		return verification;
	}
	
	
	/**
	 * Sets the {@code verification} element.
	 *
	 * @param verification The {@code verification} element. Must not be
	 *                     {@code null}.
	 *
	 * @return The updated verified claims set request.
	 */
	public VerifiedClaimsSetRequest withVerification(final VerificationRequest verification) {
		return new VerifiedClaimsSetRequest(getEntries(), verification);
	}
	
	
	@Override
	public VerifiedClaimsSetRequest add(final String claimName) {
		ClaimsSetRequest csr = add(new Entry(claimName));
		return new VerifiedClaimsSetRequest(csr.getEntries(), getVerification());
	}
	
	
	@Override
	public VerifiedClaimsSetRequest add(final Entry entry) {
		ClaimsSetRequest csr = super.add(entry);
		return new VerifiedClaimsSetRequest(csr.getEntries(), getVerification());
	}
	
	
	@Override
	public VerifiedClaimsSetRequest delete(final String claimName, final LangTag langTag) {
		ClaimsSetRequest csr = super.delete(claimName, langTag);
		return new VerifiedClaimsSetRequest(csr.getEntries(), getVerification());
	}
	
	
	@Override
	public VerifiedClaimsSetRequest delete(final String claimName) {
		ClaimsSetRequest csr = super.delete(claimName);
		return new VerifiedClaimsSetRequest(csr.getEntries(), getVerification());
	}
	
	
	/**
	 * Returns the JSON object representation of this verified claims set
	 * request.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "verification": {
	 *      "trust_framework": "eidas"
	 *   },
	 *   "claims":{
	 *      "given_name": null,
	 *      "family_name": null,
	 *      "birthdate": null
	 *   }
	 * }
	 * </pre>
	 *
	 * @return The JSON object, empty if no claims are specified.
	 */
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		
		o.put(VerifiedClaimsSet.VERIFICATION_ELEMENT, getVerification().toJSONObject());
		
		JSONObject claims = super.toJSONObject();
		
		if (claims != null && ! claims.isEmpty()) {
			o.put(VerifiedClaimsSet.CLAIMS_ELEMENT, claims);
		}
		
		return o;
	}
	
	
	/**
	 * Parses an OpenID Connect verified claims set request from the
	 * specified JSON object representation.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "verification": {
	 *      "trust_framework": "eidas"
	 *   },
	 *   "claims":{
	 *      "given_name": null,
	 *      "family_name": null,
	 *      "birthdate": null
	 *   }
	 * }
	 * </pre>
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The verified claims set request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static VerifiedClaimsSetRequest parse(final JSONObject jsonObject)
		throws ParseException {
		
		MinimalVerificationRequest verification = MinimalVerificationRequest.parse(
			JSONObjectUtils.getJSONObject(jsonObject, VerifiedClaimsSet.VERIFICATION_ELEMENT, null)
		);
		
		JSONObject claimsJSONObject = JSONObjectUtils.getJSONObject(jsonObject, VerifiedClaimsSet.CLAIMS_ELEMENT, new JSONObject());
		
		if (claimsJSONObject.isEmpty()) {
			throw new ParseException("Empty verified claims object");
		}
		
		return new VerifiedClaimsSetRequest(
			ClaimsSetRequest.parse(claimsJSONObject).getEntries(),
			verification
		);
	}
	
	
	/**
	 * Parses an OpenID Connect verified claims set request from the
	 * specified JSON object string representation.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "verification": {
	 *      "trust_framework": "eidas"
	 *   },
	 *   "claims":{
	 *      "given_name": null,
	 *      "family_name": null,
	 *      "birthdate": null
	 *   }
	 * }
	 * </pre>
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The verified claims set request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static VerifiedClaimsSetRequest parse(final String json)
		throws ParseException {
		
		return parse(JSONObjectUtils.parse(json));
	}
}
