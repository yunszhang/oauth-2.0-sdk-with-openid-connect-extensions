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

package com.nimbusds.openid.connect.sdk.assurance.request;


import java.util.Objects;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;


/**
 * Minimal verification request. Allows setting of a preferred trust framework
 * for the identity verification. Can be extended with additional setters.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 6.
 * </ul>
 */
@Immutable
public class MinimalVerificationRequest implements VerificationRequest {
	
	
	/**
	 * The underlying JSON object.
	 */
	protected final JSONObject jsonObject;
	
	
	/**
	 * Creates a new minimal verification request with the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	protected MinimalVerificationRequest(final JSONObject jsonObject) {
		Objects.requireNonNull(jsonObject);
		this.jsonObject = jsonObject;
	}
	
	
	/**
	 * Creates a new minimal verification request.
	 */
	public MinimalVerificationRequest() {
		this(new JSONObject());
		jsonObject.put("trust_framework", null);
	}
	
	
	/**
	 * Creates a new minimal verification request with a preferred trust
	 * framework.
	 *
	 * @param trustFramework The trust framework, {@code null} if not
	 *                       specified.
	 */
	public MinimalVerificationRequest(final IdentityTrustFramework trustFramework) {
		this();
		if (trustFramework != null) {
			JSONObject spec = new JSONObject();
			spec.put("value", trustFramework.getValue());
			jsonObject.put("trust_framework", spec);
		}
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		o.putAll(jsonObject);
		return o;
	}
	
	
	/**
	 * Parses a verification request from the specified JSON object
	 * representation.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The verification request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static MinimalVerificationRequest parse(final JSONObject jsonObject)
		throws ParseException {
		
		return new MinimalVerificationRequest(jsonObject);
	}
}
