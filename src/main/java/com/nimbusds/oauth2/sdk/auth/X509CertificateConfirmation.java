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

package com.nimbusds.oauth2.sdk.auth;


import java.text.ParseException;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;


/**
 * X.509 certificate SHA-256 confirmation.
 */
@Immutable
public final class X509CertificateConfirmation {
	
	
	/**
	 * The X.509 certificate SHA-256 thumbprint.
	 */
	private final Base64URL x5tS256;
	
	
	/**
	 * Creates a new X.509 certificate SHA-256 confirmation.
	 *
	 * @param x5tS256 The X.509 certificate SHA-256 thumbprint.
	 */
	public X509CertificateConfirmation(final Base64URL x5tS256) {
		
		if (x5tS256 == null) {
			throw new IllegalArgumentException("The X.509 certificate thumbprint must not be null");
		}
		
		this.x5tS256 = x5tS256;
	}
	
	
	/**
	 * Returns the X.509 certificate SHA-256 thumbprint.
	 *
	 * @return The X.509 certificate SHA-256 thumbprint.
	 */
	public Base64URL getValue() {
		
		return x5tS256;
	}
	
	
	/**
	 * Returns this X.509 certificate SHA-256 confirmation as a JSON
	 * object.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "cnf" : { "x5t#S256" : "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" }
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject jsonObject = new JSONObject();
		JSONObject cnf = new JSONObject();
		cnf.put("x5t#S256", x5tS256.toString());
		jsonObject.put("cnf", cnf);
		return jsonObject;
	}
	
	
	@Override
	public boolean equals(final Object o) {
		if (this == o) return true;
		if (!(o instanceof X509CertificateConfirmation)) return false;
		X509CertificateConfirmation that = (X509CertificateConfirmation) o;
		return x5tS256 != null ? x5tS256.equals(that.x5tS256) : that.x5tS256 == null;
	}
	
	
	@Override
	public int hashCode() {
		return x5tS256 != null ? x5tS256.hashCode() : 0;
	}
	
	
	/**
	 * Parses a X.509 certificate confirmation from the specified JWT
	 * claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set.
	 *
	 * @return The X.509 certificate confirmation, {@code null} if not
	 *         found.
	 */
	public static X509CertificateConfirmation parse(final JWTClaimsSet jwtClaimsSet) {
		
		try {
			JSONObject cnf = jwtClaimsSet.getJSONObjectClaim("cnf");
			
			if (cnf == null) {
				return null;
			}
			
			String x5tString = JSONObjectUtils.getString(cnf, "x5t#S256");
			
			if (x5tString == null) {
				return null;
			}
			
			return new X509CertificateConfirmation(new Base64URL(x5tString));
			
		} catch (ParseException e) {
			return null;
		}
	}
}
