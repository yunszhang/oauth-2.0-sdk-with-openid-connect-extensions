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


import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.AbstractMap;
import java.util.Map;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertUtils;
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
		Map.Entry<String, JSONObject> cnfClaim = toJWTClaim();
		jsonObject.put(cnfClaim.getKey(), cnfClaim.getValue());
		return jsonObject;
	}
	
	
	/**
	 * Returns this X.509 certificate SHA-256 confirmation as a JWT claim.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * "cnf" : { "x5t#S256" : "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" }
	 * </pre>
	 *
	 * @return The JWT claim name / value.
	 */
	public Map.Entry<String,JSONObject> toJWTClaim() {
		
		JSONObject cnf = new JSONObject();
		cnf.put("x5t#S256", x5tS256.toString());
		
		return new AbstractMap.SimpleImmutableEntry<>(
			"cnf",
			cnf
		);
	}
	
	
	/**
	 * Applies this X.509 certificate SHA-256 confirmation to the specified
	 * JWT claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set.
	 *
	 * @return The modified JWT claims set.
	 */
	public JWTClaimsSet applyTo(final JWTClaimsSet jwtClaimsSet) {
		
		Map.Entry<String, JSONObject> cnfClaim = toJWTClaim();
		
		return new JWTClaimsSet.Builder(jwtClaimsSet)
			.claim(cnfClaim.getKey(), cnfClaim.getValue())
			.build();
	}
	
	
	@Override
	public String toString() {
		return toJSONObject().toJSONString();
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
		
		JSONObject cnf;
		try {
			cnf = jwtClaimsSet.getJSONObjectClaim("cnf");
		} catch (ParseException e) {
			return null;
		}
		
		return parseFromConfirmationJSONObject(cnf);
	}
	
	
	/**
	 * Parses a X.509 certificate confirmation from the specified JSON
	 * object representation of a JWT claims set.
	 *
	 * @param jsonObject The JSON object.
	 *
	 * @return The X.509 certificate confirmation, {@code null} if not
	 *         found.
	 */
	public static X509CertificateConfirmation parse(final JSONObject jsonObject) {
		
		if (! jsonObject.containsKey("cnf")) {
			return null;
		}
		
		try {
			return parseFromConfirmationJSONObject(JSONObjectUtils.getJSONObject(jsonObject, "cnf"));
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Parses a X.509 certificate confirmation from the specified
	 * confirmation ("cnf") JSON object.
	 *
	 * @param cnf The confirmation JSON object, {@code null} if none.
	 *
	 * @return The X.509 certificate confirmation, {@code null} if not
	 *         found.
	 */
	public static X509CertificateConfirmation parseFromConfirmationJSONObject(final JSONObject cnf) {
		
		if (cnf == null) {
			return null;
		}
		
		try {
			String x5tString = JSONObjectUtils.getString(cnf, "x5t#S256");
			
			if (x5tString == null) {
				return null;
			}
			
			return new X509CertificateConfirmation(new Base64URL(x5tString));
			
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Creates a confirmation of the specified X.509 certificate.
	 *
	 * @param x509Cert The X.509 certificate.
	 *
	 * @return The X.509 certificate confirmation.
	 */
	public static X509CertificateConfirmation of(final X509Certificate x509Cert) {
		
		return new X509CertificateConfirmation(X509CertUtils.computeSHA256Thumbprint(x509Cert));
	}
}
