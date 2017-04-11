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

package com.nimbusds.openid.connect.sdk.validators;


import java.util.List;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import net.jcip.annotations.ThreadSafe;
import net.minidev.json.JSONObject;


/**
 * ID token claims verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.6 (draft 04).
 * </ul>
 */
@ThreadSafe
public class LogoutTokenClaimsVerifier implements JWTClaimsSetVerifier {
	
	
	/**
	 * The expected logout token issuer.
	 */
	private final Issuer expectedIssuer;


	/**
	 * The requesting client.
	 */
	private final ClientID expectedClientID;
	
	
	/**
	 * Creates a new logout token claims verifier.
	 *
	 * @param issuer   The expected ID token issuer. Must not be
	 *                 {@code null}.
	 * @param clientID The client ID. Must not be {@code null}. or positive
	 *                 integer.
	 */
	public LogoutTokenClaimsVerifier(final Issuer issuer,
					 final ClientID clientID) {
		
		if (issuer == null) {
			throw new IllegalArgumentException("The expected ID token issuer must not be null");
		}
		this.expectedIssuer = issuer;
		
		if (clientID == null) {
			throw new IllegalArgumentException("The client ID must not be null");
		}
		this.expectedClientID = clientID;
	}
	
	
	/**
	 * Returns the expected ID token issuer.
	 *
	 * @return The ID token issuer.
	 */
	public Issuer getExpectedIssuer() {
		
		return expectedIssuer;
	}
	
	
	/**
	 * Returns the client ID for verifying the ID token audience.
	 *
	 * @return The client ID.
	 */
	public ClientID getClientID() {
		
		return expectedClientID;
	}
	
	
	@Override
	public void verify(final JWTClaimsSet claimsSet, final SecurityContext ctx)
		throws BadJWTException {
		
		// See http://openid.net/specs/openid-connect-backchannel-1_0-ID1.html#Validation
		
		// Check event type
		try {
			JSONObject events = claimsSet.getJSONObjectClaim("events");
			
			if (events == null) {
				throw new BadJWTException("Missing JWT events (events) claim");
			}
			
			if (JSONObjectUtils.getJSONObject(events, LogoutTokenClaimsSet.EVENT_TYPE) == null) {
				throw new BadJWTException("Invalid event type, required " + LogoutTokenClaimsSet.EVENT_TYPE);
			}
			
		} catch (java.text.ParseException | ParseException e) {
			throw new BadJWTException("Invalid JWT events (events) claim");
		}
		
		
		// Check required claims, match them with expected where needed
		
		final String tokenIssuer = claimsSet.getIssuer();
		
		if (tokenIssuer == null) {
			throw BadJWTExceptions.MISSING_ISS_CLAIM_EXCEPTION;
		}
		
		if (! getExpectedIssuer().getValue().equals(tokenIssuer)) {
			throw new BadJWTException("Unexpected JWT issuer: " + tokenIssuer);
		}
		
		final List<String> tokenAudience = claimsSet.getAudience();
		
		if (tokenAudience == null || tokenAudience.isEmpty()) {
			throw BadJWTExceptions.MISSING_AUD_CLAIM_EXCEPTION;
		}
		
		if (! tokenAudience.contains(expectedClientID.getValue())) {
			throw new BadJWTException("Unexpected JWT audience: " + tokenAudience);
		}
		
		
		if (claimsSet.getIssueTime() == null) {
			throw BadJWTExceptions.MISSING_IAT_CLAIM_EXCEPTION;
		}
		
		if (claimsSet.getJWTID() == null) {
			throw new BadJWTException("Missing JWT ID (jti) claim");
		}
		
		
		// Either sub or sid must be present
		try {
			if (claimsSet.getSubject() == null && claimsSet.getStringClaim("sid") == null) {
				throw new BadJWTException("Missing subject (sub) and / or session ID (sid) claim(s)");
			}
			
		} catch (java.text.ParseException e) {
			throw new BadJWTException("Invalid session ID (sid) claim");
		}
		
		// Nonce illegal
		if (claimsSet.getClaim("nonce") != null) {
			throw new BadJWTException("Found illegal nonce (nonce) claim");
		}
	}
}
