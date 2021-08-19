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

package com.nimbusds.oauth2.sdk.dpop.verifiers;


import java.net.URI;
import java.text.ParseException;
import java.util.*;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.singleuse.AlreadyUsedException;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;


/**
 * DPoP proof JWT claims set verifier.
 */
@ThreadSafe
class DPoPProofClaimsSetVerifier extends DefaultJWTClaimsVerifier<DPoPProofContext> {
	
	
	/**
	 * The max acceptable clock skew for the "iat" checks, in seconds.
	 */
	private final long maxClockSkewSeconds;
	
	
	/**
	 * The single use checker for the JWT ID ("jti") claims, {@code null}
	 * if not specified.
	 */
	private final SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker;
	
	
	/**
	 * Creates a new DPoP proof JWT claims set verifier.
	 *
	 * @param acceptedMethod      The accepted HTTP request method (case-
	 *                            insensitive). Must not be {@code null}.
	 * @param acceptedURI         The accepted endpoint URI. Any query or
	 *                            fragment component will be stripped from
	 *                            it before performing the comparison. Must
	 *                            not be {@code null}.
	 * @param maxClockSkewSeconds The max acceptable clock skew for the
	 *                            "iat" (issued-at) claim checks, in
	 *                            seconds. Should be in the order of a few
	 *                            seconds.
	 * @param requireATH          {@code true} to require an "ath" (access
	 *                            token hash) claim.
	 * @param singleUseChecker    The single use checker for the "jti" (JWT
	 *                            ID) claims, {@code null} if not
	 *                            specified.
	 */
	public DPoPProofClaimsSetVerifier(final String acceptedMethod,
					  final URI acceptedURI,
					  final long maxClockSkewSeconds,
					  final boolean requireATH,
					  final SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker) {
		
		super(
			new JWTClaimsSet.Builder()
				.claim("htm", acceptedMethod)
				.claim("htu", URIUtils.getBaseURI(acceptedURI).toString())
				.build(),
			new HashSet<>(
				requireATH ? Arrays.asList("jti", "iat", "ath") : Arrays.asList("jti", "iat")
			)
		);
		
		this.maxClockSkewSeconds = maxClockSkewSeconds;
		
		this.singleUseChecker = singleUseChecker;
	}
	
	
	@Override
	public void verify(final JWTClaimsSet claimsSet,
			   final DPoPProofContext context)
		throws BadJWTException {
	
		super.verify(claimsSet, context);
		
		// Check time window
		Date iat = claimsSet.getIssueTime();
		
		Date now = new Date();
		Date maxPast = new Date(now.getTime() - maxClockSkewSeconds * 1000L);
		Date maxAhead = new Date(now.getTime() + maxClockSkewSeconds * 1000L);
		
		if (iat.before(maxPast)) {
			throw new BadJWTException("The JWT iat claim is behind the current time by more than " + maxClockSkewSeconds + " seconds");
		}
		
		if (iat.after(maxAhead)) {
			throw new BadJWTException("The JWT iat claim is ahead of the current time by more than " + maxClockSkewSeconds + " seconds");
		}
		
		if (singleUseChecker != null) {
			JWTID jti = new JWTID(claimsSet.getJWTID());
			try {
				singleUseChecker.markAsUsed(new AbstractMap.SimpleImmutableEntry<>(context.getIssuer(), jti));
			} catch (AlreadyUsedException e) {
				throw new BadJWTException("The jti was used before: " + jti);
			}
		}
		
		if (getRequiredClaims().contains("ath")) {
			Base64URL ath;
			try {
				ath = new Base64URL(claimsSet.getStringClaim("ath"));
			} catch (ParseException e) {
				throw new BadJWTException("Invalid ath claim: " + e.getMessage(), e);
			}
			context.setAccessTokenHash(ath);
		}
	}
}
