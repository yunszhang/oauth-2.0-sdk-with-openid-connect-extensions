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
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;


/**
 * DPoP proof JWT verifier for a protected resource.
 */
@ThreadSafe
public class DPoPProtectedResourceRequestVerifier extends DPoPCommonVerifier {
	
	
	/**
	 * Creates a new DPoP proof JWT verifier for a protected resource.
	 *
	 * @param acceptedJWSAlgs  The accepted JWS algorithms. Must be
	 *                         supported and not {@code null}.
	 * @param maxAgeSeconds    The maximum acceptable "iat" (issued-at)
	 *                         claim age, in seconds. JWTs older than that
	 *                         will be rejected.
	 * @param singleUseChecker The single use checker for the DPoP proof
	 *                         "jti" (JWT ID) claims, {@code null} if not
	 *                         specified.
	 */
	public DPoPProtectedResourceRequestVerifier(final Set<JWSAlgorithm> acceptedJWSAlgs,
						    final long maxAgeSeconds,
						    final SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker) {
		
		super(acceptedJWSAlgs, maxAgeSeconds, true, singleUseChecker);
	}
	
	
	/**
	 * Verifies the specified DPoP proof and its access token and JWK
	 * SHA-256 thumbprint bindings.
	 *
	 * @param method      The HTTP request method (case-insensitive). Must
	 *                    not be {@code null}.
	 * @param uri         The HTTP URI. Any query or fragment component
	 *                    will be stripped from it before DPoP validation.
	 *                    Must not be {@code null}.
	 * @param issuer      Unique identifier for the DPoP proof issuer, such
	 *                    as its client ID. Must not be {@code null}.
	 * @param proof       The DPoP proof JWT. Must not be {@code null}.
	 * @param accessToken The received DPoP access token. Must not be
	 *                    {@code null}.
	 * @param cnf         The JWK SHA-256 thumbprint confirmation for the
	 *                    DPoP access token. Must not be {@code null}.
	 *
	 * @throws InvalidDPoPProofException      If the DPoP proof is invalid.
	 * @throws AccessTokenValidationException If the DPoP access token
	 *                                        binding validation failed.
	 * @throws JOSEException                  If an internal JOSE exception
	 *                                        is encountered.
	 */
	public void verify(final String method,
			   final URI uri,
			   final DPoPIssuer issuer,
			   final SignedJWT proof,
			   final DPoPAccessToken accessToken,
			   final JWKThumbprintConfirmation cnf)
		throws
		InvalidDPoPProofException,
		AccessTokenValidationException,
		JOSEException {
		
		super.verify(method, uri, issuer, proof, accessToken, cnf);
	}
}
