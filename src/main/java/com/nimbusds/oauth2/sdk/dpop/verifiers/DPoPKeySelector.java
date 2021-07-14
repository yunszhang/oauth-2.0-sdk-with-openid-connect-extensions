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


import java.security.Key;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;


/**
 * DPoP key selector based on the "jwk" JWS header parameter.
 */
class DPoPKeySelector implements JWSKeySelector<DPoPProofContext> {
	
	
	/**
	 * The accepted JWS algorithms.
	 */
	private final Set<JWSAlgorithm> acceptedJWSAlgs;
	
	
	/**
	 * Creates a new DPoP key selector.
	 *
	 * @param acceptedJWSAlgs The accepted JWS algorithms. Must not be
	 *                        empty or {@code null}.
	 */
	DPoPKeySelector(final Set<JWSAlgorithm> acceptedJWSAlgs) {
		if (CollectionUtils.isEmpty(acceptedJWSAlgs)) {
			throw new IllegalArgumentException();
		}
		this.acceptedJWSAlgs = acceptedJWSAlgs;
	}
	
	
	@Override
	public List<Key> selectJWSKeys(final JWSHeader header, final DPoPProofContext context)
		throws KeySourceException {
		
		JWSAlgorithm alg = header.getAlgorithm();
		
		if (! acceptedJWSAlgs.contains(alg)) {
			throw new KeySourceException("JWS header algorithm not accepted: " + alg);
		}
		
		JWK jwk = header.getJWK();
		
		if (jwk == null) {
			throw new KeySourceException("Missing JWS jwk header parameter");
		}
		
		List<Key> candidates = new LinkedList<>();
		if (JWSAlgorithm.Family.RSA.contains(alg) && jwk instanceof RSAKey) {
			try {
				candidates.add(((RSAKey)jwk).toRSAPublicKey());
			} catch (JOSEException e) {
				throw new KeySourceException("Invalid RSA JWK: " + e.getMessage(), e);
			}
		} else if (JWSAlgorithm.Family.EC.contains(alg) && jwk instanceof ECKey) {
			try {
				candidates.add(((ECKey)jwk).toECPublicKey());
			} catch (JOSEException e) {
				throw new KeySourceException("Invalid EC JWK: " + e.getMessage(), e);
			}
		} else {
			throw new KeySourceException("JWS header alg / jwk mismatch: alg=" + alg + " jwk.kty=" + jwk.getKeyType());
		}
		
		return candidates;
	}
}
