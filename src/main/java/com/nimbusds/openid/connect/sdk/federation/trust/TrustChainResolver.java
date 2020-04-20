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

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.util.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.TrustChainConstraints;


/**
 * Trust chain resolver.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.
 * </ul>
 */
public class TrustChainResolver {
	

	private final Map<EntityID, JWKSet> trustAnchors;
	
	
	private final TrustChainConstraints constraints;
	
	
	private final DefaultEntityStatementRetriever entityStatementRetriever;
	
	
	public TrustChainResolver(final EntityID trustAnchor,
				  final JWKSet trustAnchorJWKSet) {
		trustAnchors = new HashMap<>();
		trustAnchors.put(trustAnchor, trustAnchorJWKSet);
		constraints = new TrustChainConstraints();
		entityStatementRetriever = new DefaultEntityStatementRetriever();
	}
	
	
	public TrustChainResolver(final Map<EntityID, JWKSet> trustAnchors,
				  final TrustChainConstraints constraints,
				  final int httpConnectTimeoutMs,
				  final int httpReadTimeoutMs) {
		if (MapUtils.isEmpty(trustAnchors)) {
			throw new IllegalArgumentException("The trust anchors map must not be empty or null");
		}
		this.trustAnchors = trustAnchors;
		if (constraints != null) {
			this.constraints = constraints;
		} else {
			this.constraints = new TrustChainConstraints();
		}
		entityStatementRetriever = new DefaultEntityStatementRetriever(httpConnectTimeoutMs, httpReadTimeoutMs);
	}
	
	
	/**
	 * Returns the configured trust anchors.
	 *
	 * @return The configured trust anchors, as entity ID - public JWK set
	 *         pairs.
	 */
	public Map<EntityID, JWKSet> getTrustAnchors() {
		return Collections.unmodifiableMap(trustAnchors);
	}
	
	
	public Set<TrustChain> resolveTrustChains(final EntityID target)
		throws ResolveException, JOSEException, ParseException {
		
		if (trustAnchors.get(target) != null) {
			throw new ResolveException("Target is trust anchor");
		}
		
		TrustChainFetch trustChainFetch = new TrustChainFetch(entityStatementRetriever, constraints);
		
		Set<TrustChain> fetchedTrustChains = trustChainFetch.fetch(target);
		
		if (fetchedTrustChains.isEmpty()) {
		
		}
		
		return fetchedTrustChains;
	}
}
