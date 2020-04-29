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
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


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
	
	
	/**
	 * The configured trust anchors with their public JWK sets.
	 */
	private final Map<EntityID, JWKSet> trustAnchors;
	
	
	/**
	 * The entity statement retriever.
	 */
	private final EntityStatementRetriever statementRetriever;
	
	
	/**
	 * Creates a new trust chain resolver with a single trust anchor.
	 *
	 * @param trustAnchor       The trust anchor. Must not be {@code null}.
	 * @param trustAnchorJWKSet The trust anchor public JWK set. Must not
	 *                          be {@code null}.
	 */
	public TrustChainResolver(final EntityID trustAnchor,
				  final JWKSet trustAnchorJWKSet) {
		this(Collections.singletonMap(trustAnchor, trustAnchorJWKSet), new DefaultEntityStatementRetriever());
	}
	
	
	/**
	 * Creates a new trust chain resolver with multiple trust anchors.
	 *
	 * @param trustAnchors         The trust anchors with their public JWK
	 *                             sets. Must contain at least one anchor.
	 * @param httpConnectTimeoutMs The HTTP connect timeout in
	 *                             milliseconds, zero means timeout
	 *                             determined by the underlying HTTP
	 *                             client.
	 * @param httpReadTimeoutMs    The HTTP read timeout in milliseconds,
	 *                             zero means timout determined by the
	 *                             underlying HTTP client.
	 */
	public TrustChainResolver(final Map<EntityID, JWKSet> trustAnchors,
				  final int httpConnectTimeoutMs,
				  final int httpReadTimeoutMs) {
		this(trustAnchors, new DefaultEntityStatementRetriever(httpConnectTimeoutMs, httpReadTimeoutMs));
	}
	
	
	/**
	 * Creates new trust chain resolver.
	 *
	 * @param trustAnchors       The trust anchors with their public JWK
	 *                           sets. Must contain at least one anchor.
	 * @param statementRetriever The entity statement retriever to use.
	 *                           Must not be {@code null}.
	 */
	public TrustChainResolver(final Map<EntityID, JWKSet> trustAnchors,
				  final EntityStatementRetriever statementRetriever) {
		if (MapUtils.isEmpty(trustAnchors)) {
			throw new IllegalArgumentException("The trust anchors map must not be empty or null");
		}
		this.trustAnchors = trustAnchors;
		
		if (statementRetriever == null) {
			throw new IllegalArgumentException("The entity statement retriever must not be null");
		}
		this.statementRetriever = statementRetriever;
	}
	
	
	/**
	 * Returns the configured trust anchors.
	 *
	 * @return The trust anchors with their public JWK sets. Contains at
	 *         least one anchor.
	 */
	public Map<EntityID, JWKSet> getTrustAnchors() {
		return Collections.unmodifiableMap(trustAnchors);
	}
	
	
	/**
	 * Returns the configured entity statement retriever.
	 *
	 * @return The configured entity statement retriever.
	 */
	public EntityStatementRetriever getEntityStatementRetriever() {
		return statementRetriever;
	}
	
	
	/**
	 * Resolves the trust chains for the specified target.
	 *
	 * @param target The target. Must not be {@code null}.
	 *
	 * @return The resolved trust chains, containing at least one valid and
	 *         verified chain.
	 *
	 * @throws ResolveException If no trust chain could be resolved.
	 */
	public Set<TrustChain> resolveTrustChains(final EntityID target)
		throws ResolveException {
		
		if (trustAnchors.get(target) != null) {
			throw new ResolveException("Target is trust anchor");
		}
		
		TrustChainRetriever retriever = new DefaultTrustChainRetriever(statementRetriever);
		
		Set<TrustChain> fetchedTrustChains = retriever.fetch(target, trustAnchors.keySet());
		
		if (fetchedTrustChains.isEmpty()) {
		
			if (retriever.getAccumulatedExceptions().isEmpty()) {
				throw new ResolveException("No trust chain leading up to a trust anchor");
			} else if (retriever.getAccumulatedExceptions().size() == 1){
				Throwable cause = retriever.getAccumulatedExceptions().get(0);
				throw new ResolveException("Couldn't resolve trust chain: " + cause.getMessage(), cause);
			} else {
				throw new ResolveException("Couldn't resolve trust chain due to multiple causes", retriever.getAccumulatedExceptions());
			}
		}
		
		List<Throwable> verificationExceptions = new LinkedList<>();
		
		Set<TrustChain> verifiedTrustChains = new HashSet<>();
		
		for (TrustChain chain: fetchedTrustChains) {
			
			EntityID anchor = chain.getTrustAnchorEntityID();
			JWKSet anchorJWKSet = trustAnchors.get(anchor);
			if (anchorJWKSet == null) {
				continue;
			}
			
			try {
				chain.verifySignatures(anchorJWKSet);
			} catch (BadJOSEException | JOSEException e) {
				verificationExceptions.add(e);
				continue;
			}
			
			verifiedTrustChains.add(chain);
		}
		
		if (verifiedTrustChains.isEmpty()) {
			
			List<Throwable> accumulatedExceptions = new LinkedList<>(retriever.getAccumulatedExceptions());
			accumulatedExceptions.addAll(verificationExceptions);
			
			if (verificationExceptions.size() == 1) {
				Throwable cause = verificationExceptions.get(0);
				throw new ResolveException("Couldn't resolve trust chain: " + cause.getMessage(), accumulatedExceptions);
			} else {
				throw new ResolveException("Couldn't resolve trust chain due to multiple causes", accumulatedExceptions);
			}
		}
		
		return verifiedTrustChains;
	}
}
