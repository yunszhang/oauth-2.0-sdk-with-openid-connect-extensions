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


import java.net.URI;
import java.util.*;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


/**
 * The default trust chain retriever.
 */
class DefaultTrustChainRetriever implements TrustChainRetriever {
	
	
	private final EntityStatementRetriever retriever;
	
	
	private final List<Exception> accumulatedExceptions = new LinkedList<>();
	
	
	/**
	 * Creates a new trust chain retriever.
	 *
	 * @param retriever The entity statement retriever. Must not be
	 *                  {@code null}.
	 */
	DefaultTrustChainRetriever(final EntityStatementRetriever retriever) {
		if (retriever == null) {
			throw new IllegalArgumentException("The entity statement retriever must not be null");
		}
		this.retriever = retriever;
	}
	
	
	@Override
	public Set<TrustChain> fetch(final EntityID target, final Set<EntityID> trustAnchors) {
		
		if (CollectionUtils.isEmpty(trustAnchors)) {
			throw new IllegalArgumentException("The trust anchors must not be empty");
		}
		
		accumulatedExceptions.clear();
		
		EntityStatement targetStatement;
		try {
			targetStatement = retriever.fetchSelfIssuedEntityStatement(target);
		} catch (ResolveException e) {
			accumulatedExceptions.add(e);
			return Collections.emptySet();
		}
		
		List<EntityID> authorityHints = targetStatement.getClaimsSet().getAuthorityHints();
		
		if (CollectionUtils.isEmpty(authorityHints)) {
			// Dead end
			accumulatedExceptions.add(new ResolveException("Entity " + target + " has no authorities listed (authority_hints)"));
			return Collections.emptySet();
		}
		
		EntityID subject;
		try {
			subject = EntityID.parse(targetStatement.getClaimsSet().getSubject());
		} catch (ParseException e) {
			accumulatedExceptions.add(new ResolveException("Entity " + target + " subject is illegal: " + e.getMessage(), e));
			return Collections.emptySet();
		}
		
		Set<List<EntityStatement>> anchoredChains = fetchStatementsFromSuperiors(subject, trustAnchors, authorityHints, Collections.<EntityStatement>emptyList());
		
		Set<TrustChain> trustChains = new HashSet<>();
		
		for (List<EntityStatement> chain: anchoredChains) {
			trustChains.add(new TrustChain(targetStatement, chain));
		}
		
		return trustChains;
	}
	
	
	private Set<List<EntityStatement>> fetchStatementsFromSuperiors(final EntityID subject,
									final Set<EntityID> trustAnchors,
									final List<EntityID> authorityHints,
									final List<EntityStatement> partialChain) {
		
		// Number of updated chains equals number of authority_hints
		Set<List<EntityStatement>> updatedChains = new HashSet<>();
		
		for (EntityID superior: authorityHints) {
			
			if (superior == null) {
				continue; // skip
			}
			
			URI federationAPIURI;
			try {
				federationAPIURI = retriever.resolveFederationAPIURI(superior);
			} catch (ResolveException e) {
				accumulatedExceptions.add(new ResolveException("Couldn't resolve federation API URI for " + superior + ": " + e.getMessage(), e));
				continue;
				
			}
			if (federationAPIURI == null) {
				accumulatedExceptions.add(new ResolveException("No federation API URI for " + superior));
				continue;
			}
			
			EntityStatement entityStatement;
			try {
				entityStatement = retriever.fetchEntityStatement(
					federationAPIURI,
					superior,
					subject);
			} catch (ResolveException e) {
				accumulatedExceptions.add(new ResolveException("Couldn't fetch entity statement from " + federationAPIURI + ": " + e.getMessage(), e));
				continue;
			}
			
			List<EntityStatement> updatedChain = new LinkedList<>(partialChain);
			updatedChain.add(entityStatement);
			updatedChains.add(Collections.unmodifiableList(updatedChain));
		}
		
		// Find out which chains are now anchored and which still partial
		Set<List<EntityStatement>> anchoredChains = new LinkedHashSet<>();
		Set<List<EntityStatement>> remainingPartialChains = new LinkedHashSet<>();
		
		for (List<EntityStatement> chain: updatedChains) {
			EntityStatement last = chain.get(chain.size() - 1);
			if (trustAnchors.contains(last.getClaimsSet().getIssuerEntityID())) {
				// Reached statement from trust anchor about leaf or intermediate
				anchoredChains.add(chain);
			} else if (CollectionUtils.isEmpty(last.getClaimsSet().getAuthorityHints())) {
				// Reached unknown trust anchor
				continue;
			} else {
				// More statements remain
				remainingPartialChains.add(chain);
			}
		}
		
		for (List<EntityStatement> chain: remainingPartialChains) {
			
			EntityStatement last = chain.get(chain.size() - 1);
			
			// Recursion
			anchoredChains.addAll(fetchStatementsFromSuperiors(
				last.getClaimsSet().getSubjectEntityID(),
				trustAnchors,
				last.getClaimsSet().getAuthorityHints(),
				chain));
			
		}
		
		return anchoredChains;
	}
	
	
	@Override
	public List<Exception> getAccumulatedExceptions() {
		return accumulatedExceptions;
	}
}
