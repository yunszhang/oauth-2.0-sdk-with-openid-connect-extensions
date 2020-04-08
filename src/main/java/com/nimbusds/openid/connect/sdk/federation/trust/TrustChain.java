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


import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


/**
 * Federation entity trust chain.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 2.2.
 * </ul>
 */
@Immutable
public final class TrustChain {
	
	
	/**
	 * The leaf entity self-statement.
	 */
	private final EntityStatement leaf;
	
	
	/**
	 * The superior entity statements.
	 */
	private final List<EntityStatement> superiors;
	
	
	/**
	 * Caches the resolved expiration time for this trust chain.
	 */
	private Date exp;
	
	
	/**
	 * Creates a new federation entity trust chain. Validates the subject -
	 * issuer chain, the signatures are not verified.
	 *
	 * @param leaf      The leaf entity self-statement. Must not be
	 *                  {@code null}.
	 * @param superiors The superior entity statements, starting with a
	 *                  statement of the first superior about the leaf,
	 *                  ending with the statement of the trust anchor about
	 *                  the last intermediate or the leaf (for a minimal
	 *                  trust chain). Must contain at least one entity
	 *                  statement.
	 *
	 * @throws IllegalArgumentException If the subject - issuer chain is
	 *                                  broken.
	 */
	public TrustChain(final EntityStatement leaf, List<EntityStatement> superiors) {
		if (leaf == null) {
			throw new IllegalArgumentException("The leaf statement must not be null");
		}
		this.leaf = leaf;
		
		if (CollectionUtils.isEmpty(superiors)) {
			throw new IllegalArgumentException("There must be at least one superior statement (issued by the trust anchor)");
		}
		this.superiors = superiors;
		if (! hasValidIssuerSubjectChain(leaf, superiors)) {
			throw new IllegalArgumentException("Broken subject - issuer chain");
		}
	}
	
	
	private static boolean hasValidIssuerSubjectChain(final EntityStatement leaf, final List<EntityStatement> superiors) {
		
		Subject nextExpectedSubject = leaf.getClaimsSet().getSubject();
		
		for (EntityStatement superiorStmt : superiors) {
			if (! nextExpectedSubject.equals(superiorStmt.getClaimsSet().getSubject())) {
				return false;
			}
			nextExpectedSubject = new Subject(superiorStmt.getClaimsSet().getIssuer().getValue());
		}
		return true;
	}
	
	
	/**
	 * Returns the leaf entity self-statement.
	 *
	 * @return The leaf entity self-statement.
	 */
	public EntityStatement getLeafStatement() {
		return leaf;
	}
	
	
	/**
	 * Returns the superior entity statements.
	 *
	 * @return The superior entity statements, starting with a statement of
	 *         the first superior about the leaf, ending with the statement
	 *         of the trust anchor about the last intermediate or the leaf
	 *         (for a minimal trust chain).
	 */
	public List<EntityStatement> getSuperiorStatements() {
		return superiors;
	}
	
	
	/**
	 * Returns the entity ID of the trust anchor.
	 *
	 * @return The entity ID of the trust anchor.
	 */
	public EntityID getTrustAnchorEntityID() {
		
		// Return last in superiors
		return getSuperiorStatements()
			.get(getSuperiorStatements().size() - 1)
			.getClaimsSet()
			.getIssuerEntityID();
	}
	
	
	/**
	 * Return an iterator starting from the leaf entity statement.
	 *
	 * @return The iterator.
	 */
	public Iterator<EntityStatement> iteratorFromLeaf() {
		
		// Init
		final AtomicReference<EntityStatement> next = new AtomicReference<>(getLeafStatement());
		final Iterator<EntityStatement> superiorsIterator = getSuperiorStatements().iterator();
		
		return new Iterator<EntityStatement>() {
			@Override
			public boolean hasNext() {
				return next.get() != null;
			}
			
			
			@Override
			public EntityStatement next() {
				EntityStatement toReturn = next.get();
				if (toReturn == null) {
					return null; // reached end on last iteration
				}
				
				// Set statement to return on next iteration
				if (toReturn.equals(getLeafStatement())) {
					// Return first superior
					next.set(superiorsIterator.next());
				} else {
					// Return next superior or end
					if (superiorsIterator.hasNext()) {
						next.set(superiorsIterator.next());
					} else {
						next.set(null);
					}
				}
				
				return toReturn;
			}
			
			
			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}
	
	
	/**
	 * Resolves the expiration time for this trust chain. Equals the
	 * nearest expiration when all entity statements in the trust chain are
	 * considered.
	 *
	 * @return The expiration time for this trust chain.
	 */
	public Date resolveExpirationTime() {
		
		if (exp != null) {
			return exp;
		}
		
		Iterator<EntityStatement> it = iteratorFromLeaf();
		
		Date nearestExp = null;
		
		while (it.hasNext()) {
			
			Date stmtExp = it.next().getClaimsSet().getExpirationTime();
			
			if (nearestExp == null) {
				nearestExp = stmtExp; // on first iteration
			} else if (stmtExp.before(nearestExp)) {
				nearestExp = stmtExp; // replace nearest
			}
		}
		
		exp = nearestExp;
		return exp;
	}
}
