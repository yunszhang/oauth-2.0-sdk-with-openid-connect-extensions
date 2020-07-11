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


import java.util.List;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.NotThreadSafe;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


/**
 * Single use trust chain retriever. Implementations are not considered
 * thread-safe.
 */
@NotThreadSafe
interface TrustChainRetriever {
	
	
	/**
	 * Fetches the trust chains for the specified target entity. Intended
	 * for use in automatic federation client registration.
	 *
	 * @param target       The target entity ID. Must not be {@code null}.
	 * @param trustAnchors The trust anchors. Must contain at least one
	 *                     trust anchor.
	 *
	 * @return The successfully fetched trust chains, empty set if none.
	 */
	TrustChainSet retrieve(final EntityID target, final Set<EntityID> trustAnchors);
	
	
	/**
	 * Fetches the trust chains for the specified target entity. Intended
	 * for use in explicit federation client registration.
	 *
	 * @param targetStatement The target entity statement. Must not be
	 *                        {@code null}.
	 * @param trustAnchors    The trust anchors. Must contain at least one
	 *                        trust anchor.
	 *
	 * @return The successfully fetched trust chains, empty set if none.
	 */
	TrustChainSet retrieve(final EntityStatement targetStatement, final Set<EntityID> trustAnchors);
	
	
	/**
	 * Returns the accumulated trust anchor JWK sets from self-issued
	 * entity statements during the last retrieve.
	 *
	 * @return The JWK set map, empty if none.
	 */
	Map<EntityID, JWKSet> getAccumulatedTrustAnchorJWKSets();
	
	
	/**
	 * Returns the accumulated exceptions during the last retrieval.
	 *
	 * @return The accumulated exceptions, empty list if none.
	 */
	List<Throwable> getAccumulatedExceptions();
}
