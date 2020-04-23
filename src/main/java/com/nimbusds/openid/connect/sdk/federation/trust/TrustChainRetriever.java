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
import java.util.Set;

import net.jcip.annotations.NotThreadSafe;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Single use trust chain retriever. Implementations are not considered
 * thread-safe.
 */
@NotThreadSafe
interface TrustChainRetriever {
	
	
	/**
	 * Fetches the trust chains for the specified target entity.
	 *
	 * @param target       The target entity ID. Must not be {@code null}.
	 * @param trustAnchors The trust anchors. Must contain at least one
	 *                     trust anchor.
	 *
	 * @return The successfully fetched trust chains, empty set if none.
	 */
	Set<TrustChain> fetch(final EntityID target, final Set<EntityID> trustAnchors);
	
	
	/**
	 * Returns the accumulated exceptions during the last fetch.
	 *
	 * @return The accumulated exceptions, empty list if none.
	 */
	List<Exception> getAccumulatedExceptions();
}
