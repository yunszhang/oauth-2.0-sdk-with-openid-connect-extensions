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

package com.nimbusds.openid.connect.sdk.federation.trust.constraints;


import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Entity ID constraint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.3.
 *     <li>RFC 5280, section 4.2.1.10.
 * </ul>
 */
public abstract class EntityIDConstraint {
	
	
	/**
	 * Matches an entity ID with this constraint.
	 *
	 * @param entityID The entity ID to match. Must not be {@code null}.
	 *
	 * @return {@code true} if this constraint matches the specified entity
	 *         ID, else {@code false}.
	 */
	public abstract boolean matches(final EntityID entityID);
}
