/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.jose.jwk;


import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Abstract JSON Web Key (JWK) selector.
 */
@ThreadSafe
@Deprecated
public abstract class AbstractJWKSelector {


	/**
	 * Identifier for the JWK selector.
	 */
	private final Identifier id;


	/**
	 * Creates a new abstract JWK selector.
	 *
	 * @param id Identifier for the JWK selector. Must not be {@code null}.
	 */
	public AbstractJWKSelector(final Identifier id) {
		if (id == null) {
			throw new IllegalArgumentException("The identifier must not be null");
		}
		this.id = id;
	}


	/**
	 * Returns the the identifier for the JWK selector.
	 *
	 * @return The identifier.
	 */
	public Identifier getIdentifier() {
		return id;
	}
}
