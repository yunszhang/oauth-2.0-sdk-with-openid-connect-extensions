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
 *  Abstract JSON Web Key (JWK) selector with source.
 */
@ThreadSafe
@Deprecated
abstract class AbstractJWKSelectorWithSource extends AbstractJWKSelector {
	

	/**
	 * The JWK source.
	 */
	private final JWKSource jwkSource;


	/**
	 * Creates a new abstract JWK selector with a source.
	 *
	 * @param id        Identifier for the JWK selector. Must not be
	 *                  {@code null}.
	 * @param jwkSource The JWK source. Must not be {@code null}.
	 */
	public AbstractJWKSelectorWithSource(final Identifier id, final JWKSource jwkSource) {
		super(id);
		if (jwkSource == null) {
			throw new IllegalArgumentException("The JWK source must not be null");
		}
		this.jwkSource = jwkSource;
	}


	/**
	 * Returns the JWK source.
	 *
	 * @return The JWK source.
	 */
	public JWKSource getJWKSource() {
		return jwkSource;
	}
}
