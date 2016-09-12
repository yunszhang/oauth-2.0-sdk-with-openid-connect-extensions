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


import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.Immutable;


/**
 * Immutable client secret.
 */
@Immutable
@Deprecated
public final class ImmutableClientSecret extends ImmutableJWKSet {


	/**
	 * Creates a new immutable client secret.
	 *
	 * @param id     The client identifier. Must not be {@code null}.
	 * @param secret The client secret. Must not be {@code null}.
	 */
	public ImmutableClientSecret(final ClientID id, final Secret secret) {

		this(id, new OctetSequenceKey.Builder(secret.getValueBytes()).build());
	}


	/**
	 * Creates a new immutable client secret.
	 *
	 * @param id     The client identifier. Must not be {@code null}.
	 * @param secret The client secret. Must not be {@code null}.
	 */
	public ImmutableClientSecret(final ClientID id, final OctetSequenceKey secret) {
		super(id, new JWKSet(secret));
	}


	/**
	 * Returns the client secret.
	 *
	 * @return The client secret.
	 */
	public OctetSequenceKey getClientSecret() {

		return (OctetSequenceKey) getJWKSet().getKeys().get(0);
	}


	@Override
	public List<JWK> get(final Identifier id, final JWKSelector jwkSelector) {
		// Owner not checked, we have a shared secret
		return jwkSelector.select(getJWKSet());
	}
}
