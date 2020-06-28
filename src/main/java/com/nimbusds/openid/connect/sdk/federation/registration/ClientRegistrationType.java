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

package com.nimbusds.openid.connect.sdk.federation.registration;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * OpenID Connect Federation 1.0 client registration type.
 */
@Immutable
public final class ClientRegistrationType extends Identifier {
	
	
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Automatic federation. No negotiation between the RP and the OP is
	 * made regarding what features the client should use in future
	 * requests to the OP. The RP's published metadata filtered by the
	 * chosen trust chain's metadata policies defines the metadata that is
	 * to be used.
	 */
	public static final ClientRegistrationType AUTOMATIC = new ClientRegistrationType("automatic");
	
	
	/**
	 * Explicit federation. The RP will access the
	 * {@code federation_registration_endpoint}, which provides the
	 * metadata for the RP to use. The OP may return a metadata policy that
	 * adds restrictions over and above what the trust chain already has
	 * defined.
	 */
	public static final ClientRegistrationType EXPLICIT = new ClientRegistrationType("explicit");
	
	
	/**
	 * Creates a new federation type with the specified identifier value.
	 *
	 * @param value The identifier value. Must not be {@code null}.
	 */
	public ClientRegistrationType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof ClientRegistrationType &&
			this.toString().equals(object.toString());
	}
}
