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

package com.nimbusds.oauth2.sdk;


import java.net.URI;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;


/**
 * Abstract request with client authentication.
 *
 * <p>Client authentication methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretBasic client_secret_basic}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretPost client_secret_post}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretJWT client_secret_jwt}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT private_key_jwt}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication self_signed_tls_client_auth}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.PKITLSClientAuthentication tls_client_auth}
 * </ul>
 */
public abstract class AbstractAuthenticatedRequest extends AbstractRequest {
	

	/**
	 * The client authentication.
	 */
	private final ClientAuthentication clientAuth;


	/**
	 * Creates a new abstract request with client authentication.
	 *
	 * @param uri        The URI of the endpoint (HTTP or HTTPS) for which
	 *                   the request is intended, {@code null} if not
	 *                   specified (if, for example, the
	 *                   {@link #toHTTPRequest()} method will not be used).
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 */
	public AbstractAuthenticatedRequest(final URI uri,
					    final ClientAuthentication clientAuth) {

		super(uri);

		if (clientAuth == null) {
			throw new IllegalArgumentException("The client authentication must not be null");
		}
		
		this.clientAuth = clientAuth;
	}


	/**
	 * Returns the client authentication.
	 *
	 * @return The client authentication.
	 */
	public ClientAuthentication getClientAuthentication() {

		return clientAuth;
	}
}
