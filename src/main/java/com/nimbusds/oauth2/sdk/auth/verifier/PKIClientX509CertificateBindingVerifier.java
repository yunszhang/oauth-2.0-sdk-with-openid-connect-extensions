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

package com.nimbusds.oauth2.sdk.auth.verifier;


import java.security.cert.X509Certificate;

import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Client X.509 certificate binding verifier. Intended for verifying that a
 * client X.509 certificate submitted during successful PKI mutual TLS
 * authentication (in
 * {@link com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod#TLS_CLIENT_AUTH
 * tls_client_auth}) matches one of the registered values for the client.
 * These can be: {@code tls_client_auth_subject_dn},
 * {@code tls_client_auth_san_dns},
 * {@code tls_client_auth_san_uri},
 * {@code tls_client_auth_san_ip} or
 * {@code tls_client_auth_san_email}.
 *
 * <p>Implementations must be tread-safe.
 */
public interface PKIClientX509CertificateBindingVerifier<T> {
	
	
	/**
	 * Verifies that the specified X.509 certificate binds to
	 * the claimed client ID.
	 *
	 * @param clientID    The claimed client ID. Not {@code null}.
	 * @param certificate The X.509 certificate. Not {@code null}.
	 * @param context     Additional context. May be {@code null}.
	 *
	 * @throws InvalidClientException If client ID and certificate don't
	 *                                bind or are invalid.
	 */
	void verifyCertificateBinding(final ClientID clientID,
				      final X509Certificate certificate,
				      final Context<T> context)
		throws InvalidClientException;
}
