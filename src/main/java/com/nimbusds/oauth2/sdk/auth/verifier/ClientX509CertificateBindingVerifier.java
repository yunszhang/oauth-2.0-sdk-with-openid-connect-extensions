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


import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Client X.509 certificate binding verifier. Intended for verifying that the
 * subject and root issuer of a client X.509 certificate submitted during
 * successful mutual TLS authentication (in
 * {@link com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod#TLS_CLIENT_AUTH
 * tls_client_auth}) match the registered {@code tls_client_auth_subject_dn}
 * and {@code tls_client_auth_root_dn} values for the submitted client ID.
 *
 * <p>Implementations must be tread-safe.
 */
public interface ClientX509CertificateBindingVerifier {
	
	
	/**
	 * Verifies that the specified X.509 certificate issuer DN and subject
	 * DN bind to the claimed client ID.
	 *
	 * @param clientID  The claimed client ID. Not {@code null}.
	 * @param subjectDN The X.509 certificate subject DN. Not {@code null}.
	 * @param rootDN    The X.509 certificate root DN, {@code null} if not
	 *                  available.
	 *
	 * @throws InvalidClientException If client ID and issuer / subject DN
	 *                                tuple don't bind or are invalid.
	 */
	void verifyCertificateBinding(final ClientID clientID,
				      final String subjectDN,
				      final String rootDN)
		throws InvalidClientException;
}
