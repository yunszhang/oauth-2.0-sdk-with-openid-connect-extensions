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

package com.nimbusds.oauth2.sdk.auth;


import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import net.jcip.annotations.Immutable;


/**
 * Public key TLS / X.509 certificate client authentication at the Token
 * endpoint. The client certificate is public key bound and typically
 * self-signed, as opposed to {@link TLSClientAuthentication tls_client_auth}
 * which relies on PKI binding. Implements
 * {@link ClientAuthenticationMethod#PUB_KEY_TLS_CLIENT_AUTH}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Mutual TLS Profile for OAuth 2.0 (draft-ietf-oauth-mtls-03), section
 *         2.1.
 * </ul>
 */
@Immutable
public class PublicKeyTLSClientAuthentication extends AbstractTLSClientAuthentication {
	
	
	/**
	 * Creates a new public key TLS / X.509 certificate client
	 * authentication. This constructor is intended for an outgoing token
	 * request.
	 *
	 * @param clientID         The client identifier. Must not be
	 *                         {@code null}.
	 * @param sslSocketFactory The SSL socket factory to use for the
	 *                         outgoing HTTPS request and to present the
	 *                         client certificate(s), {@code null} to use
	 *                         the default one.
	 */
	public PublicKeyTLSClientAuthentication(final ClientID clientID,
						final SSLSocketFactory sslSocketFactory) {
		
		super(ClientAuthenticationMethod.PUB_KEY_TLS_CLIENT_AUTH, clientID, sslSocketFactory);
	}
	
	
	/**
	 * Creates a new public key TLS / X.509 certificate client
	 * authentication. This constructor is intended for a received token
	 * request.
	 *
	 * @param clientID        The client identifier. Must not be
	 *                        {@code null}.
	 * @param x509Certificate The validated client X.509 certificate from
	 *                        the received HTTPS request. Must not be
	 *                        {@code null}.
	 */
	public PublicKeyTLSClientAuthentication(final ClientID clientID,
						final X509Certificate x509Certificate) {
		
		super(ClientAuthenticationMethod.TLS_CLIENT_AUTH, clientID, x509Certificate);
	}
	
	
	/**
	 * Parses a public key TLS / X.509 certificate client authentication
	 * from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null} and must include a validated client
	 *                    X.509 certificate.
	 *
	 * @return The public key TLS / X.509 certificate client
	 *         authentication.
	 *
	 * @throws ParseException If the {@code client_id} or client X.509
	 *                        certificate is missing.
	 */
	public static PublicKeyTLSClientAuthentication parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		TLSClientAuthentication pkiClientAuth = TLSClientAuthentication.parse(httpRequest);
		
		return new PublicKeyTLSClientAuthentication(
			pkiClientAuth.getClientID(),
			pkiClientAuth.getClientX509Certificate());
	}
}
