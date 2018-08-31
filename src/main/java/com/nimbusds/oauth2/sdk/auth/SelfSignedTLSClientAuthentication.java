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
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;


/**
 * Self-signed certificate mutual TLS client authentication at the Token
 * endpoint. The client certificate is self-signed, as opposed to
 * {@link TLSClientAuthentication tls_client_auth} which relies on PKI binding.
 * Implements {@link ClientAuthenticationMethod#SELF_SIGNED_TLS_CLIENT_AUTH}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-08), section 2.2.
 * </ul>
 */
@Immutable
public class SelfSignedTLSClientAuthentication extends AbstractTLSClientAuthentication {
	
	
	/**
	 * The validated client X.509 certificate from the received HTTPS
	 * request, {@code null} for an outgoing HTTPS request.
	 */
	private final X509Certificate x509Certificate;
	
	
	/**
	 * Creates a new self-signed certificate mutual TLS client
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
	public SelfSignedTLSClientAuthentication(final ClientID clientID,
						 final SSLSocketFactory sslSocketFactory) {
		
		super(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH, clientID, sslSocketFactory);
		x509Certificate = null;
	}
	
	
	/**
	 * Creates a new self-signed certificate mutual TLS client
	 * authentication. This constructor is intended for a received token
	 * request.
	 *
	 * @param clientID        The client identifier. Must not be
	 *                        {@code null}.
	 * @param x509Certificate The validated client X.509 certificate from
	 *                        the received HTTPS request. Must not be
	 *                        {@code null}.
	 */
	public SelfSignedTLSClientAuthentication(final ClientID clientID,
						 final X509Certificate x509Certificate) {
		
		super(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH, clientID);
		
		if (x509Certificate == null) {
			throw new IllegalArgumentException("The client X.509 certificate must not be null");
		}
		
		this.x509Certificate = x509Certificate;
	}
	
	
	/**
	 * Returns the validated client X.509 certificate from the received
	 * HTTPS request.
	 *
	 * @return The client X.509 certificate, {@code null} for an outgoing
	 *         HTTPS request.
	 */
	public X509Certificate getClientX509Certificate() {
		
		return x509Certificate;
	}
	
	
	/**
	 * Parses a self-signed certificate mutual TLS client authentication
	 * from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null} and must include a validated client
	 *                    X.509 certificate.
	 *
	 * @return The self-signed TLS / X.509 certificate client
	 *         authentication.
	 *
	 * @throws ParseException If the {@code client_id} or client X.509
	 *                        certificate is missing.
	 */
	public static SelfSignedTLSClientAuthentication parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		String query = httpRequest.getQuery();
		
		if (query == null) {
			throw new ParseException("Missing HTTP POST request entity body");
		}
		
		Map<String,List<String>> params = URLUtils.parseParameters(query);
		
		String clientIDString = URLUtils.getFirstValue(params, "client_id");
		
		if (StringUtils.isBlank(clientIDString)) {
			throw new ParseException("Missing client_id parameter");
		}
		
		X509Certificate cert = httpRequest.getClientX509Certificate();
		
		if (cert == null) {
			throw new ParseException("Missing client X.509 certificate");
		}
		
		return new SelfSignedTLSClientAuthentication(new ClientID(clientIDString), cert);
	}
}
