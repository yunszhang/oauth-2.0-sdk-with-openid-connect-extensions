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


import java.util.Map;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;
import org.apache.commons.lang3.StringUtils;


/**
 * TLS / X.509 certificate client authentication at the Token endpoint. The
 * client certificate is PKI bound, as opposed to
 * {@link PublicKeyTLSClientAuthentication pub_key_tls_client_auth} which
 * relies on direct public key binding. Implements
 * {@link ClientAuthenticationMethod#TLS_CLIENT_AUTH}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Mutual TLS Profile for OAuth 2.0 (draft-ietf-oauth-mtls-03), section
 *         2.1.
 * </ul>
 */
@Immutable
public class TLSClientAuthentication extends AbstractTLSClientAuthentication {
	
	
	/**
	 * The client X.509 certificate subject DN.
	 */
	private final String certSubjectDN;
	
	
	/**
	 * The client X.509 certificate root DN, {@code null} if not specified.
	 */
	private final String certRootDN;
	
	
	/**
	 * Creates a new TLS / X.509 certificate client authentication. This
	 * constructor is intended for an outgoing token request.
	 *
	 * @param clientID         The client identifier. Must not be
	 *                         {@code null}.
	 * @param sslSocketFactory The SSL socket factory to use for the
	 *                         outgoing HTTPS request and to present the
	 *                         client certificate(s), {@code null} to use
	 *                         the default one.
	 */
	public TLSClientAuthentication(final ClientID clientID,
				       final SSLSocketFactory sslSocketFactory) {
		
		super(ClientAuthenticationMethod.TLS_CLIENT_AUTH, clientID, sslSocketFactory);
		certSubjectDN = null;
		certRootDN = null;
	}
	
	
	/**
	 * Creates a new TLS / X.509 certificate client authentication. This
	 * constructor is intended for a received token request.
	 *
	 * @param clientID      The client identifier. Must not be
	 *                      {@code null}.
	 * @param certSubjectDN The subject DN of the received validated client
	 *                      X.509 certificate. Must not be {@code null}.
	 * @param certRootDN    The root issuer DN of the received validated
	 *                      client X.509 certificate, {@code null} if not
	 *                      specified.
	 */
	public TLSClientAuthentication(final ClientID clientID,
				       final String certSubjectDN,
				       final String certRootDN) {
		
		super(ClientAuthenticationMethod.TLS_CLIENT_AUTH, clientID);
		
		if (certSubjectDN == null) {
			throw new IllegalArgumentException("The X.509 client certificate subject DN must not be null");
		}
		this.certSubjectDN = certSubjectDN;
		
		this.certRootDN = certRootDN;
	}
	
	
	/**
	 * Gets the subject DN of the received validated client X.509
	 * certificate.
	 *
	 * @return The subject DN.
	 */
	public String getClientX509CertificateSubjectDN() {
		
		return certSubjectDN;
	}
	
	
	/**
	 * Gets the root issuer DN of the received validated client X.509
	 * certificate.
	 *
	 * @return The root DN, {@code null} if not specified.
	 */
	public String getClientX509CertificateRootDN() {
		
		return certRootDN;
	}
	
	
	/**
	 * Parses a TLS / X.509 certificate client authentication from the
	 * specified HTTP request.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null} and must include a validated client
	 *                    X.509 certificate.
	 *
	 * @return The TLS / X.509 certificate client authentication.
	 *
	 * @throws ParseException If the {@code client_id} or client X.509
	 *                        certificate is missing.
	 */
	public static TLSClientAuthentication parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		String query = httpRequest.getQuery();
		
		if (query == null) {
			throw new ParseException("Missing HTTP POST request entity body");
		}
		
		Map<String,String> params = URLUtils.parseParameters(query);
		
		String clientIDString = params.get("client_id");
		
		if (StringUtils.isBlank(clientIDString)) {
			throw new ParseException("Missing client_id parameter");
		}
		
		if (httpRequest.getClientX509CertificateSubjectDN() == null) {
			throw new ParseException("Missing client X.509 certificate subject DN");
		}
		
		return new TLSClientAuthentication(
			new ClientID(clientIDString),
			httpRequest.getClientX509CertificateSubjectDN(),
			httpRequest.getClientX509CertificateRootDN());
	}
}
