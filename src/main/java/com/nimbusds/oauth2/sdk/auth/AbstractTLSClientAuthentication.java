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
import javax.mail.internet.ContentType;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * The base abstract class for mutual TLS client authentication at the Token
 * endpoint.
 */
abstract class AbstractTLSClientAuthentication extends ClientAuthentication {
	
	
	/**
	 * The SSL socket factory for an outgoing HTTPS request, {@code null}
	 * to use the default one.
	 */
	private final SSLSocketFactory sslSocketFactory;
	
	
	/**
	 * Creates a new abstract mutual TLS client authentication. This
	 * constructor is intended for an outgoing token request.
	 *
	 * @param method           The client authentication method. Must not
	 *                         be {@code null}.
	 * @param clientID         The client identifier. Must not be
	 *                         {@code null}.
	 * @param sslSocketFactory The SSL socket factory to use for the
	 *                         outgoing HTTPS request and to present the
	 *                         client certificate(s), {@code null} to use
	 *                         the default one.
	 */
	protected AbstractTLSClientAuthentication(final ClientAuthenticationMethod method,
						  final ClientID clientID,
						  final SSLSocketFactory sslSocketFactory) {
		
		super(method, clientID);
		this.sslSocketFactory = sslSocketFactory;
	}
	
	
	/**
	 * Creates a new abstract mutual TLS client authentication. This
	 * constructor is intended for a received token request.
	 *
	 * @param method   The client authentication method. Must not be
	 *                 {@code null}.
	 * @param clientID The client identifier. Must not be {@code null}.
	 */
	protected AbstractTLSClientAuthentication(final ClientAuthenticationMethod method,
						  final ClientID clientID) {
		super(method, clientID);
		sslSocketFactory = null;
	}
	
	
	/**
	 * Returns the SSL socket factory to use for an outgoing HTTPS request
	 * and to present the client certificate(s).
	 *
	 * @return The SSL socket factory, {@code null} to use the default one.
	 */
	public SSLSocketFactory getSSLSocketFactory() {
		
		return sslSocketFactory;
	}
	
	
	@Override
	public void applyTo(final HTTPRequest httpRequest) {
		
		if (httpRequest.getMethod() != HTTPRequest.Method.POST)
			throw new SerializeException("The HTTP request method must be POST");
		
		ContentType ct = httpRequest.getContentType();
		
		if (ct == null)
			throw new SerializeException("Missing HTTP Content-Type header");
		
		if (! ct.match(CommonContentTypes.APPLICATION_URLENCODED))
			throw new SerializeException("The HTTP Content-Type header must be " + CommonContentTypes.APPLICATION_URLENCODED);
		
		Map<String,String> params = httpRequest.getQueryParameters();
		
		params.put("client_id", getClientID().getValue());
		
		String queryString = URLUtils.serializeParameters(params);
		
		httpRequest.setQuery(queryString);
		
		// If set for an outgoing request
		httpRequest.setSSLSocketFactory(sslSocketFactory);
	}
}
