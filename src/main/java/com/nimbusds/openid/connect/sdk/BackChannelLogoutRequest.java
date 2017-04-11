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

package com.nimbusds.openid.connect.sdk;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;


/**
 * Back-channel logout request initiated by an OpenID provider (OP).
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /backchannel_logout HTTP/1.1
 * Host: rp.example.org
 * Content-Type: application/x-www-form-urlencoded
 *
 * logout_token=eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.5 (draft 04).
 * </ul>
 */
@Immutable
public class BackChannelLogoutRequest extends AbstractRequest {
	
	
	/**
	 * The logout token.
	 */
	private final JWT logoutToken;
	
	
	/**
	 * Creates a new back-channel logout request.
	 *
	 * @param uri         The back-channel logout URI. May be {@code null}
	 *                    if the {@link #toHTTPRequest} method will not be
	 *                    used.
	 * @param logoutToken The logout token. Must be signed, or signed and
	 *                    encrypted. Must not be {@code null}.
	 */
	public BackChannelLogoutRequest(final URI uri,
					final JWT logoutToken) {
		
		super(uri);
		
		if (logoutToken == null) {
			throw new IllegalArgumentException("The logout token must not be null");
		}
		
		if (logoutToken instanceof PlainJWT) {
			throw new IllegalArgumentException("The logout token must not be unsecured (plain)");
		}
		
		this.logoutToken = logoutToken;
	}
	
	
	/**
	 * Returns the logout token.
	 *
	 * @return The logout token.
	 */
	public JWT getLogoutToken() {
		
		return logoutToken;
	}
	
	
	/**
	 * Returns the parameters for this back-channel logout request.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * logout_token=eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
	 * </pre>
	 *
	 * @return The parameters.
	 */
	public Map<String,String> toParameters() {
		
		Map <String,String> params = new LinkedHashMap<>();
		
		try {
			params.put("logout_token", logoutToken.serialize());
		} catch (IllegalStateException e) {
			throw new SerializeException("Couldn't serialize logout token: " + e.getMessage(), e);
		}
		
		return params;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");
		
		HTTPRequest httpRequest;
		
		URL endpointURL;
		
		try {
			endpointURL = getEndpointURI().toURL();
			
		} catch (MalformedURLException e) {
			
			throw new SerializeException(e.getMessage(), e);
		}
		
		httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpointURL);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(toParameters()));
		
		return httpRequest;
	}
	
	
	/**
	 * Parses a back-channel logout request from the specified parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * logout_token = eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
	 * </pre>
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The back-channel logout request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to a
	 *                        back-channel logout request.
	 */
	public static BackChannelLogoutRequest parse(final Map<String,String> params)
		throws ParseException {
		
		return parse(null, params);
	}
	
	
	/**
	 * Parses a back-channel logout request from the specified parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * logout_token = eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
	 * </pre>
	 *
	 * @param uri    The back-channel logout URI. May be {@code null} if
	 *               the {@link #toHTTPRequest()} method will not be used.
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The back-channel logout request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to a
	 *                        back-channel logout request.
	 */
	public static BackChannelLogoutRequest parse(final URI uri, Map<String,String> params)
		throws ParseException {
		
		String logoutTokenString = params.get("logout_token");
		
		if (logoutTokenString == null) {
			throw new ParseException("Missing logout_token parameter");
		}
		
		JWT logoutToken;
		
		try {
			logoutToken = JWTParser.parse(logoutTokenString);
		} catch (java.text.ParseException e) {
			throw new ParseException("Invalid logout token: " + e.getMessage(), e);
		}
		
		try {
			return new BackChannelLogoutRequest(uri, logoutToken);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Parses a back-channel logout request from the specified HTTP request.
	 *
	 * <p>Example HTTP request (POST):
	 *
	 * <pre>
	 * POST /backchannel_logout HTTP/1.1
	 * Host: rp.example.org
	 * Content-Type: application/x-www-form-urlencoded
	 *
	 * logout_token=eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The back-channel logout request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        back-channel logout request.
	 */
	public static BackChannelLogoutRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		if (! HTTPRequest.Method.POST.equals(httpRequest.getMethod())) {
			throw new ParseException("HTTP POST required");
		}
		
		// Lenient on content-type
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing URI query string");
		
		Map<String,String> params = URLUtils.parseParameters(query);
		
		try {
			return parse(URIUtils.getBaseURI(httpRequest.getURL().toURI()), params);
			
		} catch (URISyntaxException e) {
			
			throw new ParseException(e.getMessage(), e);
		}
	}
}
