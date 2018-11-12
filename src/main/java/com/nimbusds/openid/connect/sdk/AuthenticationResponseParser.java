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


import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.jarm.JARMUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Parser of OpenID Connect authentication response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.2.5. and 3.1.2.6.
 *     <li>OAuth 2.0 (RFC 6749), section 3.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM).
 * </ul>
 */
public class AuthenticationResponseParser {


	/**
	 * Parses an OpenID Connect authentication response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication response.
	 */
	public static AuthenticationResponse parse(final URI redirectURI,
						   final Map<String,List<String>> params)
		throws ParseException {
		
		if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "error"))) {
			return AuthenticationErrorResponse.parse(redirectURI, params);
		} else if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "response"))) {
			// JARM, peek into JWT if signed only
			JWT jwt;
			try {
				jwt = JWTParser.parse(MultivaluedMapUtils.getFirstValue(params, "response"));
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid JWT-encoded authorization response: " + e.getMessage(), e);
			}
			
			boolean likelyError = JARMUtils.impliesAuthorizationErrorResponse(jwt);
			
			if (likelyError) {
				return AuthenticationErrorResponse.parse(redirectURI, params);
			} else {
				return AuthenticationSuccessResponse.parse(redirectURI, params);
			}
			
		} else {
			return AuthenticationSuccessResponse.parse(redirectURI, params);
		}
	}


	/**
	 * Parses an OpenID Connect authentication response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("https:///?code=Qcb0Orv1...&amp;state=af0ifjsldkj");
	 * </pre>
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authentication
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the redirection URI couldn't be parsed to
	 *                        an OpenID Connect authentication response.
	 */
	public static AuthenticationResponse parse(final URI uri)
		throws ParseException {

		String paramString;
		
		if (uri.getRawQuery() != null) {

			paramString = uri.getRawQuery();

		} else if (uri.getRawFragment() != null) {

			paramString = uri.getRawFragment();

		} else {

			throw new ParseException("Missing authorization response parameters");
		}
		
		Map<String,List<String>> params = URLUtils.parseParameters(paramString);

		if (params == null)
			throw new ParseException("Missing or invalid authorization response parameters");

		return parse(URIUtils.getBaseURI(uri), params);
	}
	
	
	/**
	 * Parses an OpenID Connect authentication response from the specified
	 * initial HTTP 302 redirect response output at the authorisation
	 * endpoint.
	 *
	 * <p>Example HTTP response (authorisation success):
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param httpResponse The HTTP response to parse. Must not be
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect authentication response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect authentication response.
	 */
	public static AuthenticationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		URI location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirection URI / HTTP Location header");

		return parse(location);
	}
	
	
	/**
	 * Parses an OpenID Connect authentication response from the specified
	 * HTTP request at the client redirection (callback) URI. Applies to
	 * the {@code query}, {@code fragment} and {@code form_post} response
	 * modes.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #parse(HTTPResponse)
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authentication response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        OpenID Connect authentication response.
	 */
	public static AuthenticationResponse parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		final URI baseURI;
		
		try {
			baseURI = httpRequest.getURL().toURI();
			
		} catch (URISyntaxException e) {
			throw new ParseException(e.getMessage(), e);
		}
		
		if (httpRequest.getQuery() != null) {
			// For query string and form_post response mode
			return parse(baseURI, URLUtils.parseParameters(httpRequest.getQuery()));
		} else if (httpRequest.getFragment() != null) {
			// For fragment response mode (never available in actual HTTP request from browser)
			return parse(baseURI, URLUtils.parseParameters(httpRequest.getFragment()));
		} else {
			throw new ParseException("Missing URI fragment, query string or post body");
		}
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private AuthenticationResponseParser() { }
}
