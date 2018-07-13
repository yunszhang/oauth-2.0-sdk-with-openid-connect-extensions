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
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;


/**
 * OpenID Connect authentication error response. Intended only for errors which
 * are allowed to be communicated back to the requesting OAuth 2.0 client, such
 * as {@code access_denied}. For a complete list see OAuth 2.0 (RFC 6749),
 * sections 4.1.2.1 and 4.2.2.1, OpenID Connect Core 1.0 section 3.1.2.6.
 *
 * <p>If the authorisation request fails due to a missing, invalid, or
 * mismatching {@code redirect_uri}, or if the {@code client_id} is missing or
 * invalid, a response <strong>must not</strong> be sent back to the requesting
 * client. Instead, the OpenID provider should simply display the error to the
 * end-user.
 *
 * <p>Standard errors:
 *
 * <ul>
 *     <li>OAuth 2.0 authorisation errors:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_REQUEST}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#UNAUTHORIZED_CLIENT}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#ACCESS_DENIED}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#UNSUPPORTED_RESPONSE_TYPE}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_SCOPE}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#SERVER_ERROR}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#TEMPORARILY_UNAVAILABLE}
 *         </ul>
 *     <li>OpenID Connect specific errors:
 *         <ul>
 *             <li>{@link OIDCError#INTERACTION_REQUIRED}
 *             <li>{@link OIDCError#LOGIN_REQUIRED}
 *             <li>{@link OIDCError#ACCOUNT_SELECTION_REQUIRED}
 *             <li>{@link OIDCError#CONSENT_REQUIRED}
 *             <li>{@link OIDCError#INVALID_REQUEST_URI}
 *             <li>{@link OIDCError#INVALID_REQUEST_OBJECT}
 *             <li>{@link OIDCError#REGISTRATION_NOT_SUPPORTED}
 *             <li>{@link OIDCError#REQUEST_NOT_SUPPORTED}
 *             <li>{@link OIDCError#REQUEST_URI_NOT_SUPPORTED}
 *         </ul>
 *     </li>
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.org/cb?
 *           error=invalid_request
 *           &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
 *           &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.2.6.
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.2.1 and 4.2.2.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 * </ul>
 */
@Immutable
public class AuthenticationErrorResponse
	extends AuthorizationErrorResponse
	implements AuthenticationResponse {


	/**
	 * The standard errors for an OpenID Connect authentication error
	 * response.
	 */
	private static final Set<ErrorObject> stdErrors = new HashSet<>();
	
	
	static {
		stdErrors.addAll(AuthorizationErrorResponse.getStandardErrors());

		stdErrors.add(OIDCError.INTERACTION_REQUIRED);
		stdErrors.add(OIDCError.LOGIN_REQUIRED);
		stdErrors.add(OIDCError.ACCOUNT_SELECTION_REQUIRED);
		stdErrors.add(OIDCError.CONSENT_REQUIRED);
		stdErrors.add(OIDCError.INVALID_REQUEST_URI);
		stdErrors.add(OIDCError.INVALID_REQUEST_OBJECT);
		stdErrors.add(OIDCError.REGISTRATION_NOT_SUPPORTED);
		stdErrors.add(OIDCError.REQUEST_NOT_SUPPORTED);
		stdErrors.add(OIDCError.REQUEST_URI_NOT_SUPPORTED);
	}


	/**
	 * Gets the standard errors for an OpenID Connect authentication error
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {
	
		return Collections.unmodifiableSet(stdErrors);
	}


	/**
	 * Creates a new OpenID Connect authentication error response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param error       The error. Should match one of the 
	 *                    {@link #getStandardErrors standard errors} for an 
	 *                    OpenID Connect authentication error response.
	 *                    Must not be {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 * @param rm          The implied response mode, {@code null} if
	 *                    unknown.
	 */
	public AuthenticationErrorResponse(final URI redirectURI,
					   final ErrorObject error,
					   final State state,
					   final ResponseMode rm) {
					  
		super(redirectURI, error, state, rm);
	}
	
	
	@Override
	public AuthenticationSuccessResponse toSuccessResponse() {
		throw new ClassCastException("Cannot cast to AuthenticationSuccessResponse");
	}
	
	
	@Override
	public AuthenticationErrorResponse toErrorResponse() {
		return this;
	}
	
	
	/**
	 * Parses an OpenID Connect authentication error response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authentication error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication error response.
	 */
	public static AuthenticationErrorResponse parse(final URI redirectURI,
							final Map<String,String> params)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(redirectURI, params);

		return new AuthenticationErrorResponse(
			resp.getRedirectionURI(),
			resp.getErrorObject(),
			resp.getState(),
			null);
	}


	/**
	 * Parses an OpenID Connect authentication error response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("https:///?error=invalid_request");
	 * </pre>
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?
	 * error=invalid_request
	 * &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication error response.
	 *
	 * @throws ParseException If the URI couldn't be parsed to an OpenID
	 *                        Connect authentication error response.
	 */
	public static AuthenticationErrorResponse parse(final URI uri)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(uri);

		return new AuthenticationErrorResponse(
			resp.getRedirectionURI(),
			resp.getErrorObject(),
			resp.getState(),
			null);
	}


	/**
	 * Parses an OpenID Connect authentication error response from the
	 * specified initial HTTP 302 redirect response generated at the
	 * authorisation endpoint.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?error=invalid_request&amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect authentication error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect authentication error response.
	 */
	public static AuthenticationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(httpResponse);

		return new AuthenticationErrorResponse(
			resp.getRedirectionURI(),
			resp.getErrorObject(),
			resp.getState(),
			null);
	}


	/**
	 * Parses an OpenID Connect authentication error response from the
	 * specified HTTP request at the client redirection (callback) URI.
	 * Applies to {@code query}, {@code fragment} and {@code form_post}
	 * response modes.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?error=invalid_request&amp;state=af0ifjsldkj HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #parse(HTTPResponse)
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null}.
	 *
	 * @return The authentication error response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        OpenID Connect authentication error response.
	 */
	public static AuthenticationErrorResponse parse(final HTTPRequest httpRequest)
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
}
