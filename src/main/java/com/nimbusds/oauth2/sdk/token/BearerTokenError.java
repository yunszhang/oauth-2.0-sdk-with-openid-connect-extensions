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

package com.nimbusds.oauth2.sdk.token;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OAuth 2.0 bearer token error. Used to indicate that access to a resource 
 * protected by a Bearer access token is denied, due to the request or token 
 * being invalid, or due to the access token having insufficient scope.
 *
 * <p>Standard bearer access token errors:
 *
 * <ul>
 *     <li>{@link #MISSING_TOKEN}
 *     <li>{@link #INVALID_REQUEST}
 *     <li>{@link #INVALID_TOKEN}
 *     <li>{@link #INSUFFICIENT_SCOPE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: Bearer realm="example.com",
 *                   error="invalid_token",
 *                   error_description="The access token expired"
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 *     <li>Hypertext Transfer Protocol (HTTP/1.1): Authentication (RFC 7235),
 *         section 4.1.
 * </ul>
 */
@Immutable
public class BearerTokenError extends ErrorObject {


	/**
	 * The request does not contain an access token. No error code or
	 * description is specified for this error, just the HTTP status code
	 * is set to 401 (Unauthorized).
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * HTTP/1.1 401 Unauthorized
	 * WWW-Authenticate: Bearer
	 * </pre>
	 */
	public static final BearerTokenError MISSING_TOKEN =
		new BearerTokenError(null, null, HTTPResponse.SC_UNAUTHORIZED);

	/**
	 * The request is missing a required parameter, includes an unsupported
	 * parameter or parameter value, repeats the same parameter, uses more
	 * than one method for including an access token, or is otherwise 
	 * malformed. The HTTP status code is set to 400 (Bad Request).
	 */
	public static final BearerTokenError INVALID_REQUEST = 
		new BearerTokenError("invalid_request", "Invalid request", 
			             HTTPResponse.SC_BAD_REQUEST);


	/**
	 * The access token provided is expired, revoked, malformed, or invalid
	 * for other reasons.  The HTTP status code is set to 401 
	 * (Unauthorized).
	 */
	public static final BearerTokenError INVALID_TOKEN =
		new BearerTokenError("invalid_token", "Invalid access token", 
			             HTTPResponse.SC_UNAUTHORIZED);
	
	
	/**
	 * The request requires higher privileges than provided by the access 
	 * token. The HTTP status code is set to 403 (Forbidden).
	 */
	public static final BearerTokenError INSUFFICIENT_SCOPE =
		new BearerTokenError("insufficient_scope", "Insufficient scope", 
			             HTTPResponse.SC_FORBIDDEN);
	
	
	/**
	 * Returns {@code true} if the specified error code consists of valid
	 * characters. Values for the "error" and "error_description"
	 * attributes must not include characters outside the [0x20, 0x21] |
	 * [0x23 - 0x5B] | [0x5D - 0x7E] range. See RFC 6750, section 3.
	 *
	 * @see ErrorObject#isLegal(String)
	 *
	 * @param errorCode The error code string.
	 *
	 * @return {@code true} if the error code string contains valid
	 *         characters, else {@code false}.
	 */
	@Deprecated
	public static boolean isCodeWithValidChars(final String errorCode) {
		
		return ErrorObject.isLegal(errorCode);
	}
	
	
	/**
	 * Returns {@code true} if the specified error description consists of
	 * valid characters. Values for the "error" and "error_description"
	 * attributes must not include characters outside the [0x20, 0x21] |
	 * [0x23 - 0x5B] | [0x5D - 0x7E] range. See RFC 6750, section 3.
	 *
	 * @see ErrorObject#isLegal(String)
	 *
	 * @param errorDescription The error description string.
	 *
	 * @return {@code true} if the error description string contains valid
	 *         characters, else {@code false}.
	 */
	@Deprecated
	public static boolean isDescriptionWithValidChars(final String errorDescription) {
	
		return ErrorObject.isLegal(errorDescription);
	}
	
	
	/**
	 * Returns {@code true} if the specified scope consists of valid
	 * characters. Values for the "scope" attributes must not include
	 * characters outside the [0x20, 0x21] | [0x23 - 0x5B] | [0x5D - 0x7E]
	 * range. See RFC 6750, section 3.
	 *
	 * @see ErrorObject#isLegal(String)
	 *
	 * @param scope The scope.
	 *
	 * @return {@code true} if the scope contains valid characters, else
	 *         {@code false}.
	 */
	public static boolean isScopeWithValidChars(final Scope scope) {
		
		
		return ErrorObject.isLegal(scope.toString());
	}
	
	
	/**
	 * Regex pattern for matching the realm parameter of a WWW-Authenticate 
	 * header. Limits the realm string length to 256 chars to prevent
	 * potential stack overflow exception for very long strings due to
	 * recursive nature of regex.
	 */
	private static final Pattern realmPattern = Pattern.compile("realm=\"(([^\\\\\"]|\\\\.){0,256})\"");

	
	/**
	 * Regex pattern for matching the error parameter of a WWW-Authenticate 
	 * header. Double quoting is optional.
	 */
	private static final Pattern errorPattern = Pattern.compile("error=(\"([\\w\\_-]+)\"|([\\w\\_-]+))");


	/**
	 * Regex pattern for matching the error description parameter of a 
	 * WWW-Authenticate header.
	 */
	private static final Pattern errorDescriptionPattern = Pattern.compile("error_description=\"([^\"]+)\"");
	
	
	/**
	 * Regex pattern for matching the error URI parameter of a 
	 * WWW-Authenticate header.
	 */
	private static final Pattern errorURIPattern = Pattern.compile("error_uri=\"([^\"]+)\"");


	/**
	 * Regex pattern for matching the scope parameter of a WWW-Authenticate 
	 * header.
	 */
	private static final Pattern scopePattern = Pattern.compile("scope=\"([^\"]+)");
	
	
	/**
	 * The realm, {@code null} if not specified.
	 */
	private final String realm;


	/**
	 * Required scope, {@code null} if not specified.
	 */
	private final Scope scope;
	
	
	/**
	 * Creates a new OAuth 2.0 bearer token error with the specified code
	 * and description.
	 *
	 * @param code        The error code, {@code null} if not specified.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 */
	public BearerTokenError(final String code, final String description) {
	
		this(code, description, 0, null, null, null);
	}


	/**
	 * Creates a new OAuth 2.0 bearer token error with the specified code,
	 * description and HTTP status code.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 */
	public BearerTokenError(final String code, final String description, final int httpStatusCode) {
	
		this(code, description, httpStatusCode, null, null, null);
	}


	/**
	 * Creates a new OAuth 2.0 bearer token error with the specified code,
	 * description, HTTP status code, page URI, realm and scope.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 * @param uri            The error page URI, {@code null} if not
	 *                       specified.
	 * @param realm          The realm, {@code null} if not specified.
	 * @param scope          The required scope, {@code null} if not 
	 *                       specified.
	 */
	public BearerTokenError(final String code, 
		                final String description, 
		                final int httpStatusCode, 
		                final URI uri,
		                final String realm,
		                final Scope scope) {
	
		super(code, description, httpStatusCode, uri);
		this.realm = realm;
		this.scope = scope;
		
		if (scope != null && ! isScopeWithValidChars(scope)) {
			throw new IllegalArgumentException("The scope contains illegal characters, see RFC 6750, section 3");
		}
	}


	@Override
	public BearerTokenError setDescription(final String description) {

		return new BearerTokenError(super.getCode(), description, super.getHTTPStatusCode(), super.getURI(), realm, scope);
	}


	@Override
	public BearerTokenError appendDescription(final String text) {

		String newDescription;

		if (getDescription() != null)
			newDescription = getDescription() + text;
		else
			newDescription = text;

		return new BearerTokenError(super.getCode(), newDescription, super.getHTTPStatusCode(), super.getURI(), realm, scope);
	}


	@Override
	public BearerTokenError setHTTPStatusCode(final int httpStatusCode) {

		return new BearerTokenError(super.getCode(), super.getDescription(), httpStatusCode, super.getURI(), realm, scope);
	}


	@Override
	public BearerTokenError setURI(final URI uri) {

		return new BearerTokenError(super.getCode(), super.getDescription(), super.getHTTPStatusCode(), uri, realm, scope);
	}
	
	
	/**
	 * Gets the realm.
	 *
	 * @return The realm, {@code null} if not specified.
	 */
	public String getRealm() {
	
		return realm;
	}


	/**
	 * Sets the realm.
	 *
	 * @param realm realm, {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified realm.
	 */
	public BearerTokenError setRealm(final String realm) {

		return new BearerTokenError(getCode(), 
			                    getDescription(), 
			                    getHTTPStatusCode(), 
			                    getURI(), 
			                    realm, 
			                    getScope());
	}


	/**
	 * Gets the required scope.
	 *
	 * @return The required scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}


	/**
	 * Sets the required scope.
	 *
	 * @param scope The required scope, {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified required scope.
	 */
	public BearerTokenError setScope(final Scope scope) {

		return new BearerTokenError(getCode(),
			                    getDescription(),
			                    getHTTPStatusCode(),
			                    getURI(),
			                    getRealm(),
			                    scope);
	}


	/**
	 * Returns the {@code WWW-Authenticate} HTTP response header code for 
	 * this bearer access token error response.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * Bearer realm="example.com", error="invalid_token", error_description="Invalid access token"
	 * </pre>
	 *
	 * @return The {@code Www-Authenticate} header value.
	 */
	public String toWWWAuthenticateHeader() {

		StringBuilder sb = new StringBuilder("Bearer");
		
		int numParams = 0;
		
		// Serialise realm, may contain double quotes
		if (realm != null) {
			sb.append(" realm=\"");
			sb.append(getRealm().replaceAll("\"","\\\\\""));
			sb.append('"');
			
			numParams++;
		}
		
		// Serialise error, error_description, error_uri
		if (getCode() != null) {
			
			if (numParams > 0)
				sb.append(',');
			
			sb.append(" error=\"");
			sb.append(getCode());
			sb.append('"');
			numParams++;
			
			if (getDescription() != null) {

				if (numParams > 0)
					sb.append(',');

				sb.append(" error_description=\"");
				sb.append(getDescription());
				sb.append('"');
				numParams++;
			}

			if (getURI() != null) {
		
				if (numParams > 0)
					sb.append(',');
				
				sb.append(" error_uri=\"");
				sb.append(getURI().toString()); // double quotes always escaped in URI representation
				sb.append('"');
				numParams++;
			}
		}

		// Serialise scope
		if (scope != null) {

			if (numParams > 0)
				sb.append(',');

			sb.append(" scope=\"");
			sb.append(scope.toString());
			sb.append('"');
		}


		return sb.toString();
	}


	/**
	 * Parses an OAuth 2.0 bearer token error from the specified HTTP
	 * response {@code WWW-Authenticate} header.
	 *
	 * @param wwwAuth The {@code WWW-Authenticate} header value to parse. 
	 *                Must not be {@code null}.
	 *
	 * @return The bearer token error.
	 *
	 * @throws ParseException If the {@code WWW-Authenticate} header value 
	 *                        couldn't be parsed to a Bearer token error.
	 */
	public static BearerTokenError parse(final String wwwAuth)
		throws ParseException {

		// We must have a WWW-Authenticate header set to Bearer .*
		if (! wwwAuth.regionMatches(true, 0, "Bearer", 0, "Bearer".length()))
			throw new ParseException("WWW-Authenticate scheme must be OAuth 2.0 Bearer");
		
		Matcher m;
		
		// Parse optional realm
		m = realmPattern.matcher(wwwAuth);
		
		String realm = null;
		
		if (m.find())
			realm = m.group(1);
		
		if (realm != null)
			realm = realm.replace("\\\"", "\""); // strip escaped double quotes
		
		
		// Parse optional error 
		String errorCode = null;
		String errorDescription = null;
		URI errorURI = null;

		m = errorPattern.matcher(wwwAuth);
		
		if (m.find()) {
			
			// Error code: try group with double quotes, else group with no quotes
			errorCode = m.group(2) != null ? m.group(2) : m.group(3);
			
			if (! ErrorObject.isLegal(errorCode))
				errorCode = null; // found invalid chars

			// Parse optional error description
			m = errorDescriptionPattern.matcher(wwwAuth);

			if (m.find())
				errorDescription = m.group(1);

			
			// Parse optional error URI
			m = errorURIPattern.matcher(wwwAuth);
			
			if (m.find()) {
				try {
					errorURI = new URI(m.group(1));
				} catch (URISyntaxException e) {
					// ignore, URI is not required to construct error object
				}
			}
		}


		Scope scope = null;

		m = scopePattern.matcher(wwwAuth);

		if (m.find())
			scope = Scope.parse(m.group(1));
		

		return new BearerTokenError(errorCode, 
			                    errorDescription, 
			                    0, // HTTP status code not known
			                    errorURI, 
			                    realm, 
			                    scope);
	}
}
