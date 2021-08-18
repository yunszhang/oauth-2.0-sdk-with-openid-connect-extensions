/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Access token utilities.
 */
class AccessTokenUtils {
	
	
	/**
	 * Parses a {@code token_type} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 * @param type   The expected token type. Must not be {@code null}.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static void parseAndEnsureType(final JSONObject params, final AccessTokenType type)
		throws ParseException {
		
		if (! new AccessTokenType(JSONObjectUtils.getString(params, "token_type")).equals(type)) {
			throw new ParseException("Token type must be " + type);
		}
	}
	
	
	/**
	 * Parses a {code access_token} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The token value.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static String parseValue(final JSONObject params)
		throws ParseException {
		
		return JSONObjectUtils.getString(params, "access_token");
	}
	
	
	/**
	 * Parses a {@code expires_in} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The lifetime, in seconds, zero if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static long parseLifetime(final JSONObject params)
		throws ParseException {
		
		if (params.containsKey("expires_in")) {
			
			// Lifetime can be a JSON number or string
			if (params.get("expires_in") instanceof Number) {
				return JSONObjectUtils.getLong(params, "expires_in");
			} else {
				String lifetimeStr = JSONObjectUtils.getString(params, "expires_in");
				try {
					return Long.parseLong(lifetimeStr);
				} catch (NumberFormatException e) {
					throw new ParseException("Invalid expires_in parameter, must be integer");
				}
			}
		}
		
		return 0L;
	}
	
	
	/**
	 * Parses a {@code scope} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The scope, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Scope parseScope(final JSONObject params)
		throws ParseException {
		
		return Scope.parse(JSONObjectUtils.getString(params, "scope", null));
	}
	
	
	/**
	 * Parses an access token value from the specified Authorization header
	 * value.
	 *
	 * @param headerValue The Authorisation header value, {@code null} if
	 *                    not specified or missing.
	 * @param type        The expected access token type. Must be
	 *                    {@link AccessTokenType#BEARER} or
	 *                    {@link AccessTokenType#DPOP} and not
	 *                    {@code null}.
	 *
	 * @return The access token value.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static String parseValueFromHeader(final String headerValue, final AccessTokenType type)
		throws ParseException {
		
		if (! AccessTokenType.BEARER.equals(type) && ! AccessTokenType.DPOP.equals(type)) {
			throw new IllegalArgumentException("Unsupported access token type, must be Bearer or DPoP: " + type);
		}
		
		if (StringUtils.isBlank(headerValue)) {
			TokenSchemeError schemeError = BearerTokenError.MISSING_TOKEN;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.MISSING_TOKEN;
			}
			throw new ParseException("Missing HTTP Authorization header", schemeError);
		}
		
		String[] parts = headerValue.split("\\s", 2);
		
		if (parts.length != 2) {
			TokenSchemeError schemeError = BearerTokenError.INVALID_REQUEST;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.INVALID_REQUEST;
			}
			throw new ParseException("Invalid HTTP Authorization header value", schemeError);
		}
		
		if (! parts[0].equals(type.getValue())) {
			TokenSchemeError schemeError = BearerTokenError.INVALID_REQUEST;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.INVALID_TOKEN;
			}
			throw new ParseException("Token type must be Bearer", schemeError);
		}
		
		if (StringUtils.isBlank(parts[1])) {
			TokenSchemeError schemeError = BearerTokenError.INVALID_REQUEST;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.INVALID_REQUEST;
			}
			throw new ParseException("The token value must not be null or empty string", schemeError);
		}
		
		return parts[1];
	}
	
	
	private AccessTokenUtils() {}
}