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

package com.nimbusds.oauth2.sdk;


import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;


/**
 * Client credentials grant. Used in access token requests where the client is
 * acting on its own behalf.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 4.4.2.
 * </ul>
 */
@Immutable
public class ClientCredentialsGrant extends AuthorizationGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.CLIENT_CREDENTIALS;


	/**
	 * Creates a new client credentials grant. The actual client
	 * credentials are included in the
	 * {@link com.nimbusds.oauth2.sdk.auth.ClientAuthentication client
	 * authentication} of the {@link com.nimbusds.oauth2.sdk.TokenRequest}.
	 */
	public ClientCredentialsGrant() {

		super(GRANT_TYPE);
	}


	@Override
	public Map<String,String> toParameters() {

		Map<String,String> params = new LinkedHashMap<>();
		params.put("grant_type", GRANT_TYPE.getValue());
		return params;
	}


	/**
	 * Parses a client credentials grant from the specified parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=client_credentials
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The client credentials grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ClientCredentialsGrant parse(final Map<String,String> params)
		throws ParseException {

		// Parse grant type
		String grantTypeString = params.get("grant_type");

		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter", OAuth2Error.INVALID_REQUEST);

		if (! GrantType.parse(grantTypeString).equals(GRANT_TYPE))
			throw new ParseException("The \"grant_type\" must be " + GRANT_TYPE, OAuth2Error.UNSUPPORTED_GRANT_TYPE);

		return new ClientCredentialsGrant();
	}
}
