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

package com.nimbusds.oauth2.sdk.jose.jwk;


import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * JSON Web Key (JWK) source. Exposes a method for retrieving selected keys for
 * a party (OAuth 2.0 server or client). Implementations must be thread-safe.
 */
@Deprecated
public interface JWKSource {
	

	/**
	 * Retrieves a list of JWKs matching the specified criteria.
	 *
	 * @param id          Identifier of the JWK owner, typically an
	 *                    Authorisation Server / OpenID Provider issuer ID,
	 *                    or client ID. Must not be {@code null}.
	 * @param jwkSelector A JWK selector. Must not be {@code null}.
	 *
	 * @return The matching JWKs, empty list if no matches were found or
	 *         retrieval failed.
	 */
	List<JWK> get(final Identifier id, final JWKSelector jwkSelector);
}
