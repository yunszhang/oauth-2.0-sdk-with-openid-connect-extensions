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

package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * Authorised party.
 * Use {@link com.nimbusds.openid.connect.sdk.claims.AuthorizedParty} instead.
 */
@Deprecated
@Immutable
public final class AuthorizedParty extends Identifier {


	/**
	 * Creates a new authorised party identifier with the specified value.
	 *
	 * @param value The authorised party value. Must not be {@code null}
	 *              or empty string.
	 */
	public AuthorizedParty(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {

		return object instanceof AuthorizedParty &&
			this.toString().equals(object.toString());
	}
}