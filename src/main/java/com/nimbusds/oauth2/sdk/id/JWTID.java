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
 * JSON Web Token (JWT) identifier.
 */
@Immutable
public final class JWTID extends Identifier {
	
	
	private static final long serialVersionUID = 6958512198352608856L;
	
	
	/**
	 * Creates a new JWT identifier with the specified value.
	 *
	 * @param value The JWT identifier value. Must not be {@code null} or
	 *              empty string.
	 */
	public JWTID(final String value) {

		super(value);
	}


	/**
	 * Creates a new JWT identifier with a randomly generated value of the 
	 * specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public JWTID(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new JWT identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public JWTID() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof JWTID &&
		       this.toString().equals(object.toString());
	}
}