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
 * Subject (user) identifier.
 */
@Immutable
public final class Subject extends Identifier {
	
	
	private static final long serialVersionUID = 4305952346483638353L;
	
	
	/**
	 * Creates a new subject identifier with the specified value.
	 *
	 * @param value The subject identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public Subject(final String value) {

		super(value);
	}


	/**
	 * Creates a new subject identifier with a randomly generated value of 
	 * the specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public Subject(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new subject identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public Subject() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Subject &&
		       this.toString().equals(object.toString());
	}
}