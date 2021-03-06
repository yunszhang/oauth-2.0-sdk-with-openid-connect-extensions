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

package com.nimbusds.oauth2.sdk.assertions.saml2;


/**
 * Bad SAML 2.0 assertion exception.
 */
public class BadSAML2AssertionException extends Exception {
	
	
	private static final long serialVersionUID = 7849539907246003512L;
	
	
	/**
	 * Creates a new bad SAML 2.0 assertion exception.
	 *
	 * @param message The exception message.
	 */
	public BadSAML2AssertionException(final String message) {

		super(message);
	}


	/**
	 * Creates a new bad SAML 2.0 assertion exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public BadSAML2AssertionException(final String message, final Throwable cause) {

		super(message, cause);
	}
}
