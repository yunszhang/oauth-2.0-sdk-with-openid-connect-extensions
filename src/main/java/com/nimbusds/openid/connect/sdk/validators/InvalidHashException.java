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

package com.nimbusds.openid.connect.sdk.validators;


/**
 * Invalid access token / code hash exception.
 */
public class InvalidHashException extends Exception {


	/**
	 * Invalid access token hash exception.
	 */
	public static final InvalidHashException INVALID_ACCESS_T0KEN_HASH_EXCEPTION
		= new InvalidHashException("Invalid access token hash (at_hash)");
	

	/**
	 * Invalid authorisation code hash exception.
	 */
	public static final InvalidHashException INVALID_CODE_HASH_EXCEPTION
		= new InvalidHashException("Invalid authorization code hash (c_hash)");


	/**
	 * Creates a new invalid hash exception.
	 *
	 * @param message The exception message.
	 */
	private InvalidHashException(String message) {
		super(message);
	}
}
