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

package com.nimbusds.oauth2.sdk.dpop.verifier;


/**
 * Invalid DPoP proof exception.
 */
public class InvalidDPoPProofException extends Exception {
	
	
	private static final long serialVersionUID = -379875576526526089L;
	
	
	/**
	 * Creates a new invalid DPoP proof exception.
	 *
	 * @param message The message, {@code null} if not specified.
	 */
	public InvalidDPoPProofException(final String message) {
		super(message);
	}
	
	
	/**
	 * Creates a new invalid DPoP proof exception.
	 *
	 * @param message The message, {@code null} if not specified.
	 * @param cause   The cause, {@code null} if not specified.
	 */
	public InvalidDPoPProofException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
