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

package com.nimbusds.openid.connect.sdk.id;


/**
 * Invalid pairwise subject exception.
 */
public class InvalidPairwiseSubjectException extends Exception {
	
	
	private static final long serialVersionUID = 3292935320822130346L;
	
	
	/**
	 * Creates a new invalid pairwise subject exception.
	 *
	 * @param message The exception message.
	 */
	public InvalidPairwiseSubjectException(final String message) {
		super(message);
	}


	/**
	 * Creates a new invalid pairwise subject exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public InvalidPairwiseSubjectException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
