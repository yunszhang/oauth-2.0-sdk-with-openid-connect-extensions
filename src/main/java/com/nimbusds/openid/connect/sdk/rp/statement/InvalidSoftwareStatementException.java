/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.rp.statement;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.client.RegistrationError;


/**
 * Invalid software statement exception.
 */
public class InvalidSoftwareStatementException extends Exception {
	
	
	private static final long serialVersionUID = -3170931736329757864L;
	
	
	/**
	 * Creates a new invalid software statement exception.
	 *
	 * @param message The message, {@code null} if not specified.
	 */
	public InvalidSoftwareStatementException(final String message) {
		this(message, null);
	}
	
	
	/**
	 * Creates a new invalid software statement exception.
	 *
	 * @param message The message, {@code null} if not specified.
	 * @param cause   The error cause, {@code null} if not specified.
	 */
	public InvalidSoftwareStatementException(final String message, final Throwable cause) {
		super(message, cause);
	}
	
	
	/**
	 * Returns the error object to return, an instance of a
	 * {@link RegistrationError#INVALID_SOFTWARE_STATEMENT}.
	 *
	 * @return The error object.
	 */
	public ErrorObject getErrorObject() {
		if (getMessage() != null) {
			return RegistrationError.INVALID_SOFTWARE_STATEMENT.setDescription(getMessage());
		} else {
			return RegistrationError.INVALID_SOFTWARE_STATEMENT;
		}
	}
}
