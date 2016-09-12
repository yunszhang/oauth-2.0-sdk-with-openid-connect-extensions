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


import java.net.URI;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * Parse exception.
 */
public class ParseException extends GeneralException {


	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public ParseException(final String message) {
	
		this(message, null, null, null, null, null);
	}
	
	
	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public ParseException(final String message, final Throwable cause) {
	
		this(message, null, null, null, null, null, cause);
	}


	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated error, {@code null} if not specified.
	 */
	public ParseException(final String message, final ErrorObject error) {
	
		this(message, error, null, null, null, null);
	}


	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated error, {@code null} if not specified.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public ParseException(final String message, 
		              final ErrorObject error,
		              final Throwable cause) {
	
		this(message, error, null, null, null, null, cause);
	}
	
	
	/**
	 * Creates a new parse exception.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param error       The associated error, {@code null} if not
	 *                    specified.
	 * @param clientID    The associated client identifier. Must not be
	 *                    {@code null}.
	 * @param redirectURI The associated redirection URI. Must not be
	 *                    {@code null}.
	 * @param responseMode The optional associated response mode,
	 *                     {@code null} if not specified.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 */
	public ParseException(final String message, 
		              final ErrorObject error,
			      final ClientID clientID,
		              final URI redirectURI,
			      final ResponseMode responseMode,
		              final State state) {

		this(message, error, clientID, redirectURI, responseMode, state, null);
	}


	/**
	 * Creates a new parse exception.
	 *
	 * @param message      The exception message. May be {@code null}.
	 * @param error        The associated error, {@code null} if not
	 *                     specified.
	 * @param clientID     The associated client identifier. Must not be
	 *                     {@code null}.
	 * @param redirectURI  The associated redirection URI. Must not be
	 *                     {@code null}.
	 * @param responseMode The optional associated response mode,
	 *                     {@code null} if not specified.
	 * @param state        The optional associated state parameter,
	 *                     {@code null} if not specified.
	 * @param cause        The exception cause, {@code null} if not
	 *                     specified.
	 */
	public ParseException(final String message, 
		              final ErrorObject error,
			      final ClientID clientID,
		              final URI redirectURI,
			      final ResponseMode responseMode,
		              final State state,
		              final Throwable cause) {

		super(message, error, clientID, redirectURI, responseMode, state, cause);
	}
}
