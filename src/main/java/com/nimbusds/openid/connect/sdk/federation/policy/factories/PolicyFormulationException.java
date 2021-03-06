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

package com.nimbusds.openid.connect.sdk.federation.policy.factories;


/**
 * Policy formulation exception.
 */
public class PolicyFormulationException extends Exception {
	
	
	private static final long serialVersionUID = -1254653984673380779L;
	
	
	/**
	 * Creates a new policy formulation exception.
	 *
	 * @param message The exception message.
	 */
	public PolicyFormulationException(final String message) {
		super(message);
	}
	
	
	/**
	 * Creates a new policy formulation exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public PolicyFormulationException(final String message, final Throwable cause) {
		super(message);
	}
}
