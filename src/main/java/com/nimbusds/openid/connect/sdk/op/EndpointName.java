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

package com.nimbusds.openid.connect.sdk.op;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * OpenID provider endpoint name, used in specifying the applicable client
 * authentication methods in automatic registration in OpenID Connect
 * Federation 1.0.
 */
@Immutable
public final class EndpointName extends Identifier {
	
	
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Authorisation request (endpoint).
	 */
	public static final EndpointName AR = new EndpointName("ar");
	
	/**
	 * Pushed authorisation request (endpoint).
	 */
	public static final EndpointName PAR = new EndpointName("par");
	
	
	/**
	 * Creates a new endpoint name.
	 *
	 * @param value The endpoint name. Must not be {@code null}.
	 */
	public EndpointName(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof EndpointName &&
			this.toString().equals(object.toString());
	}
}
