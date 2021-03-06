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

package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * The end-user's gender: Values defined by the OpenID Connect specification 
 * are {@link #FEMALE} and {@link #MALE} ({@code gender}). Other values may be
 * used when neither of the defined values are applicable.
 */
@Immutable
public class Gender extends Identifier {
	
	
	private static final long serialVersionUID = 3616234558991226411L;
	
	
	/**
	 * Female gender claim value.
	 */
	public static final Gender FEMALE = new Gender("female");
	
	
	/**
	 * Male gender claim value.
	 */
	public static final Gender MALE = new Gender("male");
	
	
	/**
	 * Creates a new gender with the specified value.
	 *
	 * @param value The gender value. Must not be {@code null}.
	 */
	public Gender(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Gender &&
		       this.toString().equals(object.toString());
	}
}