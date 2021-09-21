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

package com.nimbusds.openid.connect.sdk.federation.api;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Federation API operation type.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 6.
 * </ul>
 */
@Immutable
public final class OperationType extends Identifier {
	
	
	private static final long serialVersionUID = 377502712948643524L;
	
	
	/**
	 * Fetch operation.
	 */
	public static final OperationType FETCH = new OperationType("fetch");
	
	
	/**
	 * Resolve metadata operation.
	 */
	public static final OperationType RESOLVE_METADATA = new OperationType("resolve_metadata");
	
	
	/**
	 * Listing operation.
	 */
	public static final OperationType LISTING = new OperationType("listing");
	
	
	/**
	 * Creates a new operation type.
	 *
	 * @param value The operation type value. Must not be {@code null},
	 */
	public OperationType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof OperationType &&
			this.toString().equals(object.toString());
	}
}
