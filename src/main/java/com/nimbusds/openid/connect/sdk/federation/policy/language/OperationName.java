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

package com.nimbusds.openid.connect.sdk.federation.policy.language;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Policy operation name.
 */
@Immutable
public final class OperationName extends Identifier {
	
	
	private static final long serialVersionUID = 1496506482155366452L;
	
	
	/**
	 * Creates a new policy operation name.
	 *
	 * @param name The policy operation name.
	 */
	public OperationName(final String name) {
		super(name);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof OperationName &&
			this.toString().equals(object.toString());
	}
}
