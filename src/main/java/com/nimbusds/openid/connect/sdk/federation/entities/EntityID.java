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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.net.URI;
import java.net.URISyntaxException;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Federation entity identifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 1.2.
 * </ul>
 */
@Immutable
public final class EntityID extends Identifier {
	
	
	
	/**
	 * Creates a new entity identifier with the specified value.
	 *
	 * @param value The identifier value. Must represent an URI and must
	 *              not be {@code null}.
	 */
	public EntityID(final String value) {
		
		super(value);
		
		try {
			new URI(value);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("The entity identifier must be an URI: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Returns the entity identifier as an URI.
	 *
	 * @return The entity identifier URI.
	 */
	public URI toURI() {
		return URI.create(getValue());
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof EntityID &&
			this.toString().equals(object.toString());
	}
}
