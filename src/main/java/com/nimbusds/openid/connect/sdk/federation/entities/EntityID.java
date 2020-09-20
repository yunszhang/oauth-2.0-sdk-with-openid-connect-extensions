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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.StringUtils;


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
	
	
	private static final long serialVersionUID = -2884746939238001871L;
	
	
	/**
	 * Creates a new entity identifier from the specified URI.
	 *
	 * @param value The URI. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException On a illegal entity ID.
	 */
	public EntityID(final URI value) {
		this(value.toString());
	}
	
	
	/**
	 * Creates a new entity identifier from the specified issuer
	 * identifier.
	 *
	 * @param issuer The issuer. Must represent an URI and must not be
	 *               {@code null}.
	 *
	 * @throws IllegalArgumentException On a illegal entity ID.
	 */
	public EntityID(final Issuer issuer) {
		this(issuer.getValue());
	}
	
	
	/**
	 * Creates a new entity identifier from the specified subject
	 * identifier.
	 *
	 * @param subject The subject. Must represent an URI and must not be
	 *                {@code null}.
	 *
	 * @throws IllegalArgumentException On a illegal entity ID.
	 */
	public EntityID(final Subject subject) {
		this(subject.getValue());
	}
	
	
	/**
	 * Creates a new entity identifier from the specified client
	 * identifier.
	 *
	 * @param clientID The client ID. Must represent an URI and must not be
	 *                 {@code null}.
	 */
	public EntityID(final ClientID clientID) {
		this(clientID.getValue());
	}
	
	
	/**
	 * Creates a new entity identifier with the specified value.
	 *
	 * @param value The identifier value. Must represent an URI and must
	 *              not be {@code null}.
	 *
	 * @throws IllegalArgumentException On a illegal entity ID.
	 */
	public EntityID(final String value) {
		super(value);
		
		URI uri;
		try {
			uri = new URI(value);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("The entity ID must be an URI: " + e.getMessage(), e);
		}
		
		if (! "https".equalsIgnoreCase(uri.getScheme()) && ! "http".equalsIgnoreCase(uri.getScheme())) {
			throw new IllegalArgumentException("The entity ID must be an URI with https or http scheme");
		}
		
		if (StringUtils.isBlank(uri.getAuthority())) {
			throw new IllegalArgumentException("The entity ID must be an URI with authority (hostname)");
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
	
	/**
	 * Returns the entity identifier as an issuer.
	 *
	 * @return The issuer.
	 */
	public Issuer toIssuer() {
		return new Issuer(getValue());
	}
	
	
	/**
	 * Returns the entity identifier as a subject.
	 *
	 * @return The subject.
	 */
	public Subject toSubject() {
		return new Subject(getValue());
	}
	
	
	/**
	 * Returns the entity identifier as a client ID.
	 *
	 * @return The client ID.
	 */
	public ClientID toClientID() {
		return new ClientID(getValue());
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof EntityID &&
			this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an entity ID from the specified string.
	 *
	 * @param value The string value. Must not be {@code null}.
	 *
	 * @return The entity ID.
	 *
	 * @throws ParseException On a illegal entity ID.
	 */
	public static EntityID parse(final String value)
		throws ParseException {
		try {
			return new EntityID(value);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
	
	
	/**
	 * Parses an entity ID from the specified issuer.
	 *
	 * @param issuer The issuer. Must not be {@code null}.
	 *
	 * @return The entity ID.
	 *
	 * @throws ParseException On a illegal entity ID.
	 */
	public static EntityID parse(final Issuer issuer)
		throws ParseException {
		return parse(issuer.getValue());
	}
	
	
	/**
	 * Parses an entity ID from the specified subject.
	 *
	 * @param subject The subject. Must not be {@code null}.
	 *
	 * @return The entity ID.
	 *
	 * @throws ParseException On a illegal entity ID.
	 */
	public static EntityID parse(final Subject subject)
		throws ParseException {
		return parse(subject.getValue());
	}
	
	
	/**
	 * Parses an entity ID from the specified client ID.
	 *
	 * @param clientID The client ID. Must not be {@code null}.
	 *
	 * @return The entity ID.
	 *
	 * @throws ParseException On a illegal entity ID.
	 */
	public static EntityID parse(final ClientID clientID)
		throws ParseException {
		return parse(clientID.getValue());
	}
}
