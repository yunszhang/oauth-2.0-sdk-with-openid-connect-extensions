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

package com.nimbusds.oauth2.sdk.id;


import java.net.URI;
import java.net.URISyntaxException;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Issuer identifier.
 *
 * <p>Valid issuer identifiers are URIs with "https" schema and no query or
 * fragment component.
 */
@Immutable
public final class Issuer extends Identifier {
	
	
	private static final long serialVersionUID = -8033463330193076151L;
	
	
	/**
	 * Checks if the specified string represents a valid issuer identifier.
	 * This method is {@code null}-safe.
	 *
	 * @param value The issuer string.
	 *
	 * @return {@code true} if the string represents a valid issuer
	 *         identifier, else {@code false}.
	 */
	public static boolean isValid(final String value) {

		if (value == null)
			return false;

		try {
			return isValid(new URI(value));

		} catch (URISyntaxException e) {

			return false;
		}
	}


	/**
	 * Checks if the specified issuer is a valid identifier. This method is
	 * {@code null}-safe.
	 *
	 * @param value The issuer.
	 *
	 * @return {@code true} if the value is a valid identifier, else
	 *         {@code false}.
	 */
	public static boolean isValid(final Issuer value) {

		if (value == null)
			return false;

		try {
			return isValid(new URI(value.getValue()));

		} catch (URISyntaxException e) {

			return false;
		}
	}


	/**
	 * Checks if the specified URI represents a valid issuer identifier.
	 * This method is {@code null}-safe.
	 *
	 * @param value The URI.
	 *
	 * @return {@code true} if the values represents a valid issuer
	 *         identifier, else {@code false}.
	 */
	public static boolean isValid(final URI value) {

		if (value == null)
			return false;

		if (value.getScheme() == null || ! value.getScheme().equalsIgnoreCase("https"))
			return false;

		if (value.getRawQuery() != null)
			return false;

		return value.getRawFragment() == null;

	}


	/**
	 * Creates a new issuer identifier with the specified value.
	 *
	 * @param value The issuer identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public Issuer(final String value) {

		super(value);
	}


	/**
	 * Creates a new issuer identifier with the specified URI value.
	 *
	 * @param value The URI value. Must not be {@code null}.
	 */
	public Issuer(final URI value) {

		super(value.toString());
	}


	/**
	 * Creates a new issuer identifier with the specified value.
	 *
	 * @param value The value. Must not be {@code null}.
	 */
	public Issuer(final Identifier value) {

		super(value.getValue());
	}


	/**
	 * Checks if this issuer is a valid identifier. This method is
	 * {@code null}-safe.
	 *
	 * @return {@code true} if the value is a valid identifier, else
	 *         {@code false}.
	 */
	public boolean isValid() {

		return Issuer.isValid(this);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Issuer && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an issuer from the specified string.
	 *
	 * @param s The string to parse, {@code null} or empty if no issuer is
	 *          specified.
	 *
	 * @return The issuer, {@code null} if the parsed string was
	 *         {@code null} or empty.
	 */
	public static Issuer parse(final String s) {
		
		if (StringUtils.isBlank(s))
			return null;
		
		return new Issuer(s);
	}
}