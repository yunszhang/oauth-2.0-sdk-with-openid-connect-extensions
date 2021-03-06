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
import java.util.*;

import net.jcip.annotations.Immutable;


/**
 * Audience identifier.
 *
 * <p>Provides helper methods for:
 *
 * <ul>
 *     <li>Converting to / from string arrays and collections
 *     <li>Matching audience values
 * </ul>
 */
@Immutable
public final class Audience extends Identifier {
	
	
	private static final long serialVersionUID = 9149519511538940783L;
	
	
	/**
	 * Creates a new audience identifier with the specified value.
	 *
	 * @param value The audience identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public Audience(final String value) {

		super(value);
	}


	/**
	 * Creates a new audience identifier with the specified URI value.
	 *
	 * @param value The URI value. Must not be {@code null}.
	 */
	public Audience(final URI value) {

		super(value.toString());
	}


	/**
	 * Creates a new audience identifier with the specified value.
	 *
	 * @param value The value. Must not be {@code null}.
	 */
	public Audience(final Identifier value) {

		super(value.getValue());
	}


	/**
	 * Returns a singleton list of this audience.
	 *
	 * @return A singleton list consisting of this audience only.
	 */
	public List<Audience> toSingleAudienceList() {

		List<Audience> audienceList = new ArrayList<>(1);
		audienceList.add(this);
		return audienceList;
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Audience &&
		       this.toString().equals(object.toString());
	}


	/**
	 * Returns a string list representation of the specified audience.
	 *
	 * @param audience The audience. May be {@code null}.
	 *
	 * @return The string list, {@code null} if the argument was
	 *         {@code null}.
	 */
	public static List<String> toStringList(final Audience audience) {

		if (audience == null) {
			return null;
		}
		return Collections.singletonList(audience.getValue());
	}


	/**
	 * Returns a string list representation of the specified audience list.
	 *
	 * @param audienceList The audience list. May be {@code null}.
	 *
	 * @return The string list, {@code null} if the argument was
	 *         {@code null}.
	 */
	public static List<String> toStringList(final List<Audience> audienceList) {

		if (audienceList == null) {
			return null;
		}

		List<String> list = new ArrayList<>(audienceList.size());
		for (Audience aud: audienceList) {
			list.add(aud.getValue());
		}
		return list;
	}


	/**
	 * Creates an audience list from the specified string list
	 * representation.
	 *
	 * @param strings The string list. May be {@code null}.
	 *
	 * @return The audience list, {@code null} if the argument was
	 *         {@code null}.
	 */
	public static List<Audience> create(final List<String> strings) {

		if (strings == null) {
			return null;
		}

		List<Audience> audienceList = new ArrayList<>(strings.size());

		for (String s: strings) {
			audienceList.add(new Audience(s));
		}
		return audienceList;
	}


	/**
	 * Creates an audience list from the specified string array.
	 *
	 * @param strings The strings. May be {@code null}.
	 *
	 * @return The audience list, {@code null} if the argument was
	 *         {@code null}.
	 */
	public static List<Audience> create(final String ... strings) {

		if (strings == null) {
			return null;
		}

		return create(Arrays.asList(strings));
	}


	/**
	 * Returns {@code true} if the specified collections have at at least
	 * one matching audience value.
	 *
	 * @param c1 The first audience collection. May be {@code null}.
	 * @param c2 The second audience collection. May be {@code null}.
	 *
	 * @return {@code true} if the specified collections have at at least
	 *         one matching audience value, {@code false} if there are no
	 *         matches or either collection is {@code null} or empty.
	 */
	public static boolean matchesAny(final Collection<Audience> c1, final Collection<Audience> c2) {

		if (c1 == null || c2 == null) {
			return false;
		}

		for (Audience aud: c1) {
			if (c2.contains(aud)) {
				return true;
			}
		}

		return false;
	}
}