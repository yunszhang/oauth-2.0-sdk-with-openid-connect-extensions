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

package com.nimbusds.oauth2.sdk.util;


import java.util.Collection;


/**
 * Collection utilities.
 */
public final class CollectionUtils {
	
	
	/**
	 * Returns {@code true} if the specified collection is {@code null} or
	 * empty.
	 *
	 * @param collection The collection. May be {@code null}.
	 *
	 * @return {@code true} if the collection is {@code null} or empty,
	 *         else {@code false}.
	 */
	public static boolean isEmpty(final Collection<?> collection) {
		
		return collection == null || collection.isEmpty();
	}
	
	
	/**
	 * Returns {@code true} if the specified collection is not empty.
	 *
	 * @param collection The collection. May be {@code null}.
	 *
	 * @return {@code true} if the collection is not empty, else
	 *         {@code false}.
	 */
	public static boolean isNotEmpty(final Collection<?> collection) {
		
		return collection != null && ! collection.isEmpty();
	}
	
	
	/**
	 * Returns {@code true} if the specified collection contains the
	 * specified item.
	 *
	 * @param collection The collection. May be {@code null}.
	 * @param item       The item. Should not be {@code null}.
	 *
	 * @return {@code true} if the collection is not empty and contains the
	 *         item, else {@code false}.
	 */
	public static <T> boolean contains(final Collection<T> collection, final T item) {
		
		return isNotEmpty(collection) && collection.contains(item);
	}
	
	
	/**
	 * Returns {@code true} if the specified collections intersect.
	 *
	 * @param a The first collection. May be {@code null}.
	 * @param b The second collection. May be {@code null}.
	 *
	 * @return {@code true} if the collections intersect, else
	 *         {@code false}.
	 */
	public static <T> boolean intersect(final Collection<T> a, final Collection<T> b) {
		
		if (isEmpty(a) || isEmpty(b)) {
			return false;
		}
		
		for (T item: a) {
			if (b.contains(item)) {
				return true;
			}
		}
		
		return false;
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private CollectionUtils() {}
}
