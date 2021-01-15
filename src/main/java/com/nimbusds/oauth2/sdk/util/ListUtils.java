/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import java.util.LinkedList;
import java.util.List;


/**
 * List utilities.
 */
public class ListUtils {
	
	
	/**
	 * Returns a copy of the specified list with all {@code null} items
	 * removed.
	 *
	 * @param list The list. May be {@code null}.
	 *
	 * @return The list with all {@code null} items removed, {@code null}
	 *         if not specified.
	 */
	public static <T> List<T> removeNullItems(final List<T> list) {
		if (list == null) {
			return null;
		}
		List<T> out = new LinkedList<>();
		for (T item: list) {
			if (item != null) {
				out.add(item);
			}
		}
		return out;
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private ListUtils() {}
}
