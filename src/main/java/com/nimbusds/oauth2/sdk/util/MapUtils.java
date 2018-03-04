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


import java.util.Map;


/**
 * Map utilities. Replicates Apache Commons Collections.
 */
public final class MapUtils {
	
	
	/**
	 * Returns {@code true} if the specified map is not {@code null} and
	 * not empty.
	 *
	 * @param map The map. May be {@code null}.
	 *
	 * @return {@code true} if the map is not {@code null} and not empty,
	 *         else {@code false}.
	 */
	public static boolean isNotEmpty(final Map<?,?> map) {
		
		return map != null && ! map.isEmpty();
	}
}
