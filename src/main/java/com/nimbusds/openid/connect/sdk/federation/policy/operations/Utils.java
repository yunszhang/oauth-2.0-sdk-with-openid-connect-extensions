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

package com.nimbusds.openid.connect.sdk.federation.policy.operations;


import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


/**
 * Policy operation utilities.
 */
class Utils {
	
	
	/**
	 * Casts a policy operation for typed {@link PolicyOperation#merge}.
	 *
	 * @param op    The policy operation. Must not be {@code null}.
	 * @param clazz The target class. Must not be {@code null}.
	 * @param <T>
	 *
	 * @return The cast policy operation.
	 *
	 * @throws PolicyViolationException If the cast failed.
	 */
	static <T> T castForMerge(final PolicyOperation op, final Class<T> clazz)
		throws PolicyViolationException {
		try {
			return (T) op;
		} catch (ClassCastException e) {
			throw new PolicyViolationException("The policy must be " + clazz.getName());
		}
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private Utils() {}
}
