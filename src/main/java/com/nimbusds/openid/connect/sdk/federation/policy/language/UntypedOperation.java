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


/**
 * Untyped operation.
 */
public interface UntypedOperation extends PolicyOperation {
	
	
	/**
	 * Applies an untyped operation.
	 *
	 * @param value The value, {@code null} if not specified.
	 *
	 * @return The resulting value, must represent a valid JSON entity such
	 *         as boolean, number, string, array or object.
	 *
	 * @throws PolicyViolationException On a policy violation.
	 */
	Object apply(final Object value) throws PolicyViolationException;
}
