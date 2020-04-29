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


import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Federation policy operation.
 */
public interface PolicyOperation {
	
	
	/**
	 * Returns the name identifying the policy operation.
	 *
	 * @return The operation name.
	 */
	OperationName getOperationName();
	
	
	/**
	 * Parses a federation policy operation configuration from the
	 * specified JSON entity.
	 *
	 * @param jsonEntity The JSON entity, must represent a boolean, number,
	 *                   string, array or object. {@code null} if not
	 *                   specified.
	 *
	 * @throws ParseException On a parse exception.
	 */
	void parseConfiguration(final Object jsonEntity) throws ParseException;
	
	
	/**
	 * Merges a policy operation.
	 *
	 * @param other The policy to merge. Must be of the same type and not
	 *              {@code null}.
	 *
	 * @return The resulting new policy operation.
	 *
	 * @throws PolicyViolationException On a merge exception.
	 */
	PolicyOperation merge(final PolicyOperation other) throws PolicyViolationException;
}
