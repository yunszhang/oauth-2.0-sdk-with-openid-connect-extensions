/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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


import java.util.List;

import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


/**
 * Validates the permitted combinations of known policy operations for a given
 * metadata parameter.
 *
 * <p>Supports all standard OpenID Connect federation policy operations:
 *
 * <ul>
 *     <li>{@link SubsetOfOperation subset_of}
 *     <li>{@link OneOfOperation one_of}
 *     <li>{@link SupersetOfOperation superset_of}
 *     <li>{@link AddOperation add}
 *     <li>{@link ValueOperation value}
 *     <li>{@link DefaultOperation default}
 *     <li>{@link EssentialOperation essential}
 * </ul>
 *
 * <p>Override the {@link #validate(List)} method to support additional custom
 * policies.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 4.2.
 * </ul>
 */
public class DefaultPolicyOperationCombinationValidator implements PolicyOperationCombinationValidator {
	
	
	@Override
	public void validate(final List<PolicyOperation> policyOperations)
		throws PolicyViolationException {
		
		
	}
}
