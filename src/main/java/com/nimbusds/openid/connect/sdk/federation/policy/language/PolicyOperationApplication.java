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

package com.nimbusds.openid.connect.sdk.federation.policy.language;


import java.util.List;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONUtils;


/**
 * Utility for applying a policy operation to a metadata parameter value.
 */
public class PolicyOperationApplication {
	
	
	/**
	 * Applies a policy operation to a metadata parameter value.
	 *
	 * @param op    The policy operation. Must not be {@code null}.
	 * @param value The parameter value. Must be a boolean, string, string
	 *              list or {@code null}.
	 *
	 * @return The new parameter value, potentially modified.
	 *
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static Object apply(final PolicyOperation op, final Object value)
		throws PolicyViolationException {
		
		if (op instanceof UntypedOperation) {
			
			return ((UntypedOperation)op).apply(value);
		}
		
		if (op instanceof BooleanOperation) {
			
			if (! (value instanceof Boolean)) {
				throw new PolicyViolationException("The value must be a boolean");
			}
			return ((BooleanOperation)op).apply((Boolean)value);
		}
		
		if (op instanceof StringOperation) {
			
			StringOperation stringOperation = (StringOperation)op;
			
			if (value == null) {
				return stringOperation.apply(null);
			} else if (value instanceof String) {
				return stringOperation.apply((String)value);
			} else {
				throw new PolicyViolationException("The value must be a string");
			}
		}
		
		if (op instanceof StringListOperation) {
			
			StringListOperation stringListOperation = (StringListOperation)op;
			
			if (value == null) {
				return stringListOperation.apply(null);
			} else if (value instanceof List) {
				try {
					return stringListOperation.apply(JSONUtils.toStringList(value));
				} catch (ParseException e) {
					throw new PolicyViolationException("The value must be a string list", e);
				}
			} else {
				throw new PolicyViolationException("The value must be a string list");
			}
		}
		
		throw new PolicyViolationException("Unsupported policy operation: " + op.getClass().getName());
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private PolicyOperationApplication() {}
}
