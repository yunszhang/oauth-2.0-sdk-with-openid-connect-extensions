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


import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.PolicyOperationFactory;


@Immutable
public final class PolicyEntry {
	
	
	private final String parameterName;
	
	
	private final List<PolicyOperation> operations;
	
	
	public PolicyEntry(final String parameterName, final List<PolicyOperation> operations) {
		if (StringUtils.isBlank(parameterName)) {
			throw new IllegalArgumentException("The parameter name must not be null or empty");
		}
		this.parameterName = parameterName;
		this.operations = operations != null ? operations : Collections.<PolicyOperation>emptyList();
	}
	
	
	public String getParameterName() {
		return parameterName;
	}
	
	
	public List<PolicyOperation> getOperations() {
		return operations;
	}
	
	
	public Object apply(final Object value)
		throws PolicyViolationException {
		
		if (CollectionUtils.isEmpty(getOperations())) {
			// no ops
			return value;
		}
		
		// Apply policy operations in list
		Object updatedValue = value;
		for (PolicyOperation op: getOperations()) {
			updatedValue = apply(op, updatedValue);
		}
		return updatedValue;
	}
	
	
	protected static Object apply(final PolicyOperation op, final Object value)
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
				throw new PolicyViolationException("The value must be string list");
			}
		}
		
		throw new PolicyViolationException("Unsupported policy operation: " + op.getClass().getName());
	}
	
	
	public static PolicyEntry parse(final String parameterName,
					final Map<String,Object> spec,
					final PolicyOperationFactory factory)
		throws ParseException  {
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		
		for (String opName: spec.keySet()) {
			PolicyOperation op = factory.createForName(new OperationName(opName));
			op.parseConfiguration(spec.get(opName));
			policyOperations.add(op);
		}
		
		return new PolicyEntry(parameterName, policyOperations);
	}
	
	
	public static PolicyEntry parse(final String parameterName,
					final Map<String,Object> spec)
		throws ParseException  {
		
		return parse(parameterName, spec, new PolicyOperationFactory());
	}
}
