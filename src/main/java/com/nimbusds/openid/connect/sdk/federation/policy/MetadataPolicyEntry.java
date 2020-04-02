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

package com.nimbusds.openid.connect.sdk.federation.policy;


import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.*;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.DefaultPolicyOperationCombinationValidator;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.DefaultPolicyOperationFactory;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.PolicyOperationCombinationValidator;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.PolicyOperationFactory;


/**
 * Policy entry for a metadata parameter.
 *
 * @see MetadataPolicy
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 4.1.
 * </ul>
 */
public class MetadataPolicyEntry implements Map.Entry<String, List<PolicyOperation>> {
	
	
	/**
	 * The default policy operation factory.
	 */
	protected final static PolicyOperationFactory DEFAULT_POLICY_OPERATION_FACTORY = new DefaultPolicyOperationFactory();
	
	
	/**
	 * The default policy operation combination validator.
	 */
	protected final static PolicyOperationCombinationValidator DEFAULT_POLICY_COMBINATION_VALIDATOR = new DefaultPolicyOperationCombinationValidator();
	
	
	/**
	 * The parameter name.
	 */
	private final String parameterName;
	
	
	/**
	 * The policy operations, empty list if none.
	 */
	private List<PolicyOperation> policyOperations;
	
	
	/**
	 * Creates a new policy entry for a metadata parameter.
	 *
	 * @param parameterName    The parameter name. Must not be
	 *                         {@code null}.
	 * @param policyOperations The policy operations, empty list or
	 *                         {@code null} if none.
	 */
	public MetadataPolicyEntry(final String parameterName, final List<PolicyOperation> policyOperations) {
		if (StringUtils.isBlank(parameterName)) {
			throw new IllegalArgumentException("The parameter name must not be null or empty");
		}
		this.parameterName = parameterName;
		this.policyOperations = policyOperations;
	}
	
	
	/**
	 * Returns the parameter name.
	 * @see #getKey()
	 *
	 * @return The parameter name.
	 */
	public String getParameterName() {
		return getKey();
	}
	
	
	/**
	 * @see #getParameterName()
	 */
	@Override
	public String getKey() {
		return parameterName;
	}
	
	
	/**
	 * Returns the policy operations.
	 * @see #getValue()
	 *
	 * @return The policy operations, empty list if none.
	 */
	public List<PolicyOperation> getPolicyOperations() {
		return getValue();
	}
	
	
	/**
	 * @see #getPolicyOperations()
	 */
	@Override
	public List<PolicyOperation> getValue() {
		return policyOperations;
	}
	
	
	@Override
	public List<PolicyOperation> setValue(final List<PolicyOperation> policyOperations) {
		throw new UnsupportedOperationException();
	}
	
	
	/**
	 * Applies this policy entry for a metadata parameter to the specified
	 * value.
	 *
	 * @param value The parameter value, {@code null} if not specified.
	 *
	 * @return The resulting value, can be {@code null}.
	 *
	 * @throws PolicyViolationException On a policy violation.
	 */
	public Object apply(final Object value)
		throws PolicyViolationException {
		
		if (CollectionUtils.isEmpty(getValue())) {
			// no ops
			return value;
		}
		
		// Apply policy operations in list
		Object updatedValue = value;
		for (PolicyOperation op: getValue()) {
			updatedValue = PolicyOperationApplication.apply(op, updatedValue);
		}
		return updatedValue;
	}
	
	
	/**
	 * Returns a JSON object representation of the policy operations for
	 * this entry.
	 *
	 * @return The JSON object keeping the ordering of the members.
	 */
	public LinkedHashMap<String,Object> toJSONObject() {
		
		if (CollectionUtils.isEmpty(getValue())) {
			return null;
		}
		
		LinkedHashMap<String,Object> orderedMap = new LinkedHashMap<>();
		for (PolicyOperation operation: getValue()) {
			// E.g. "subset_of": ["code", "code token", "code id_token"]}
			orderedMap.put(operation.getOperationName().getValue(), configToJSONEntity(operation));
		}
		
		return orderedMap;
	}
	
	
	private static Object configToJSONEntity(final PolicyOperation op) {
		
		// The order matters
		
		if (op instanceof StringConfiguration) {
			Object value = ((StringConfiguration)op).getStringConfiguration();
			if (value != null) {
				return value;
			}
		}
		
		if (op instanceof StringListConfiguration) {
			Object value = ((StringListConfiguration)op).getStringListConfiguration();
			if (value != null) {
				return value;
			}
		}
		
		if (op instanceof BooleanConfiguration) {
			return ((BooleanConfiguration)op).getBooleanConfiguration();
		}
		
		throw new IllegalArgumentException("Unsupported policy operation: " + op.getClass());
		
	}
	
	
	/**
	 * Parses a policy entry for a metadata parameter. This method is
	 * intended for policies including non-standard
	 * {@link PolicyOperation}s.
	 *
	 * @param parameterName        The parameter name. Must not be
	 *                             {@code null}.
	 * @param entrySpec            The JSON object entry specification,
	 *                             must not be {@code null}.
	 * @param factory              The policy operation factory. Must not
	 *                             be {@code null}.
	 * @param combinationValidator The policy operation combination
	 *                             validator. Must not be {@code null}.
	 *
	 * @return The policy entry for the metadata parameter.
	 *
	 * @throws ParseException           On JSON parsing exception.
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicyEntry parse(final String parameterName,
						final Map<String,Object> entrySpec,
						final PolicyOperationFactory factory,
						final PolicyOperationCombinationValidator combinationValidator)
		throws ParseException, PolicyViolationException {
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		
		for (String opName: entrySpec.keySet()) {
			PolicyOperation op = factory.createForName(new OperationName(opName));
			op.parseConfiguration(entrySpec.get(opName));
			policyOperations.add(op);
		}
		
		List<PolicyOperation> validatedPolicyOperations = combinationValidator.validate(policyOperations);
		
		return new MetadataPolicyEntry(parameterName, validatedPolicyOperations);
	}
	
	
	/**
	 * Parses a policy entry for a metadata parameter. This method is
	 * intended for policies with standard {@link PolicyOperation}s only.
	 * Uses the default {@link DefaultPolicyOperationFactory policy
	 * operation} and {@link DefaultPolicyOperationCombinationValidator
	 * policy combination validator} factories.
	 *
	 * @param parameterName The parameter name. Must not be {@code null}.
	 * @param entrySpec     The JSON object entry specification, must not
	 *                      be {@code null}.
	 *
	 * @return The policy entry for the metadata parameter.
	 *
	 * @throws ParseException           On JSON parsing exception.
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicyEntry parse(final String parameterName,
						final Map<String,Object> entrySpec)
		throws ParseException, PolicyViolationException {
		
		return parse(parameterName, entrySpec, DEFAULT_POLICY_OPERATION_FACTORY, DEFAULT_POLICY_COMBINATION_VALIDATOR);
	}
}
