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

package com.nimbusds.openid.connect.sdk.assurance;


import java.util.Objects;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Identity assurance process.
 */
@Immutable
public final class IdentityAssuranceProcess {
	
	
	/**
	 * The policy.
	 */
	private final Policy policy;
	
	
	/**
	 * The procedure.
	 */
	private final Procedure procedure;
	
	
	/**
	 * The status.
	 */
	private final Status status;
	
	
	/**
	 * Creates a new identity assurance process. At least one assurance
	 * process element must be specified.
	 *
	 * @param policy    The policy, {@code null} if not specified.
	 * @param procedure The procedure, {@code null} if not specified.
	 * @param status    The status, {@code null} if not specified.
	 */
	public IdentityAssuranceProcess(final Policy policy,
					final Procedure procedure,
					final Status status) {
		
		if (policy == null && procedure == null && status == null) {
			throw new IllegalArgumentException("At least one assurance process element must be specified");
		}
		
		this.policy = policy;
		this.procedure = procedure;
		this.status = status;
	}
	
	
	/**
	 * Returns the policy.
	 *
	 * @return The policy, {@code null} if not specified.
	 */
	public Policy getPolicy() {
		return policy;
	}
	
	
	/**
	 * Returns the procedure.
	 *
	 * @return The procedure, {@code null} if not specified.
	 */
	public Procedure getProcedure() {
		return procedure;
	}
	
	
	/**
	 * Returns the status.
	 *
	 * @return The status, {@code null} if not specified.
	 */
	public Status getStatus() {
		return status;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof IdentityAssuranceProcess)) return false;
		IdentityAssuranceProcess that = (IdentityAssuranceProcess) o;
		return Objects.equals(getPolicy(), that.getPolicy()) && Objects.equals(getProcedure(), that.getProcedure()) && Objects.equals(getStatus(), that.getStatus());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getPolicy(), getProcedure(), getStatus());
	}
	
	
	/**
	 * Returns a JSON object representation of this identity assurance
	 * process.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (policy != null) {
			o.put("policy", policy.getValue());
		}
		if (procedure != null) {
			o.put("procedure", procedure.getValue());
		}
		if (status != null) {
			o.put("status", status.getValue());
		}
		return o;
	}
	
	
	/**
	 * Parses an identity assurance process from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The identity assurance process.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IdentityAssuranceProcess parse(final JSONObject jsonObject)
		throws ParseException {
		
		Policy policy = null;
		String value = JSONObjectUtils.getString(jsonObject, "policy", null);
		if (StringUtils.isNotBlank(value)) {
			policy = new Policy(value);
		}
		
		Procedure procedure = null;
		value = JSONObjectUtils.getString(jsonObject, "procedure", null);
		if (StringUtils.isNotBlank(value)) {
			procedure = new Procedure(value);
		}
		
		Status status = null;
		value = JSONObjectUtils.getString(jsonObject, "status", null);
		if (StringUtils.isNotBlank(value)) {
			status = new Status(value);
		}
		
		try {
			return new IdentityAssuranceProcess(policy, procedure, status);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}
