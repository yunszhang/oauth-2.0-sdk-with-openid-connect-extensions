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


import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.StringListConfiguration;


/**
 * Abstract set based policy operation.
 */
abstract class AbstractSetBasedOperation implements PolicyOperation, StringListConfiguration {
	
	
	/**
	 * The set configuration.
	 */
	protected Set<String> setConfig;
	
	
	@Override
	public void configure(final List<String> parameter) {
		this.setConfig = new LinkedHashSet<>(parameter);
	}
	
	
	@Override
	public void parseConfiguration(final Object jsonEntity) throws ParseException {
		configure(JSONUtils.toStringList(jsonEntity));
	}
	
	
	@Override
	public List<String> getStringListConfiguration() {
		return new LinkedList<>(setConfig);
	}
}
