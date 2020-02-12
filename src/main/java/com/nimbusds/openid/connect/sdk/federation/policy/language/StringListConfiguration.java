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


import java.util.List;


/**
 * String list configuration.
 */
public interface StringListConfiguration extends PolicyConfiguration {
	
	
	/**
	 * Configures.
	 *
	 * @param parameter The string list configuration parameter. Must not
	 *                  be {@code null}.
	 */
	void configure(final List<String> parameter);
	
	
	/**
	 * Gets the string list configuration.
	 *
	 * @return The string list configuration parameter.
	 */
	List<String> getStringListConfiguration();
}
