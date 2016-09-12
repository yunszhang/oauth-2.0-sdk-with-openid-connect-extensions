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

package com.nimbusds.oauth2.sdk.auth.verifier;


import net.jcip.annotations.ThreadSafe;


/**
 * Generic context for passing objects.
 */
@ThreadSafe
public class Context<T> {


	/**
	 * The context content.
	 */
	private T o;


	/**
	 * Sets the context content.
	 *
	 * @param o The context content.
	 */
	public void set(final T o) {

		this.o = o;
	}


	/**
	 * Gets the context content.
	 *
	 * @return The context content.
	 */
	public T get() {

		return o;
	}
}
