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

package com.nimbusds.oauth2.sdk.ciba;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;

/**
 * Modes of authentication through the backchannel
 *
 */
@Immutable
public final class BackChannelTokenDeliveryMode extends Identifier {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7661605920720830935L;
	/**
	 * When configured in Push mode, the OP will send a request with the tokens to a
	 * callback URI previously registered by the Client.
	 */
	public static final BackChannelTokenDeliveryMode PUSH = new BackChannelTokenDeliveryMode("push");
	/**
	 * When configured in Poll mode, the Client will poll the token endpoint to get
	 * a response with the tokens.
	 */
	public static final BackChannelTokenDeliveryMode POLL = new BackChannelTokenDeliveryMode("poll");

	/**
	 * When configured in Ping mode, the OP will send a request to a callback URI
	 * previously registered by the Client with the unique identifier returned from
	 * the Backchannel Authentication Endpoint. Upon receipt of the notification,
	 * the Client makes a request to the token endpoint to obtain the tokens.
	 */
	public static final BackChannelTokenDeliveryMode PING = new BackChannelTokenDeliveryMode("ping");

	/**
	 * Creates a new Backchannel Token Delivery Mode response mode with the
	 * specified value.
	 *
	 * @param value The response mode value. Must not be {@code null}.
	 */
	public BackChannelTokenDeliveryMode(final String value) {

		super(value);
	}

	@Override
	public boolean equals(final Object object) {

		return object instanceof BackChannelTokenDeliveryMode && this.toString().equals(object.toString());
	}

	/**
	 * Converts the string representation of a delivery mode into typed
	 * BackChannelTokenDeliveryMode or throws Illegal Argument Exception if the type
	 * is invalid.
	 * 
	 * @param backChannelTokenDeliveryMode - the string representation of the token
	 *                                     delivery mode (ping, pull or push)
	 * @return parsed BackChannelTokenDeliveryMode or throws Illegal Argument
	 *         Exception if the type is invalid.
	 */
	public static BackChannelTokenDeliveryMode parse(final String backChannelTokenDeliveryMode) {
		if (PING.getValue().equals(backChannelTokenDeliveryMode)) {
			return PING;
		} else if (POLL.getValue().equals(backChannelTokenDeliveryMode)) {
			return POLL;
		} else if (PUSH.getValue().equals(backChannelTokenDeliveryMode)) {
			return PUSH;
		} else {
			throw new IllegalArgumentException("Invalid BackChannel Token Delivery Mode");
		}
	}
}
