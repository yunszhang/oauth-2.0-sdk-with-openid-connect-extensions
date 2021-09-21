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

package com.nimbusds.oauth2.sdk.util;


import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.NotThreadSafe;
import net.minidev.json.JSONObject;


/**
 * Ordered JSON object.
 */
@NotThreadSafe
public class OrderedJSONObject extends JSONObject {
	
	
	private static final long serialVersionUID = -8682025379611131137L;
	
	
	/**
	 * Keeps an ordered copy of the JSON object members.
	 */
	private final Map<String,Object> orderedMap = new LinkedHashMap<>();
	
	
	@Override
	public Object put(final String s, final Object o) {
		orderedMap.put(s, o);
		return super.put(s, o);
	}
	
	
	@Override
	public void putAll(Map<? extends String, ?> map) {
		orderedMap.putAll(map);
		super.putAll(map);
	}
	
	
	@Override
	public Set<String> keySet() {
		return orderedMap.keySet();
	}
	
	
	@Override
	public Set<Entry<String, Object>> entrySet() {
		return orderedMap.entrySet();
	}
	
	
	@Override
	public Object remove(Object o) {
		orderedMap.remove(o);
		return super.remove(o);
	}
	
	
	@Override
	public void clear() {
		orderedMap.clear();
		super.clear();
	}
	
	
	@Override
	public String toJSONString() {
		return JSONObject.toJSONString(orderedMap);
	}
}
