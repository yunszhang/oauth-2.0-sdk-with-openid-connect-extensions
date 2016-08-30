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
