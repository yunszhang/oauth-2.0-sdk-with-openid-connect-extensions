package com.nimbusds.openid.connect.claims;


/**
 * A locally unique and never reassigned identifier for the end-user, which is
 * intended to be consumed by the client ({@code user_id}).
 *
 * <p>The user identifier cannot exceed {@link #MAX_LENGTH 255 ASCII characters}
 * in length.
 *
 * <p>Example values:
 *
 * <pre>
 * 24400320
 * AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.1 and 2.3.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class UserID extends StringClaim {


	/**
	 * The maximum user identifier length.
	 */
	public static final int MAX_LENGTH = 255;
	
	
	/**
	 * Enumeration of the user identifier types.
	 */
	public static enum Type {
	
	
		/**
		 * Pairwise.
		 */
		PAIRWISE,
		
		
		/**
		 * Public.
		 */
		PUBLIC;
		
		
		/**
		 * Returns the string representation of this user identifier 
		 * type.
		 *
		 * @return The string representation of this user identifier
		 *         type.
		 */
		public String toString() {

			return super.toString().toLowerCase();
		}
	}
	
	
	/**
	 * Checks if the specified string represents a legal user identifier.
	 *
	 * @return value The string to check.
	 *
	 * @return {@code true} if the string is not {@code null}, not empty
	 *         and is less than 256 characters length; else {@code false}.
	 */
	public static boolean isLegal(final String value) {
	
		if (value == null)
			return false;
		
		if (value.trim().isEmpty())
			return false;
			
		if (value.length() > MAX_LENGTH)	
			return false;
			
		return true; // OK
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @return "user_id".
	 */
	@Override
	public String getClaimName() {
	
		return "user_id";
	}
	
	
	/**
	 * Checks if the claim value represents a legal user identifier.
	 *
	 * @return {@code true} if the value is less than 256 characters length;
	 *         else {@code false}.
	 */
	public boolean isLegal() {
	
		return UserID.isLegal(this.getClaimValue());
	}
}
