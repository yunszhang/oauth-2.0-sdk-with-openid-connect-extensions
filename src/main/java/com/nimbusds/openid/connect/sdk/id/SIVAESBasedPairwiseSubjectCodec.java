package com.nimbusds.openid.connect.sdk.id;


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.id.Subject;
import net.jcip.annotations.ThreadSafe;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.cryptomator.siv.SivMode;


/**
 * SIV AES - based encoder / decoder of pairwise subject identifiers. Requires
 * a 256, 384, or 512-bit secret key. Reversal is supported.
 *
 * <p>The plain text is formatted as follows ('|' as delimiter):
 *
 * <pre>
 * sector_id|local_sub
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Synthetic Initialization Vector (SIV) Authenticated Encryption Using
 *         the Advanced Encryption Standard (AES) (RFC 5297).
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
@ThreadSafe
public class SIVAESBasedPairwiseSubjectCodec extends PairwiseSubjectCodec {
	
	
	/**
	 * The AES SIV crypto engine.
	 */
	private static final SivMode AES_SIV = new SivMode();
	
	
	/**
	 * The AES CTR key (1st half).
	 */
	private final byte[] aesCtrKey;
	
	
	/**
	 * The MAC key (2nd half).
	 */
	private final byte[] macKey;
	
	
	/**
	 * Creates a new SIV AES - based codec for pairwise subject
	 * identifiers.
	 *
	 * @param secretKey A 256, 384, or 512-bit secret key. Must not be
	 *                  {@code null}.
	 */
	public SIVAESBasedPairwiseSubjectCodec(final SecretKey secretKey) {
		super(null);
		if (secretKey == null) {
			throw new IllegalArgumentException("The SIV AES secret key must not be null");
		}
		
		byte[] keyBytes = secretKey.getEncoded();
		
		switch (keyBytes.length) {
			case 32:
				aesCtrKey = ByteUtils.subArray(keyBytes, 0, 16);
				macKey = ByteUtils.subArray(keyBytes, 16, 16);
				break;
			case 48:
				aesCtrKey = ByteUtils.subArray(keyBytes, 0, 24);
				macKey = ByteUtils.subArray(keyBytes, 24, 24);
				break;
			case 64:
				aesCtrKey = ByteUtils.subArray(keyBytes, 0, 32);
				macKey = ByteUtils.subArray(keyBytes, 32, 32);
				break;
			default:
				throw new IllegalArgumentException("The SIV AES secret key length must be 256, 384 or 512 bits");
		}
	}
	
	
	/**
	 * Returns the secret key.
	 *
	 * @return The key.
	 */
	public SecretKey getSecretKey() {
		
		return new SecretKeySpec(ByteUtils.concat(aesCtrKey, macKey), "AES");
	}
	
	
	@Override
	public Subject encode(final SectorID sectorID, final Subject localSub) {
		
		// Join parameters, delimited by '\'
		byte[] plainText = (sectorID.getValue().replace("|", "\\|") + '|' + localSub.getValue().replace("|", "\\|")).getBytes(CHARSET);
		byte[] cipherText = AES_SIV.encrypt(aesCtrKey, macKey, plainText);
		return new Subject(Base64URL.encode(cipherText).toString());
	}
	
	
	@Override
	public Pair<SectorID, Subject> decode(final Subject pairwiseSubject)
		throws InvalidPairwiseSubjectException {
		
		byte[] cipherText = new Base64URL(pairwiseSubject.getValue()).decode();
		
		byte[] plainText;
		try {
			plainText  = AES_SIV.decrypt(aesCtrKey, macKey, cipherText);
		} catch (Exception e) {
			throw new InvalidPairwiseSubjectException("Decryption failed: " + e.getMessage(), e);
		}
		
		String parts[] = new String(plainText, CHARSET).split("(?<!\\\\)\\|");
		
		// Unescape delimiter
		for (int i=0; i<parts.length; i++) {
			parts[i] = parts[i].replace("\\|", "|");
		}
		
		// Check format
		if (parts.length != 2) {
			throw new InvalidPairwiseSubjectException("Invalid format: Unexpected number of tokens: " + parts.length);
		}
		
		return new ImmutablePair<>(new SectorID(parts[0]), new Subject(parts[1]));
	}
}
