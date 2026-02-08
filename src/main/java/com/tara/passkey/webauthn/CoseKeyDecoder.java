package com.tara.passkey.webauthn;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import java.security.PublicKey;

public final class CoseKeyDecoder {
    private static final ObjectConverter CONVERTER = new ObjectConverter();

    private CoseKeyDecoder() {
    }

    public static COSEKey decode(byte[] coseKeyBytes) {
        return CONVERTER.getCborConverter().readValue(coseKeyBytes, COSEKey.class);
    }

    public static PublicKey decodePublicKey(byte[] coseKeyBytes) {
        return decode(coseKeyBytes).getPublicKey();
    }
}
