package com.webauthn4j.webauthn.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.webauthn.attestation.WebAuthnAttestationObject;
import com.webauthn4j.webauthn.util.jackson.WebAuthnModule;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Base64;

public class WebAuthnAttestationObjectConverter {

    private ObjectMapper objectMapper;

    public WebAuthnAttestationObjectConverter() {
        objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
    }

    public WebAuthnAttestationObject convert(String source) {
        byte[] value = java.util.Base64.getUrlDecoder().decode(source);
        return convert(value);
    }

    public WebAuthnAttestationObject convert(byte[] source){
        try {
            return objectMapper.readValue(source, WebAuthnAttestationObject.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convert(WebAuthnAttestationObject source) {
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(source);
            return Base64.getUrlEncoder().encodeToString(bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
