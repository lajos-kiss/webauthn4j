/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.authenticator;

import com.webauthn4j.request.AuthenticatorTransport;
import com.webauthn4j.response.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.response.attestation.statement.AttestationStatement;

import java.io.Serializable;
import java.util.Set;

/**
 * WebAuthn Authenticator
 */
public interface Authenticator extends Serializable {

    AttestedCredentialData getAttestedCredentialData();

    AttestationStatement getAttestationStatement();

    Set<AuthenticatorTransport> getTransports();

    long getCounter();

    void setCounter(long value);

}
