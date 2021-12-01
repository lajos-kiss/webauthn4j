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

package com.webauthn4j.metadata.validator;

import com.webauthn4j.data.AuthenticatorAttestationType;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.metadata.MetadataBLOBProvider;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.toc.StatusReport;
import com.webauthn4j.metadata.exception.BadStatusException;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.CustomRegistrationValidator;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.BadAttestationStatementException;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class FidoMDS3BasedAttestationValidator implements CustomRegistrationValidator {

    private final MetadataBLOBProvider metadataBLOBProvider;
    private boolean notFidoCertifiedAllowed = false;
    private boolean selfAssertionSubmittedAllowed = false;

    private FidoMDS3BasedAttestationValidator(MetadataBLOBProvider metadataBLOBProvider){
        this.metadataBLOBProvider = metadataBLOBProvider;
    }

    public boolean isNotFidoCertifiedAllowed() {
        return notFidoCertifiedAllowed;
    }

    public void setNotFidoCertifiedAllowed(boolean notFidoCertifiedAllowed) {
        this.notFidoCertifiedAllowed = notFidoCertifiedAllowed;
    }

    public boolean isSelfAssertionSubmittedAllowed() {
        return selfAssertionSubmittedAllowed;
    }

    public void setSelfAssertionSubmittedAllowed(boolean selfAssertionSubmittedAllowed) {
        this.selfAssertionSubmittedAllowed = selfAssertionSubmittedAllowed;
    }

    @Override
    public void validate(RegistrationObject registrationObject) {

        AssertUtil.notNull(registrationObject.getAttestationObject().getAuthenticatorData(), "authenticatorData must not be null");
        AssertUtil.notNull(registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(), "attestedCredentialData must not be null");

        AAGUID aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();

        Set<MetadataBLOBPayloadEntry> entries = resolve(aaguid);

        List<AuthenticatorAttestationType> authenticatorAttestationTypes = entries.stream()
                .flatMap(item -> item.getMetadataStatement().getAttestationTypes().stream()).collect(Collectors.toList());

        boolean isSurrogate = !authenticatorAttestationTypes.isEmpty() &&
                authenticatorAttestationTypes.stream().allMatch(type -> type.equals(AuthenticatorAttestationType.BASIC_SURROGATE));

        if (isSurrogate && attestationStatement instanceof CertificateBaseAttestationStatement) {
            CertificateBaseAttestationStatement certificateBaseAttestationStatement = (CertificateBaseAttestationStatement) attestationStatement;
            if (certificateBaseAttestationStatement.getX5c() != null) {
                throw new BadAttestationStatementException("Although AAGUID is registered for surrogate attestation in metadata, x5c contains certificates.");
            }
        }

        for (MetadataBLOBPayloadEntry entry : entries) {
            validateStatusReports(entry.getStatusReports());
        }
    }

    protected void validateStatusReports(List<StatusReport> statusReports) {
        statusReports.forEach(report -> {
            switch (report.getStatus()) {
                //Info statuses
                case UPDATE_AVAILABLE:
                    // UPDATE_AVAILABLE itself doesn't mean security issue. If security related update is available,
                    // corresponding status report is expected to be added to the report list.
                    break;

                //Certification Related statuses
                case FIDO_CERTIFIED:
                case FIDO_CERTIFIED_L1:
                case FIDO_CERTIFIED_L1_PLUS:
                case FIDO_CERTIFIED_L2:
                case FIDO_CERTIFIED_L2_PLUS:
                case FIDO_CERTIFIED_L3:
                case FIDO_CERTIFIED_L3_PLUS:
                    break;
                case NOT_FIDO_CERTIFIED:
                    if (notFidoCertifiedAllowed) {
                        break;
                    } else {
                        throw new BadStatusException(String.format("FIDO Metadata Service reported `%s` for this authenticator.", report.getStatus()));
                    }
                case SELF_ASSERTION_SUBMITTED:
                    if (selfAssertionSubmittedAllowed) {
                        break;
                    } else {
                        throw new BadStatusException(String.format("FIDO Metadata Service reported `%s` for this authenticator.", report.getStatus()));
                    }

                    // Security Notification statuses
                case ATTESTATION_KEY_COMPROMISE:
                case USER_VERIFICATION_BYPASS:
                case USER_KEY_REMOTE_COMPROMISE:
                case USER_KEY_PHYSICAL_COMPROMISE:
                case REVOKED:
                default:
                    throw new BadStatusException(String.format("FIDO Metadata Service reported `%s` for this authenticator.", report.getStatus()));
            }
        });
    }


    private Set<MetadataBLOBPayloadEntry> resolve(AAGUID aaguid) {
        return metadataBLOBProvider.provide().getPayload().getEntries().stream()
                .collect(Collectors.toMap(
                        MetadataBLOBPayloadEntry::getAaguid,
                        Collections::singleton
                )).get(aaguid);
    }

}
