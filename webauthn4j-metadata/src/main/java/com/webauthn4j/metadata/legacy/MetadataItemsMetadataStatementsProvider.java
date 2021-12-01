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

package com.webauthn4j.metadata.legacy;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.legacy.MetadataItemsProvider;
import com.webauthn4j.metadata.legacy.MetadataStatementsProvider;
import com.webauthn4j.metadata.legacy.data.MetadataItem;
import com.webauthn4j.metadata.legacy.data.statement.MetadataStatement;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class MetadataItemsMetadataStatementsProvider implements MetadataStatementsProvider {

    private final MetadataItemsProvider metadataItemsProvider;

    public MetadataItemsMetadataStatementsProvider(MetadataItemsProvider metadataItemsProvider) {
        this.metadataItemsProvider = metadataItemsProvider;
    }

    @Override
    public Map<AAGUID, Set<MetadataStatement>> provide() {
        return metadataItemsProvider.provide().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().stream().map(MetadataItem::getMetadataStatement).collect(Collectors.toSet())
                ));
    }
}
