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
import com.webauthn4j.metadata.legacy.data.MetadataItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class AggregatingMetadataItemsProvider implements MetadataItemsProvider {

    private final Logger logger = LoggerFactory.getLogger(AggregatingMetadataItemsProvider.class);

    private final List<MetadataItemsProvider> metadataItemsProviders;

    public AggregatingMetadataItemsProvider(List<MetadataItemsProvider> metadataItemsProviders) {
        this.metadataItemsProviders = metadataItemsProviders;
    }

    @Override
    public Map<AAGUID, Set<MetadataItem>> provide() {
        Map<AAGUID, Set<MetadataItem>> map = new HashMap<>();
        metadataItemsProviders.forEach(provider -> {
            try {
                Map<AAGUID, Set<MetadataItem>> provided = provider.provide();
                provided.keySet().forEach(aaguid -> {
                    map.putIfAbsent(aaguid, new HashSet<>());
                    map.get(aaguid).addAll(provided.get(aaguid));
                });
            } catch (RuntimeException e) {
                logger.warn("Failed to load metadata from one of metadataItemsProviders", e);
            }
        });
        return map;
    }
}
