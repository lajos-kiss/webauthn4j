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

package com.webauthn4j.data;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.CoreServerProperty;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class CoreAuthenticationParametersTest {

    @Deprecated
    @Test
    void constructor_without_allowCredentials_test() {
        // Server properties
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        CoreServerProperty serverProperty = new CoreServerProperty(rpId, challenge);

        Authenticator authenticator = mock(Authenticator.class);

        CoreAuthenticationParameters instance =
                new CoreAuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false,
                        true
                );

        assertThat(instance.getServerProperty()).isEqualTo(serverProperty);
        assertThat(instance.getAuthenticator()).isEqualTo(authenticator);
        assertThat(instance.getAllowCredentials()).isNull();
        assertThat(instance.isUserVerificationRequired()).isFalse();
        assertThat(instance.isUserPresenceRequired()).isTrue();
    }

    @Deprecated
    @Test
    void constructor_without_allowCredentials_userPresenceRequired_test() {
        // Server properties
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        CoreServerProperty serverProperty = new CoreServerProperty(rpId, challenge);

        Authenticator authenticator = mock(Authenticator.class);

        CoreAuthenticationParameters instance =
                new CoreAuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false
                );

        assertThat(instance.getServerProperty()).isEqualTo(serverProperty);
        assertThat(instance.getAuthenticator()).isEqualTo(authenticator);
        assertThat(instance.getAllowCredentials()).isNull();
        assertThat(instance.isUserVerificationRequired()).isFalse();
    }

}