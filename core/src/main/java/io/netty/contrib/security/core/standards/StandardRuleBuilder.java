/*
 * Copyright 2022 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.contrib.security.core.standards;

import io.netty.contrib.security.core.Action;
import io.netty.contrib.security.core.IpAddresses;
import io.netty.contrib.security.core.Ports;
import io.netty.contrib.security.core.Protocol;
import io.netty.contrib.security.core.payload.Payload;
import io.netty.contrib.security.core.payload.PayloadMatcher;

import java.util.List;

public final class StandardRuleBuilder {
    private Protocol protocol;
    private Ports sourcePorts;
    private Ports destinationPorts;
    private IpAddresses sourceIpAddresses;
    private IpAddresses destinationIpAddress;
    private List<Payload<?>> payloads;
    private PayloadMatcher<Object, Object> payloadMatcher;
    private Action action;

    /**
     * Create a new {@link StandardRuleBuilder} instance
     */
    StandardRuleBuilder() {
        this(false);
    }

    /**
     * Create a new {@link StandardRuleBuilder} instance
     *
     * @param acceptAny Set to {@link Boolean#TRUE} to accept any port, ip address or payload.
     */
    StandardRuleBuilder(boolean acceptAny) {
        // Package access only
        if (acceptAny) {
            sourcePorts = Ports.ANY_PORT;
            destinationPorts = Ports.ANY_PORT;
            sourceIpAddresses = IpAddresses.ACCEPT_ANY;
            destinationIpAddress = IpAddresses.ACCEPT_ANY;
            payloads = List.of(Payload.NULL_PAYLOAD);
            payloadMatcher = PayloadMatcher.ANY_PAYLOAD;
        }
    }

    public StandardRuleBuilder withProtocol(Protocol protocol) {
        this.protocol = protocol;
        return this;
    }

    public StandardRuleBuilder withSourcePorts(Ports sourcePorts) {
        this.sourcePorts = sourcePorts;
        return this;
    }

    public StandardRuleBuilder withDestinationPorts(Ports destinationPorts) {
        this.destinationPorts = destinationPorts;
        return this;
    }

    public StandardRuleBuilder withSourceIpAddresses(IpAddresses sourceIpAddresses) {
        this.sourceIpAddresses = sourceIpAddresses;
        return this;
    }

    public StandardRuleBuilder withDestinationIpAddress(IpAddresses destinationIpAddress) {
        this.destinationIpAddress = destinationIpAddress;
        return this;
    }

    public StandardRuleBuilder withPayloads(List<Payload<?>> payloads) {
        this.payloads = payloads;
        return this;
    }

    public StandardRuleBuilder withPayloadMatcher(PayloadMatcher<Object, Object> payloadMatcher) {
        this.payloadMatcher = payloadMatcher;
        return this;
    }

    public StandardRuleBuilder withAction(Action action) {
        this.action = action;
        return this;
    }

    /**
     * Build new {@link StandardRule} instance
     */
    public StandardRule build() {
        return new StandardRule(protocol, sourcePorts, destinationPorts, sourceIpAddresses, destinationIpAddress,
                payloads, payloadMatcher, action);
    }
}
