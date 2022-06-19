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
import io.netty.contrib.security.core.IpAddress;
import io.netty.contrib.security.core.IpAddresses;
import io.netty.contrib.security.core.Protocol;
import io.netty.contrib.security.core.StaticIpAddress;
import io.netty.contrib.security.core.payload.BufferPayload;
import io.netty5.buffer.api.Buffer;
import io.netty5.buffer.api.BufferAllocator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandardRuleTest {

    @Test
    void newBuilder() {
        assertNotNull(StandardRule.newBuilder());
        assertInstanceOf(StandardRuleBuilder.class, StandardRule.newBuilder());
    }

    @Test
    void protocol() {
        {
            StandardRule standardRule = StandardRule.newBuilder(true)
                    .withProtocol(Protocol.TCP)
                    .withSourcePorts(StandardPorts.from(5000, 10000))
                    .withDestinationPorts(StandardPorts.from(2221, 2223))
                    .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 32)))
                    .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                    .withAction(Action.DROP)
                    .build();

            assertEquals(Protocol.TCP, standardRule.protocol());
        }
        {
            StandardRule standardRule = StandardRule.newBuilder(true)
                    .withProtocol(Protocol.UDP)
                    .withSourcePorts(StandardPorts.from(5000, 10000))
                    .withDestinationPorts(StandardPorts.from(2221, 2223))
                    .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 32)))
                    .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                    .withAction(Action.DROP)
                    .build();

            assertEquals(Protocol.UDP, standardRule.protocol());
        }
        {
            StandardRule standardRule = StandardRule.newBuilder(true)
                    .withProtocol(Protocol.UDP)
                    .withSourcePorts(StandardPorts.from(5000, 10000))
                    .withDestinationPorts(StandardPorts.from(2221, 2223))
                    .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 32)))
                    .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                    .withAction(Action.DROP)
                    .build();

            assertNotEquals(Protocol.TCP, standardRule.protocol());
        }
    }

    @Test
    void sourcePorts() {
        StandardRule standardRule = StandardRule.newBuilder(true)
                .withProtocol(Protocol.UDP)
                .withSourcePorts(StandardPorts.from(5000, 10000))
                .withDestinationPorts(StandardPorts.from(2221, 2223))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 32)))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                .withAction(Action.DROP)
                .build();

        assertTrue(standardRule.sourcePorts().lookupPort(5555));
    }

    @Test
    void destinationPorts() {
        StandardRule standardRule = StandardRule.newBuilder(true)
                .withProtocol(Protocol.UDP)
                .withSourcePorts(StandardPorts.from(5000, 10000))
                .withDestinationPorts(StandardPorts.from(2221, 2223))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 32)))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                .withAction(Action.DROP)
                .build();

        assertTrue(standardRule.destinationPorts().lookupPort(2222));
    }

    @Test
    void sourceIpAddresses() throws Exception {
        StandardRule standardRule = StandardRule.newBuilder(true)
                .withProtocol(Protocol.UDP)
                .withSourcePorts(StandardPorts.from(5000, 10000))
                .withDestinationPorts(StandardPorts.from(2221, 2223))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 24)))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                .withAction(Action.DROP)
                .build();

        assertTrue(standardRule.sourceIpAddresses().lookupAddress(StaticIpAddress.of("10.10.10.1")));
        assertTrue(standardRule.sourceIpAddresses().lookupAddress(StaticIpAddress.of("10.10.10.200")));
        assertTrue(standardRule.sourceIpAddresses().lookupAddress(StaticIpAddress.of("10.10.10.255")));
    }

    @Test
    void destinationIpAddresses() throws Exception {
        StandardRule standardRule = StandardRule.newBuilder(true)
                .withProtocol(Protocol.UDP)
                .withSourcePorts(StandardPorts.from(5000, 10000))
                .withDestinationPorts(StandardPorts.from(2221, 2223))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 24)))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("192.168.10.10", 24)))
                .withAction(Action.DROP)
                .build();

        assertTrue(standardRule.destinationIpAddresses().lookupAddress(StaticIpAddress.of("192.168.10.1")));
        assertTrue(standardRule.destinationIpAddresses().lookupAddress(StaticIpAddress.of("192.168.10.10")));
        assertTrue(standardRule.destinationIpAddresses().lookupAddress(StaticIpAddress.of("192.168.10.100")));
        assertTrue(standardRule.destinationIpAddresses().lookupAddress(StaticIpAddress.of("192.168.10.255")));
    }

    @Test
    void matchPayload() {
        Buffer justWord = BufferAllocator.onHeapUnpooled().copyOf("cat".getBytes());
        BufferPayload bufferPayload = StandardBufferPayload.create(justWord);

        StandardRule standardRule = StandardRule.newBuilder(true)
                .withProtocol(Protocol.UDP)
                .withSourcePorts(StandardPorts.from(5000, 10000))
                .withDestinationPorts(StandardPorts.from(2221, 2223))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 24)))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("192.168.10.10", 24)))
                .withPayloadMatcher(new StandardPayloadMatcher())
                .withPayloads(List.of(bufferPayload))
                .withAction(Action.ACCEPT)
                .build();

        assertEquals(bufferPayload, standardRule.payloads().get(0));
    }

    @Test
    void action() {
        {
            StandardRule standardRule = StandardRule.newBuilder(true)
                    .withProtocol(Protocol.TCP)
                    .withSourcePorts(StandardPorts.from(5000, 10000))
                    .withDestinationPorts(StandardPorts.from(2221, 2223))
                    .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 32)))
                    .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                    .withAction(Action.DROP)
                    .build();

            assertEquals(Action.DROP, standardRule.action());
        }
        {
            StandardRule standardRule = StandardRule.newBuilder(true)
                    .withProtocol(Protocol.UDP)
                    .withSourcePorts(StandardPorts.from(5000, 10000))
                    .withDestinationPorts(StandardPorts.from(2221, 2223))
                    .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 32)))
                    .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                    .withAction(Action.ACCEPT)
                    .build();

            assertEquals(Action.ACCEPT, standardRule.action());
        }
    }

    @Test
    void compareTo() {
        StandardRule standardRule = StandardRule.newBuilder(true)
                .withProtocol(Protocol.TCP)
                .withSourcePorts(StandardPorts.from(5000, 10000))
                .withDestinationPorts(StandardPorts.from(2221, 2223))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 24)))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                .withAction(Action.DROP)
                .build();

        StandardRule standardRule2 = StandardRule.newBuilder(true)
                .withProtocol(Protocol.TCP)
                .withSourcePorts(StandardPorts.from(5000, 10001))
                .withDestinationPorts(StandardPorts.from(2221, 2223))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("10.10.10.10", 24)))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("0.0.0.0", 0)))
                .withAction(Action.DROP)
                .build();

        assertEquals(1, standardRule.compareTo(standardRule2));
    }
}
