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
import io.netty.contrib.security.core.Filter;
import io.netty.contrib.security.core.IpAddress;
import io.netty.contrib.security.core.IpAddresses;
import io.netty.contrib.security.core.Protocol;
import io.netty.contrib.security.core.StaticIpAddress;
import io.netty.contrib.security.core.Table;
import io.netty.contrib.security.core.Tables;
import io.netty5.buffer.api.Buffer;
import io.netty5.buffer.api.BufferAllocator;
import io.netty5.channel.socket.DatagramPacket;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StandardFilterTest {

    @Test
    void validateChannelActive() throws UnknownHostException {
        Table table = StandardTable.of(100, "SimpleTable");
        table.unlock();
        table.addRule(StandardRule.newBuilder()
                .withProtocol(Protocol.TCP)
                .withSourcePorts(StandardPorts.from(22, 22))
                .withDestinationPorts(StandardPorts.from(80, 80))
                .withSourceIpAddresses(IpAddresses.create(StaticIpAddress.of("10.10.10.10")))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("192.168.1.100")))
                .withAction(Action.ACCEPT)
                .build());
        table.lock();

        Tables tables = StandardTables.create();
        tables.addTable(table);

        Filter filter = new StandardFilter(tables, Action.REJECT);
        Action action = filter.validateChannelActive(StandardFiveTuple.from(Protocol.TCP, 23, 80,
                StaticIpAddress.of("10.10.10.10"), StaticIpAddress.of("192.168.1.100")));

        assertEquals(Action.REJECT, action);

        action = filter.validateChannelActive(StandardFiveTuple.from(Protocol.TCP, 22, 80,
                StaticIpAddress.of("10.10.10.10"), StaticIpAddress.of("192.168.1.100")));

        assertEquals(Action.ACCEPT, action);
    }

    @Test
    void validateDatagramPacket() throws UnknownHostException {
        Table table = StandardTable.of(100, "SimpleTable");
        table.unlock();
        table.addRule(StandardRule.newBuilder()
                .withProtocol(Protocol.UDP)
                .withSourcePorts(StandardPorts.from(22, 22))
                .withDestinationPorts(StandardPorts.from(80, 80))
                .withSourceIpAddresses(IpAddresses.create(StaticIpAddress.of("10.10.10.10")))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("192.168.1.100")))
                .withAction(Action.ACCEPT)
                .build());
        table.lock();

        Tables tables = StandardTables.create();
        tables.addTable(table);

        Filter filter = new StandardFilter(tables, Action.REJECT);
        DatagramPacket packet = new DatagramPacket(BufferAllocator.onHeapUnpooled().allocate(0),
                new InetSocketAddress("192.168.1.100", 80), new InetSocketAddress("10.10.10.2", 22));
        Action action = filter.validateObject(packet, StandardFiveTuple.from(Protocol.UDP, 22, 80,
                StaticIpAddress.of("10.10.10.10"), StaticIpAddress.of("192.168.1.100")));

        assertEquals(Action.ACCEPT, action);

        packet = new DatagramPacket(BufferAllocator.onHeapUnpooled().allocate(0),
                new InetSocketAddress("192.168.1.100", 80), new InetSocketAddress("10.10.10.2", 22));
        action = filter.validateObject(packet, StandardFiveTuple.from(Protocol.UDP, 10000, 80,
                StaticIpAddress.of("10.10.10.10"), StaticIpAddress.of("192.168.1.100")));

        assertEquals(Action.REJECT, action);
    }

    @Test
    void validateBuffer() throws UnknownHostException {
        Table table = StandardTable.of(100, "SimpleTable");
        table.unlock();
        table.addRule(StandardRule.newBuilder()
                .withProtocol(Protocol.TCP)
                .withSourcePorts(StandardPorts.from(22, 22))
                .withDestinationPorts(StandardPorts.from(80, 80))
                .withSourceIpAddresses(IpAddresses.create(StaticIpAddress.of("10.10.10.10")))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("192.168.1.100")))
                .withAction(Action.ACCEPT)
                .build());
        table.lock();

        Tables tables = StandardTables.create();
        tables.addTable(table);

        Filter filter = new StandardFilter(tables, Action.REJECT);
        Buffer buffer = BufferAllocator.onHeapUnpooled().allocate(0);
        Action action = filter.validateObject(buffer, StandardFiveTuple.from(Protocol.TCP, 22, 80,
                StaticIpAddress.of("10.10.10.10"), StaticIpAddress.of("192.168.1.100")));

        assertEquals(Action.ACCEPT, action);

        buffer = BufferAllocator.onHeapUnpooled().allocate(0);
        action = filter.validateObject(buffer, StandardFiveTuple.from(Protocol.TCP, 10000, 80,
                StaticIpAddress.of("10.10.10.10"), StaticIpAddress.of("192.168.1.100")));

        assertEquals(Action.REJECT, action);
    }
}
