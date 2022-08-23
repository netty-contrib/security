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
import io.netty.contrib.security.core.Tables;
import io.netty5.buffer.api.Buffer;
import io.netty5.buffer.api.BufferAllocator;
import io.netty5.channel.ChannelHandlerContext;
import io.netty5.channel.socket.DatagramChannel;
import io.netty5.channel.socket.DatagramPacket;
import io.netty5.channel.socket.SocketChannel;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StandardNetworkHandlerTest {

    @Test
    void socketChannelActiveAndBufferTest() throws Exception {
        SocketChannel socketChannel = mock(SocketChannel.class);
        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);

        Tables tables = StandardTables.create();
        StandardNetworkHandler standardNetworkHandler = new StandardNetworkHandler(StandardFilter.of(tables, Action.DROP));

        // Mock Addresses because we need them in FiveTuple
        when(socketChannel.localAddress()).thenReturn(new InetSocketAddress("10.10.10.1", 8080));
        when(socketChannel.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.1", 9110));

        // Mock Socket Channel
        when(ctx.channel()).thenReturn(socketChannel);
        when(ctx.channel().close()).thenReturn(null); // No need to return on #close
        when(ctx.fireChannelRead(any())).thenReturn(null);

        // Make call to channelActive and verify Channel#close was executed.
        standardNetworkHandler.channelActive(ctx);
        verify(ctx.channel(), times(1)).close();

        StandardTable table = StandardTable.of(1, "MainTable");
        table.unlock();
        table.addRule(StandardRule.newBuilder()
                .withProtocol(Protocol.TCP)
                .withSourcePorts(StandardPorts.of(9110))
                .withDestinationPorts(StandardPorts.of(8080))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("192.168.1.1")))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("10.10.10.1")))
                .withAction(Action.ACCEPT)
                .build());
        table.lock();
        tables.addTable(table);

        // Since we inserted rule to allow us, lets call channelActive
        // once again and verify Channel#close was called only once.
        standardNetworkHandler.channelActive(ctx);
        verify(ctx.channel(), times(1)).close();

        // ------------------------ Buffer ------------------------

        // Validate Buffer
        Buffer buffer = BufferAllocator.onHeapUnpooled().allocate(1);
        standardNetworkHandler.channelRead(ctx, buffer);
        buffer.close();
        verify(ctx, times(1)).fireChannelRead(any());
    }

    @Test
    void datagramPacketTest() throws Exception {
        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
        DatagramChannel datagramChannel = mock(DatagramChannel.class);

        when(ctx.channel()).thenReturn(datagramChannel);
        when(datagramChannel.isConnected()).thenReturn(false);

        Tables tables = StandardTables.create();
        StandardNetworkHandler standardNetworkHandler = new StandardNetworkHandler(StandardFilter.of(tables, Action.DROP));

        StandardTable table = StandardTable.of(1, "MainTable");
        table.unlock();
        table.addRule(StandardRule.newBuilder()
                .withProtocol(Protocol.UDP)
                .withSourcePorts(StandardPorts.of(9110))
                .withDestinationPorts(StandardPorts.of(8080))
                .withSourceIpAddresses(IpAddresses.create(IpAddress.of("192.168.1.1")))
                .withDestinationIpAddress(IpAddresses.create(IpAddress.of("10.10.10.1")))
                .withAction(Action.ACCEPT)
                .build());
        table.lock();
        tables.addTable(table);

        Buffer buffer = BufferAllocator.onHeapUnpooled()
                .allocate(4)
                .writeCharSequence("Meow", StandardCharsets.UTF_8);

        DatagramPacket datagramPacket = new DatagramPacket(buffer,
                new InetSocketAddress("10.10.10.1", 8080),
                new InetSocketAddress("192.168.1.1", 9111)); // Different port

        // isAccessible will return true because we just created
        // the packet. However, once we pass packet to channelRead
        // it will drop and release the packet because of default action.
        assertTrue(datagramPacket.isAccessible());
        standardNetworkHandler.channelRead(ctx, datagramPacket);
        assertFalse(datagramPacket.isAccessible());

        buffer = BufferAllocator.onHeapUnpooled()
                .allocate(4)
                .writeCharSequence("Meow", StandardCharsets.UTF_8);

        datagramPacket = new DatagramPacket(buffer,
                new InetSocketAddress("10.10.10.1", 8080),
                new InetSocketAddress("192.168.1.1", 9110)); // Allowed port

        assertTrue(datagramPacket.isAccessible());
        standardNetworkHandler.channelRead(ctx, datagramPacket);
        verify(ctx, times(1)).fireChannelRead(any());
        assertTrue(datagramPacket.isAccessible());

        datagramPacket.close();
    }
}
