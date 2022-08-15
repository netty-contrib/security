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
package io.netty.contrib.security.examples;

import io.netty.contrib.security.core.Action;
import io.netty.contrib.security.core.Filter;
import io.netty.contrib.security.core.IpAddresses;
import io.netty.contrib.security.core.Ports;
import io.netty.contrib.security.core.Protocol;
import io.netty.contrib.security.core.StaticIpAddress;
import io.netty.contrib.security.core.Table;
import io.netty.contrib.security.core.standards.StandardFilter;
import io.netty.contrib.security.core.standards.StandardNetworkHandler;
import io.netty.contrib.security.core.standards.StandardRule;
import io.netty.contrib.security.core.standards.StandardTable;
import io.netty.contrib.security.core.standards.StandardTables;
import io.netty5.bootstrap.ServerBootstrap;
import io.netty5.channel.ChannelHandlerContext;
import io.netty5.channel.ChannelInitializer;
import io.netty5.channel.EventLoopGroup;
import io.netty5.channel.MultithreadEventLoopGroup;
import io.netty5.channel.SimpleChannelInboundHandler;
import io.netty5.channel.nio.NioHandler;
import io.netty5.channel.socket.SocketChannel;
import io.netty5.channel.socket.nio.NioServerSocketChannel;

import java.net.InetAddress;
import java.net.Socket;

public final class AllowEveryoneExceptOne {

    public static void main(String[] args) throws Exception {
        EventLoopGroup eventLoopGroup = new MultithreadEventLoopGroup(NioHandler.newFactory());
        try {
            StandardRule rule = StandardRule.newBuilder()
                    .withAction(Action.REJECT)
                    .withSourceIpAddresses(IpAddresses.create(StaticIpAddress.of("127.0.0.2")))
                    .withSourcePorts(Ports.ANY_PORT)
                    .withDestinationPorts(Ports.ANY_PORT)
                    .withDestinationIpAddress(IpAddresses.ACCEPT_ANY)
                    .withProtocol(Protocol.TCP)
                    .build();

            Table table = StandardTable.of(1, "SimpleTable");
            table.unlock();
            table.addRule(rule);
            table.lock();

            StandardTables tables = StandardTables.create();
            tables.addTable(table);

            Filter filter = new StandardFilter(tables, Action.ACCEPT);
            StandardNetworkHandler networkHandler = new StandardNetworkHandler(filter);

            ServerBootstrap serverBootstrap = new ServerBootstrap()
                    .group(eventLoopGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel socketChannel) {
                            socketChannel.pipeline().addFirst(networkHandler);
                            socketChannel.pipeline().addLast(new SimpleChannelInboundHandler<>() {
                                @Override
                                public void channelActive(ChannelHandlerContext ctx) {
                                    throw new IllegalStateException("This channel should never be active");
                                }

                                @Override
                                protected void messageReceived(ChannelHandlerContext ctx, Object o) {
                                    System.out.println("Received Message from: " + ctx.channel().remoteAddress());
                                }
                            });
                        }
                    });

            serverBootstrap.bind(9110).asStage().get();

            try (Socket socket = new Socket("127.0.0.1", 9110, InetAddress.getByName("127.0.0.2"), 0)) {
                if (socket.isConnected()) {
                    System.out.println("Socket Connected");
                } else {
                    System.out.println("Connection not established yet");
                }

                Thread.sleep(1000 * 5); // Wait for 5 seconds before checking connection status

                assert socket.isClosed() : "SocketState";
                System.out.println("Socket Closed");
            }
        } finally {
            eventLoopGroup.shutdownGracefully();
        }
    }
}
