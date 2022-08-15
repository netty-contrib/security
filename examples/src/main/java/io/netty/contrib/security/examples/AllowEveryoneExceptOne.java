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
import io.netty.contrib.security.core.standards.StandardRuleBuilder;
import io.netty.contrib.security.core.standards.StandardTable;
import io.netty.contrib.security.core.standards.StandardTables;
import io.netty5.bootstrap.ServerBootstrap;
import io.netty5.channel.Channel;
import io.netty5.channel.ChannelHandlerContext;
import io.netty5.channel.ChannelInitializer;
import io.netty5.channel.EventLoopGroup;
import io.netty5.channel.IoHandle;
import io.netty5.channel.IoHandler;
import io.netty5.channel.IoHandlerFactory;
import io.netty5.channel.MultithreadEventLoopGroup;
import io.netty5.channel.SimpleChannelInboundHandler;
import io.netty5.channel.nio.NioHandler;
import io.netty5.channel.socket.ServerSocketChannel;
import io.netty5.channel.socket.SocketChannel;
import io.netty5.channel.socket.nio.NioServerSocketChannel;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;

public final class AllowEveryoneExceptOne {

    private static EventLoopGroup EVENT_LOOP;
    private static Channel channel;

    public static void main(String[] args) throws Exception {
        StandardRule rule = StandardRule.newBuilder()
                .withAction(Action.REJECT)
                .withSourceIpAddresses(IpAddresses.ACCEPT_ANY)
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

        Filter filter = new StandardFilter(tables, Action.REJECT);
        StandardNetworkHandler networkHandler = new StandardNetworkHandler(filter);

        EVENT_LOOP = new MultithreadEventLoopGroup(NioHandler.newFactory());
        ServerBootstrap serverBootstrap = new ServerBootstrap()
                .group(EVENT_LOOP)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel socketChannel) {
                        socketChannel.pipeline().addFirst(networkHandler);
                        socketChannel.pipeline().addLast(new SimpleChannelInboundHandler<>() {
                            @Override
                            public void channelActive(ChannelHandlerContext ctx) {
                                System.out.println("Channel Active: " + ctx);
                            }

                            @Override
                            protected void messageReceived(ChannelHandlerContext ctx, Object o) {
                                System.out.println("Received Message from: " + ctx.channel().remoteAddress());
                            }
                        });
                    }
                });

        channel = serverBootstrap.bind(9110).asStage().get();

        try (Socket socket = new Socket("127.0.0.1", 9110, InetAddress.getByName("127.0.0.2"), 0)) {
            if (socket.isConnected()) {
                System.out.println("Socket Connected");
            }
        } catch (Exception ex) {
            if (ex instanceof SocketException) {
                ex.printStackTrace();
            } else {
                System.err.println(ex.getMessage());
            }
        }
    }
}
