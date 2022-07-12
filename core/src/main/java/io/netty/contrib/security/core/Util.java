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
package io.netty.contrib.security.core;

import io.netty.contrib.security.core.standards.StandardFiveTuple;
import io.netty5.channel.socket.DatagramChannel;
import io.netty5.channel.socket.DatagramPacket;
import io.netty5.channel.socket.SocketChannel;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.Objects;

public final class Util {
    private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

    static int prefixToSubnetMaskV4(int cidrPrefix) {
        return (int) (-1L << 32 - cidrPrefix);
    }

    static BigInteger prefixToSubnetMaskV6(int cidrPrefix) {
        return MINUS_ONE.shiftLeft(128 - cidrPrefix);
    }

    /**
     * Create a new {@link StandardFiveTuple} from {@link SocketChannel}
     *
     * @param socketChannel {@link SocketChannel} to use
     * @return new {@link StandardFiveTuple} instance
     */
    public static FiveTuple generateFiveTupleFrom(SocketChannel socketChannel) {
        Objects.requireNonNull(socketChannel, "SocketChannel");

        if (socketChannel.localAddress() instanceof InetSocketAddress && socketChannel.remoteAddress() instanceof InetSocketAddress) {
            InetSocketAddress local = (InetSocketAddress) socketChannel.localAddress();
            InetSocketAddress remote = (InetSocketAddress) socketChannel.remoteAddress();

            return StandardFiveTuple.from(Protocol.TCP, remote.getPort(), local.getPort(),
                    StaticIpAddress.of(remote.getAddress()), StaticIpAddress.of(local.getAddress()));
        } else {
            throw new IllegalArgumentException("Only InetSocketAddress is accepted");
        }
    }

    /**
     * Create a new {@link StandardFiveTuple} from {@link DatagramChannel}
     *
     * @param datagramChannel {@link DatagramChannel} to use
     * @return new {@link StandardFiveTuple} instance
     */
    public static StandardFiveTuple generateFiveTupleFrom(DatagramChannel datagramChannel) {
        Objects.requireNonNull(datagramChannel, "DatagramChannel");

        if (datagramChannel.localAddress() instanceof InetSocketAddress && datagramChannel.remoteAddress() instanceof InetSocketAddress) {
            InetSocketAddress local = (InetSocketAddress) datagramChannel.localAddress();
            InetSocketAddress remote = (InetSocketAddress) datagramChannel.remoteAddress();

            return StandardFiveTuple.from(Protocol.UDP, remote.getPort(), local.getPort(),
                    StaticIpAddress.of(remote.getAddress()), StaticIpAddress.of(local.getAddress()));
        } else {
            throw new IllegalArgumentException("Only InetSocketAddress is accepted");
        }
    }

    /**
     * Create a new {@link StandardFiveTuple} from {@link DatagramPacket}
     *
     * @param datagramPacket {@link DatagramChannel} to use
     * @return new {@link StandardFiveTuple} instance
     */
    public static StandardFiveTuple generateFiveTupleFrom(DatagramPacket datagramPacket) {
        Objects.requireNonNull(datagramPacket, "DatagramChannel");

        if (datagramPacket.recipient() instanceof InetSocketAddress && datagramPacket.sender() instanceof InetSocketAddress) {
            InetSocketAddress local = (InetSocketAddress) datagramPacket.recipient();
            InetSocketAddress remote = (InetSocketAddress) datagramPacket.sender();

            return StandardFiveTuple.from(Protocol.UDP, remote.getPort(), local.getPort(),
                    StaticIpAddress.of(remote.getAddress()), StaticIpAddress.of(local.getAddress()));
        } else {
            throw new IllegalArgumentException("Only InetSocketAddress is accepted");
        }
    }

    /**
     * Convert Hex {@link String} to byte array
     *
     * @param str Hex string
     * @return byte array
     */
    public static byte[] hexStringToByteArray(String str) {
        int len = str.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return data;
    }
}
