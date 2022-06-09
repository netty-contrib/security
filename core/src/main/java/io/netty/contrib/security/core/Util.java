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
        return StandardFiveTuple.from(Protocol.TCP, socketChannel.remoteAddress().getPort(), socketChannel.localAddress().getPort(),
                StaticIpAddress.of(socketChannel.remoteAddress().getAddress()), StaticIpAddress.of(socketChannel.localAddress().getAddress()));
    }

    /**
     * Create a new {@link StandardFiveTuple} from {@link DatagramChannel}
     *
     * @param datagramChannel {@link DatagramChannel} to use
     * @return new {@link StandardFiveTuple} instance
     */
    public static StandardFiveTuple generateFiveTupleFrom(DatagramChannel datagramChannel) {
        Objects.requireNonNull(datagramChannel, "DatagramChannel");
        return StandardFiveTuple.from(Protocol.UDP, datagramChannel.remoteAddress().getPort(), datagramChannel.localAddress().getPort(),
                StaticIpAddress.of(datagramChannel.remoteAddress().getAddress()), StaticIpAddress.of(datagramChannel.localAddress().getAddress()));
    }

    /**
     * Create a new {@link StandardFiveTuple} from {@link DatagramPacket}
     *
     * @param datagramPacket {@link DatagramChannel} to use
     * @return new {@link StandardFiveTuple} instance
     */
    public static StandardFiveTuple generateFiveTupleFrom(DatagramPacket datagramPacket) {
        Objects.requireNonNull(datagramPacket, "DatagramChannel");
        return StandardFiveTuple.from(Protocol.UDP, datagramPacket.sender().getPort(), datagramPacket.recipient().getPort(),
                StaticIpAddress.of(datagramPacket.sender().getAddress()), StaticIpAddress.of(datagramPacket.recipient().getAddress()));
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
