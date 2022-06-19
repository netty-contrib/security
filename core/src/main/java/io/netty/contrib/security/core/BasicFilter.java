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

import io.netty5.buffer.api.Buffer;
import io.netty5.channel.AddressedEnvelope;
import io.netty5.channel.Channel;
import io.netty5.channel.ChannelHandlerContext;
import io.netty5.channel.socket.DatagramPacket;

/**
 * Filters takes decision for an incoming {@link FiveTuple},
 * {@link AddressedEnvelope} or {@link Buffer}.
 */
public interface BasicFilter extends Filter {

    /**
     * Evaluate a {@link ChannelHandlerContext#fireChannelActive()}
     * and return appropriate {@link Action}
     *
     * @param fiveTuple {@link FiveTuple} instance
     * @return Appropriate {@link Action}
     */
    Action validateChannelActive(FiveTuple fiveTuple);

    /**
     * {@inheritDoc}
     */
    @Override
    default Action validateObject(Object msg, FiveTuple fiveTuple) {
        if (msg instanceof DatagramPacket) {
            return validateDatagramPacket((DatagramPacket) msg, fiveTuple);
        } else if (msg instanceof Buffer) {
            return validateBuffer((Buffer) msg, fiveTuple);
        } else {
            throw new IllegalArgumentException("Unsupported Object: " + msg.getClass().getSimpleName());
        }
    }

    /**
     * Evaluate a {@link AddressedEnvelope} and return appropriate {@link Action}
     *
     * @param datagramPacket {@link DatagramPacket} to evaluate
     * @param fiveTuple      {@link FiveTuple} instance
     * @return Appropriate {@link Action}
     */
    Action validateDatagramPacket(DatagramPacket datagramPacket, FiveTuple fiveTuple);

    /**
     * Evaluate a {@link Channel} and {@link Buffer} and
     * return appropriate {@link Action}
     *
     * @param buffer    {@link Buffer} to evaluate
     * @param fiveTuple {@link FiveTuple} instance
     * @return Appropriate {@link Action}
     */
    Action validateBuffer(Buffer buffer, FiveTuple fiveTuple);
}
