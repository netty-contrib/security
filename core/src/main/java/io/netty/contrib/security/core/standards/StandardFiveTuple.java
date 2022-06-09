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

import io.netty.contrib.security.core.Address;
import io.netty.contrib.security.core.FiveTuple;
import io.netty.contrib.security.core.Protocol;
import io.netty5.util.internal.ObjectUtil;

import java.util.Objects;

public class StandardFiveTuple implements FiveTuple {
    private final Protocol protocol;
    private final int sourcePort;
    private final int destinationPort;
    private final Address sourceIpAddress;
    private final Address destinationIpAddress;

    private StandardFiveTuple(Protocol protocol, int sourcePort, int destinationPort, Address sourceIpAddress, Address destinationIpAddress) {
        this.protocol = Objects.requireNonNull(protocol, "Protocol");
        this.sourcePort = ObjectUtil.checkInRange(sourcePort, 1, 65_535, "SourcePort");
        this.destinationPort = ObjectUtil.checkInRange(destinationPort, 1, 65_535, "DestinationPort");
        this.sourceIpAddress = Objects.requireNonNull(sourceIpAddress, "SourceIPAddress");
        this.destinationIpAddress = Objects.requireNonNull(destinationIpAddress, "DestinationIPAddress");
    }

    /**
     * Create a new {@link StandardFiveTuple}
     *
     * @param protocol             {@link Protocol} type
     * @param sourcePort           Source Port
     * @param destinationPort      Destination Port
     * @param sourceIpAddress      Source IP Address
     * @param destinationIpAddress Destination IP Address
     * @return new {@link StandardFiveTuple} instance
     */
    public static StandardFiveTuple from(Protocol protocol, int sourcePort, int destinationPort, Address sourceIpAddress, Address destinationIpAddress) {
        return new StandardFiveTuple(protocol, sourcePort, destinationPort, sourceIpAddress, destinationIpAddress);
    }

    @Override
    public Protocol protocol() {
        return protocol;
    }

    @Override
    public int sourcePort() {
        return sourcePort;
    }

    @Override
    public int destinationPort() {
        return destinationPort;
    }

    @Override
    public Address sourceIpAddress() {
        return sourceIpAddress;
    }

    @Override
    public Address destinationIpAddress() {
        return destinationIpAddress;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StandardFiveTuple that = (StandardFiveTuple) o;
        return hashCode() == that.hashCode();
    }

    @Override
    public int hashCode() {
        return Objects.hash(protocol, sourcePort, destinationPort, sourceIpAddress, destinationIpAddress);
    }

    @Override
    public String toString() {
        return "StandardFiveTuple{" +
                "protocol=" + protocol +
                ", sourcePort=" + sourcePort +
                ", destinationPort=" + destinationPort +
                ", sourceIpAddress=" + sourceIpAddress +
                ", destinationIpAddress=" + destinationIpAddress +
                '}';
    }
}
