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

/**
 * FiveTuple stores 5 elements of a network connection.
 * <p>
 * <ol>
 *     <li> Protocol (TCP/UDP) </li>
 *     <li> Source Port </li>
 *     <li> Destination Port </li>
 *     <li> Source IP Address </li>
 *     <li> Destination IP Address </li>
 * </ol>
 */
public interface FiveTuple extends Comparable<FiveTuple> {

    /**
     * Tuple {@link Protocol}
     */
    Protocol protocol();

    /**
     * Tuple Source Port
     */
    int sourcePort();

    /**
     * Tuple Destination Port
     */
    int destinationPort();

    /**
     * Tuple Source {@link Address}
     */
    Address sourceIpAddress();

    /**
     * Source Destination {@link Address}
     */
    Address destinationIpAddress();

    @Override
    default int compareTo(FiveTuple o) {
        // Protocol
        int compare = Integer.compare(protocol().ordinal(), o.protocol().ordinal());
        if (compare != 0) {
            return compare;
        }

        // Source Port
        compare = Integer.compare(sourcePort(), o.sourcePort());
        if (compare != 0) {
            return compare;
        }

        // Destination Port
        compare = Integer.compare(destinationPort(), o.destinationPort());
        if (compare != 0) {
            return compare;
        }

        // If Source version is v4 then we have v4 destination as well.
        // If Source version is v6 then we have v6 destination as well.
        if (sourceIpAddress().version() == Address.Version.v4) {
            // Source Address
            compare = Integer.compare(sourceIpAddress().v4AddressAsInt(), o.sourceIpAddress().v4AddressAsInt());
            if (compare != 0) {
                return compare;
            }

            return Integer.compare(destinationIpAddress().v4AddressAsInt(), o.destinationIpAddress().v4AddressAsInt());
        } else if (sourceIpAddress().version() == Address.Version.v6) {
            compare = sourceIpAddress().v6NetworkAddressAsBigInt().compareTo(o.sourceIpAddress().v6NetworkAddressAsBigInt());
            if (compare != 0) {
                return compare;
            }

            return destinationIpAddress().v6NetworkAddressAsBigInt().compareTo(o.destinationIpAddress().v6NetworkAddressAsBigInt());
        }

        // Unsupported IP version. So let's return -1
        // because we have no idea at all about it.
        return -1;
    }
}
