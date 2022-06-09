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

import io.netty5.util.NetUtil;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StaticIpAddressTest {

    @Test
    void ofInetAddress() {
        assertDoesNotThrow(() -> StaticIpAddress.of(InetAddress.getByName("192.168.1.100")));
        assertDoesNotThrow(() -> StaticIpAddress.of(InetAddress.getByName("0000:0000:0000:0000:0000:0000:0000:0001")));
    }

    @Test
    void ofString() {
        assertDoesNotThrow(() -> StaticIpAddress.of("192.168.1.100"));
        assertDoesNotThrow(() -> StaticIpAddress.of("10.10.10.10"));

        assertDoesNotThrow(() -> StaticIpAddress.of("0000:0000:0000:0000:0000:0000:0000:0001"));
        assertDoesNotThrow(() -> StaticIpAddress.of("0:0:0:0:0:0:0:1"));
        assertDoesNotThrow(() -> StaticIpAddress.of("::1"));

        assertThrows(UnknownHostException.class, () -> StaticIpAddress.of("0000:0000:0000:0000:0000:0000:0000:0001/128"));
        assertThrows(UnknownHostException.class, () -> StaticIpAddress.of("192.168.1.0/24"));
    }

    @Test
    void address() throws Exception {
        InetAddress inetAddress = InetAddress.getByName("192.168.1.100");
        Address address = StaticIpAddress.of(inetAddress);
        assertEquals(inetAddress, address.address());

        inetAddress = InetAddress.getByName("0000:0000:0000:0000:0000:0000:0000:0001");
        address = StaticIpAddress.of(inetAddress);
        assertEquals(inetAddress, address.address());
    }

    @Test
    void ofByteArray() throws UnknownHostException {
        {
            final InetAddress address = InetAddress.getByName("192.168.1.100");
            assertDoesNotThrow(() -> StaticIpAddress.of(address.getAddress()));
        }

        {
            final InetAddress address = InetAddress.getByName("0000:0000:0000:0000:0000:0000:0000:0001");
            assertDoesNotThrow(() -> StaticIpAddress.of(address.getAddress()));
        }
    }

    @Test
    void networkAddressV4() throws Exception {
        InetAddress inetAddress = InetAddress.getByName("192.168.1.100");
        Address address = StaticIpAddress.of(inetAddress);
        assertEquals(NetUtil.ipv4AddressToInt((Inet4Address) inetAddress), address.v4AddressAsInt());
    }

    @Test
    void subnetMaskV4() throws Exception {
        InetAddress inetAddress = InetAddress.getByName("192.168.1.100");
        Address address = StaticIpAddress.of(inetAddress);
        assertEquals(Util.prefixToSubnetMaskV4(32), address.v4SubnetMaskAsInt());
    }

    @Test
    void networkAddressV6() throws Exception {
        InetAddress inetAddress = InetAddress.getByName("0000:0000:0000:0000:0000:0000:0000:0001");
        Address address = StaticIpAddress.of(inetAddress);
        assertEquals(new BigInteger(inetAddress.getAddress()), address.v6NetworkAddressAsBigInt());
    }

    @Test
    void subnetMaskV6() throws Exception {
        InetAddress inetAddress = InetAddress.getByName("0000:0000:0000:0000:0000:0000:0000:0001");
        Address address = StaticIpAddress.of(inetAddress);
        assertEquals(Util.prefixToSubnetMaskV6(128), address.v6SubnetMaskAsBigInt());
    }

    @Test
    void version() throws Exception {
        InetAddress inetAddress = InetAddress.getByName("192.168.1.100");
        Address address = StaticIpAddress.of(inetAddress);
        assertEquals(Address.Version.v4, address.version());

        inetAddress = InetAddress.getByName("0000:0000:0000:0000:0000:0000:0000:0001");
        address = StaticIpAddress.of(inetAddress);
        assertEquals(Address.Version.v6, address.version());
    }
}
