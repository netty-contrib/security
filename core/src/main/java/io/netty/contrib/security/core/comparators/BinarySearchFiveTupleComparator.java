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
package io.netty.contrib.security.core.comparators;

import io.netty.contrib.security.core.FiveTuple;
import io.netty.contrib.security.core.Rule;

import java.util.Comparator;

/**
 * This is a special {@link Comparator} implementation only for
 * Binary search to lookup using {@link Rule} and {@link FiveTuple}.
 * <p>
 * Sending any other object will result in {@link ClassCastException}
 */
public final class BinarySearchFiveTupleComparator implements Comparator<Object> {

    public static final BinarySearchFiveTupleComparator INSTANCE = new BinarySearchFiveTupleComparator();

    private BinarySearchFiveTupleComparator() {
        // Prevent outside initialization
    }

    @Override
    public int compare(Object o1, Object o2) {
        Rule rule = (Rule) o1;
        FiveTuple fiveTuple = (FiveTuple) o2;

        int compare = Integer.compare(rule.protocol().ordinal(), fiveTuple.protocol().ordinal());
        if (compare != 0) {
            return compare;
        }

        compare = rule.sourcePorts().lookup(fiveTuple.sourcePort());
        if (compare != 0) {
            return compare;
        }

        compare = rule.destinationPorts().lookup(fiveTuple.destinationPort());
        if (compare != 0) {
            return compare;
        }

        compare = rule.sourceIpAddresses().lookup(fiveTuple.sourceIpAddress());
        if (compare != 0) {
            return compare;
        }

        return rule.destinationIpAddresses().lookup(fiveTuple.destinationIpAddress());
    }
}
