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
import io.netty.contrib.security.core.BasicFilter;
import io.netty.contrib.security.core.FiveTuple;
import io.netty.contrib.security.core.Rule;
import io.netty.contrib.security.core.Table;
import io.netty.contrib.security.core.Tables;
import io.netty.contrib.security.core.payload.Payload;
import io.netty5.buffer.api.Buffer;
import io.netty5.buffer.api.BufferHolder;
import io.netty5.channel.ChannelHandlerContext;
import io.netty5.channel.socket.DatagramPacket;

import java.util.Objects;

/**
 * This is a standard implementation of {@link BasicFilter}
 * which handles {@link ChannelHandlerContext#fireChannelActive()},
 * {@link DatagramPacket}, {@link Buffer} and {@link BufferHolder}.
 */
public class StandardFilter implements BasicFilter {

    private final Tables tables;
    private final Action defaultAction;

    /**
     * Create a new instance {@link StandardFilter}
     *
     * @param tables        {@link Tables} to use
     * @param defaultAction {@link Action} to be taken if a request does
     *                      not match against any rules in the {@link Tables}
     * @throws NullPointerException If any parameter is {@code null}
     */
    public StandardFilter(Tables tables, Action defaultAction) {
        this.tables = Objects.requireNonNull(tables, "Tables");
        this.defaultAction = Objects.requireNonNull(defaultAction, "DefaultAction");
    }

    @Override
    public Action validateChannelActive(FiveTuple fiveTuple) {
        return checkRule(fiveTuple, null);
    }

    @Override
    public Action validateDatagramPacket(DatagramPacket datagramPacket, FiveTuple fiveTuple) {
        return checkRule(fiveTuple, datagramPacket.content());
    }

    @Override
    public Action validateBuffer(Buffer buffer, FiveTuple fiveTuple) {
        return checkRule(fiveTuple, buffer);
    }

    private Action checkRule(FiveTuple fiveTuple, Buffer bufferPayload) {
        Rule rule = ruleLookup(fiveTuple, bufferPayload);
        if (rule != null) {
            return rule.action();
        }

        // If rule is null then we couldn't locate the appropriate rule.
        // We will fall back to default action now.
        return defaultAction;
    }

    /**
     * Lookup for appropriate {@link Rule} in {@link Tables}
     *
     * @param fiveTuple {@link FiveTuple} implementation
     * @return {@link Rule} if found else {@code null}
     */
    private Rule ruleLookup(FiveTuple fiveTuple, Buffer bufferPayload) {
        // Iterate over all Tables and lookup for Rule using FiveTuple.
        for (Table table : tables.tables()) {
            Rule rule = table.lookup(fiveTuple);

            // If rule was found then check if there are any payload instructions.
            // If there are, check payload one by one and if it matches, return rule.
            // If there are none, just return rule.
            if (rule != null) {
                if (rule.payloads().size() > 0 && bufferPayload != null) {
                    for (int i = 0; i < rule.payloads().size(); i++) {
                        Payload<?> payload = rule.payloads().get(i);
                        if (rule.payloadMatcher().validate(payload.needle(), bufferPayload)) {
                            return rule;
                        }
                    }
                } else {
                    return rule;
                }
            }
        }

        // for-loop was not executed because there were no rules.
        // Let's return null since we couldn't find anything.
        return null;
    }
}
