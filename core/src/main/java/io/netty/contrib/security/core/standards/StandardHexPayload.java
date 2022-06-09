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

import io.netty.contrib.security.core.payload.HexPayload;
import io.netty5.buffer.api.Buffer;
import io.netty5.buffer.api.BufferAllocator;

import java.util.Objects;

import static io.netty.contrib.security.core.Util.hexStringToByteArray;

/**
 * {@link StandardHexPayload} handles Hex Payload Needle. It will convert
 * Hex String or Hex {@link Buffer} into Hex {@link Buffer}.
 */
public final class StandardHexPayload implements HexPayload {

    private final Buffer buffer;

    private StandardHexPayload(Buffer buffer) {
        this.buffer = Objects.requireNonNull(buffer, "Buffer");
    }

    /**
     * Create a new {@link StandardRegexPayload} with specified {@link String}
     *
     * @param hexString {@link String} to use as needle
     * @return New {@link StandardRegexPayload} instance
     */
    public static StandardHexPayload create(String hexString) {
        byte[] hex = hexStringToByteArray(hexString);
        return new StandardHexPayload(BufferAllocator.onHeapUnpooled().copyOf(hex));
    }

    @Override
    public Buffer needle() {
        return buffer;
    }
}
