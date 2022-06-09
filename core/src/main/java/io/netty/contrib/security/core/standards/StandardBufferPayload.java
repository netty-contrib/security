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

import io.netty.contrib.security.core.payload.BufferPayload;
import io.netty5.buffer.api.Buffer;
import io.netty5.buffer.api.internal.Statics;

import java.util.Objects;

public final class StandardBufferPayload implements BufferPayload {
    private final Buffer buffer;

    private StandardBufferPayload(Buffer buffer) {
        this.buffer = Objects.requireNonNull(buffer, "Buffer");
    }

    /**
     * Create a new {@link StandardBufferPayload} with specified {@link Buffer}
     *
     * @param buffer    {@link Buffer} to use as needle
     * @return New {@link StandardBufferPayload} instance
     */
    public static StandardBufferPayload create(Buffer buffer) {
        return new StandardBufferPayload(buffer);
    }

    @Override
    public Buffer needle() {
        return buffer;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StandardBufferPayload that = (StandardBufferPayload) o;
        return Statics.equals(buffer, that.buffer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(buffer);
    }

    @Override
    public String toString() {
        return "BufferPayloadHolder{buffer=" + buffer + '}';
    }
}
