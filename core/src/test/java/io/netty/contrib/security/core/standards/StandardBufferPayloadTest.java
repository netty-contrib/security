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
import io.netty.contrib.security.core.payload.PayloadMatcher;
import io.netty5.buffer.api.Buffer;
import io.netty5.buffer.api.BufferAllocator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandardBufferPayloadTest {

    @Test
    void createBufferPayloadAndMatch() {
        Buffer completeSentence = BufferAllocator.onHeapUnpooled().copyOf("Hey, I'm not a cat".getBytes());
        Buffer justWord = BufferAllocator.onHeapUnpooled().copyOf("cat".getBytes());

        BufferPayload bufferPayload = StandardBufferPayload.create(justWord);
        PayloadMatcher<Object, Object> payloadMatcher = new StandardPayloadMatcher();
        assertTrue(payloadMatcher.validate(bufferPayload, completeSentence));
    }

    @Test
    void createBufferPayloadAndDoesNotMatch() {
        Buffer completeSentence = BufferAllocator.onHeapUnpooled().copyOf("Hey, I'm not a cat".getBytes());
        Buffer justWord = BufferAllocator.onHeapUnpooled().copyOf("Cat".getBytes()); // cat should be in lowercase

        BufferPayload bufferPayload = StandardBufferPayload.create(justWord);
        PayloadMatcher<Object, Object> payloadMatcher = new StandardPayloadMatcher();
        assertFalse(payloadMatcher.validate(bufferPayload, completeSentence));
    }
}
