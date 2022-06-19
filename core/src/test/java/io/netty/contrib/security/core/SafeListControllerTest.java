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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SafeListControllerTest {

    @Test
    void lock() {
        SafeListController<String> impl = new Impl();
        assertTrue(impl.isLocked());

        impl.unlock();
        assertFalse(impl.isLocked());

        impl.lock();
        assertTrue(impl.isLocked());
    }

    @Test
    void unlock() {
        SafeListController<String> impl = new Impl();
        impl.unlock();
        assertFalse(impl.isLocked());

        impl.lock();
        assertTrue(impl.isLocked());

        impl.unlock();
        assertFalse(impl.isLocked());
    }

    @Test
    void add() {
        SafeListController<String> impl = new Impl();
        impl.unlock();
        assertFalse(impl.isLocked());

        impl.add("Meow");
        assertEquals(0, impl.MAIN_LIST.size());

        impl.lock();
        assertTrue(impl.isLocked());
        assertEquals(1, impl.MAIN_LIST.size());

        assertThrows(IllegalStateException.class, () -> impl.add("MeowMeow"));
        impl.unlock();
        assertFalse(impl.isLocked());
        assertDoesNotThrow(() -> impl.add("MeowMeow"));

        impl.lock();
        assertTrue(impl.isLocked());

        assertEquals(2, impl.MAIN_LIST.size());
    }

    @Test
    void remove() {
        SafeListController<String> impl = new Impl();
        impl.unlock();
        assertFalse(impl.isLocked());

        impl.add("Meow");
        assertEquals(0, impl.MAIN_LIST.size());

        impl.lock();
        assertTrue(impl.isLocked());
        assertEquals(1, impl.MAIN_LIST.size());

        assertThrows(IllegalStateException.class, () -> impl.remove("Meow"));
        impl.unlock();
        assertFalse(impl.isLocked());
        assertDoesNotThrow(() -> impl.remove("Meow"));

        impl.lock();
        assertTrue(impl.isLocked());

        assertEquals(0, impl.MAIN_LIST.size());
    }

    @Test
    void copy() {
        SafeListController<String> impl = new Impl();
        impl.unlock();

        impl.add("MeowMeow");
        impl.lock();

        assertEquals(1, impl.MAIN_LIST.size());
        assertEquals(impl.MAIN_LIST.get(0), impl.copy().get(0));
    }

    @Test
    void isLocked() {
        SafeListController<String> impl = new Impl();

        assertTrue(impl.isLocked());
        impl.unlock();
        assertFalse(impl.isLocked());

        impl.lock();
        assertTrue(impl.isLocked());
    }

    private static final class Impl extends SafeListController<String> {
        // NO-OP
    }
}
