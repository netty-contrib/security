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
 * Actions to be taken
 */
public enum Action {

    /**
     * Accept the request and pass it to next handler.
     *
     * <p>
     * Supported usage: Channel and Data
     */
    ACCEPT,

    /**
     * Drop the request without closing the connection.
     *
     * <p>
     * Supported usage: Data
     */
    DROP,

    /**
     * Drop the request and close the connection.
     *
     * <p>
     * Supported usage: Channel and Data
     */
    REJECT
}
