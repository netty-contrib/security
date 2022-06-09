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

import io.netty.contrib.security.core.FiveTuple;
import io.netty.contrib.security.core.Rule;
import io.netty.contrib.security.core.RuleLookup;
import io.netty.contrib.security.core.SafeListController;
import io.netty.contrib.security.core.Table;
import io.netty.contrib.security.core.comparators.BinarySearchFiveTupleComparator;
import io.netty5.util.internal.ObjectUtil;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This is a standard implementation of {@link Table}.
 * It handles {@link Rule} lookup by implementing {@link RuleLookup}.
 * Modification of {@link Rule}s such as add or remove is supported.
 * Take a look at {@link SafeListController} to know how to add or remove rules.
 */
public class StandardTable extends SafeListController<Rule> implements Table {
    private final int priority;
    private final String name;

    private StandardTable(int priority, String name) {
        super(SortAndFilterImpl.INSTANCE);
        this.priority = ObjectUtil.checkInRange(priority, 1, Integer.MAX_VALUE - 1, "Priority");
        this.name = Objects.requireNonNull(name, "Name");
    }

    /**
     * Create a new {@link StandardTable} instance
     *
     * @param priority      Table priority
     * @param name          Table name
     * @return New {@link StandardTable} instance
     */
    public static StandardTable of(int priority, String name) {
        return new StandardTable(priority, name);
    }

    @Override
    public int priority() {
        return priority;
    }

    @Override
    public String name() {
        return name;
    }

    /**
     * Return an unmodifiable {@link List} of {@link Rule}.
     */
    @Override
    public List<Rule> rules() {
        return super.copy();
    }

    @Override
    public void addRule(Rule rule) {
        super.add(rule);
    }

    @Override
    public void removeRule(Rule rule) {
        super.remove(rule);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StandardTable that = (StandardTable) o;
        return hashCode() == that.hashCode();
    }

    @Override
    public int hashCode() {
        return Objects.hash(priority);
    }

    @Override
    public Rule lookup(FiveTuple fiveTuple) {
        int index = Collections.binarySearch(MAIN_LIST, fiveTuple, BinarySearchFiveTupleComparator.INSTANCE);

        if (index >= 0) {
            return MAIN_LIST.get(index);
        } else {
            // If rule was not found, return null.
            return null;
        }
    }

    private static final class SortAndFilterImpl implements SafeListController.SortAndFilter<Rule> {

        private static final SortAndFilterImpl INSTANCE = new SortAndFilterImpl();

        @Override
        public List<Rule> process(List<Rule> list) {
            Collections.sort(list);
            return list;
        }

        private SortAndFilterImpl() {
            // Prevent outside initialization
        }
    }
}
