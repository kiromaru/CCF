// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <array>
#include <vector>
#include <memory>
#include <string>
#include <sstream>
#include <iomanip>

#include "oZKS/ozks.h"

namespace ccf {
    // Adapter to use HistoryTree with OZKS library
    class HistoryTreeAdapter 
    {
    public:
        class Hash
        {
        public:
            static constexpr size_t HASH_SIZE = 32;

            std::uint8_t bytes[HASH_SIZE];
            
            Hash(const std::array<std::uint8_t, HASH_SIZE>& hash)
            {
                memcpy(bytes, hash.data(), hash.size());
            }

            Hash()
            {
                memset(bytes, 0, HASH_SIZE);
            }

            void serialise(std::vector<std::uint8_t>& v) const
            {
                for (const std::uint8_t bt : bytes)
                {
                    v.push_back(bt);
                }
            }

            void deserialise(const std::vector<std::uint8_t>& v, size_t position)
            {
                for (size_t i = 0; i < HASH_SIZE; i++)
                {
                    bytes[i] = v[i + position];
                }
            }

            bool operator==(const Hash& other) const
            {
                return (0 == memcmp(bytes, other.bytes, HASH_SIZE));
            }

            std::string to_string() const
            {
                std::stringstream ss;
                ss << std::hex;

                for (size_t i = 0; i < HASH_SIZE; i++)
                {
                    ss << std::setw(2) << std::setfill('0') << (int)bytes[i];
                }

                return ss.str();
            }

            size_t size() const
            {
                return HASH_SIZE;
            }
        };

        class Path
        {
        public:
            typedef enum
            {
                PATH_LEFT,
                PATH_RIGHT
            } Direction;

            typedef struct
            {
                /// @brief The hash of the path element
                Hash hash;

                /// @brief The direction at which @p hash joins at this path element
                /// @note If @p direction == PATH_LEFT, @p hash joins at the left, i.e.
                /// if t is the current hash, e.g. a leaf, then t' = Hash( @p hash, t );
                Direction direction;
            } Element;


            Path(const std::vector<std::uint8_t>& bytes, size_t& position)
            {

            }

            Path()
            {

            }

            size_t max_index() const
            {
                return 0;
            }

            bool verify(const Hash& root) const
            {
                return false;
            }

            const Hash leaf() const
            {
                return Hash();
            }

            void serialise(std::vector<std::uint8_t>& v) const
            {

            }

            /// @brief Iterator for path elements
            typedef typename std::list<Element>::const_iterator const_iterator;

            /// @brief Start iterator for path elements
            const_iterator begin() const
            {
                return elements_.begin();
            }

            /// @brief End iterator for path elements
            const_iterator end() const
            {
                return elements_.end();
            }

        private:
            std::list<Element> elements_;
        };

        HistoryTreeAdapter(const std::vector<std::uint8_t>& v)
        {

        }

        HistoryTreeAdapter(const Hash& hash)
        {

        }

        const Hash& root() const
        {
            return root_;
        }

        std::shared_ptr<Hash> past_root(size_t index) const
        {
            return std::make_shared<Hash>();
        }

        const Hash& leaf(size_t index) const
        {
            return root_;
        }

        void flush_to(size_t index)
        {

        }

        void retract_to(size_t index)
        {

        }

        std::shared_ptr<Path> path(size_t index) const
        {
            return std::make_shared<Path>();
        }

        size_t max_index() const
        {
            return 0;
        }

        size_t min_index() const
        {
            return 0;
        }

        void insert(const Hash& hash)
        {
            
        }

        void serialise(std::vector<std::uint8_t>& v) const
        {

        }

        void serialise(size_t from, size_t to, std::vector<std::uint8_t>& v) const
        {

        }

    private:
        Hash root_;
    };
}
