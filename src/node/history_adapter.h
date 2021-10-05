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

namespace {
    void serialise_u64(std::uint64_t value, std::vector<std::uint8_t>& v)
    {
        std::size_t original_size = v.size();
        v.resize(original_size + sizeof(uint64_t));
        memcpy(v.data() + original_size, &value, sizeof(uint64_t));
    }

    void serialise_bytearray(const std::uint8_t* bytes, std::size_t size, std::vector<std::uint8_t>& v)
    {
        std::size_t original_size = v.size();
        v.resize(original_size + size);
        memcpy(v.data() + original_size, bytes, size);
    }

    std::uint64_t deserialise_u64(const std::vector<std::uint8_t>& v, std::size_t position)
    {
        std::uint64_t result = 0;
        memcpy(&result, v.data() + position, sizeof(uint64_t));
        return result;
    }

    void deserialise_bytearray(std::uint8_t* bytes, std::size_t size, const std::vector<std::uint8_t>& v, std::size_t position)
    {
        memcpy(bytes, v.data() + position, size);
    }
}

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

            void to_key(ozks::key_type& key) const
            {
                key.resize(HASH_SIZE);
                memcpy(key.data(), bytes, HASH_SIZE);
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
            deserialise(v);
        }

        HistoryTreeAdapter(const Hash& hash)
        {
            insert(hash);
        }

        const Hash root() const
        {
            return get_root();
        }

        std::shared_ptr<Hash> past_root(size_t index) const
        {
            if (index >= previous_roots_.size())
                throw std::runtime_error("Invalid index");

            ozks::commitment_type commitment = previous_roots_[index];
            return std::make_shared<Hash>(get_root(commitment));
        }

        const Hash leaf(size_t index) const
        {
            if (index >= leaves_.size())
                throw std::runtime_error("Invalid index");

            return leaves_[index];
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
            size_t leaves_ct = leaves_.size();
            return (leaves_ct == 0) ? 0 : (leaves_ct - 1);
        }

        size_t min_index() const
        {
            return 0;
        }

        void insert(const Hash& hash)
        {
            ozks::payload_type empty_payload;
            ozks::key_type key;
            hash.to_key(key);
            tree_.insert(key, empty_payload);
            leaves_.push_back(hash);

            ozks::Commitment commitment = tree_.get_commitment();
            previous_roots_.push_back(commitment.root_commitment);
        }

        void serialise(std::vector<std::uint8_t>& v) const
        {
            tree_.save(v);

            // Save leaves vector
            serialise_u64(leaves_.size(), v);
            for (std::size_t idx = 0; idx < leaves_.size(); idx++) {
                serialise_bytearray(leaves_[idx].bytes, Hash::HASH_SIZE, v);
            }

            // Save past roots vector
            serialise_u64(previous_roots_.size(), v);
            for (std::size_t idx = 0; idx < previous_roots_.size(); idx++) {
                serialise_u64(previous_roots_[idx].size(), v);
                serialise_bytearray(reinterpret_cast<const std::uint8_t*>(previous_roots_[idx].data()), previous_roots_[idx].size(), v);
            }
        }

        void serialise(std::size_t from, std::size_t to, std::vector<std::uint8_t>& v) const
        {
            // Ignore from and to for now
            serialise(v);
        }

        void deserialise(const std::vector<std::uint8_t>& v)
        {
            tree_.clear();
            leaves_.clear();
            previous_roots_.clear();

            std::size_t position = tree_.load(v, tree_);

            // Read leaves
            std::size_t leaves_size = deserialise_u64(v, position);
            position += sizeof(uint64_t);

            for (std::size_t idx = 0; idx < leaves_size; idx++) {
                Hash hash;
                deserialise_bytearray(hash.bytes, Hash::HASH_SIZE, v, position);
                position += Hash::HASH_SIZE;

                leaves_.push_back(hash);
            }

            // Read previous roots
            std::size_t previous_roots_size = deserialise_u64(v, position);
            position += sizeof(uint64_t);

            for (std::size_t idx = 0; idx < previous_roots_size; idx++) {
                std::size_t cmt_size = deserialise_u64(v, position);
                position += sizeof(uint64_t);

                ozks::commitment_type commitment(cmt_size);
                deserialise_bytearray(reinterpret_cast<uint8_t*>(commitment.data()), cmt_size, v, position);
                position += cmt_size;

                previous_roots_.push_back(commitment);
            }
        }

    private:
        ozks::OZKS tree_;
        std::vector<Hash> leaves_;
        std::vector<ozks::commitment_type> previous_roots_;

        Hash get_root() const
        {
            Hash root;
            ozks::Commitment commitment = tree_.get_commitment();
            return get_root(commitment.root_commitment);
        }

        Hash get_root(const ozks::commitment_type& commitment) const
        {
            Hash root;
            memcpy(root.bytes, commitment.data(), Hash::HASH_SIZE);
            return root;
        }
    };
}
