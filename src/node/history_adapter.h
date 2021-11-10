// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <array>
#include <vector>
#include <memory>
#include <string>
#include <sstream>
#include <iomanip>
#include <list>

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
                *this = hash;
            }

            Hash()
            {
                memset(bytes, 0, HASH_SIZE);
            }

            Hash(const Hash &other)
            {
                *this = other;
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

            Hash& operator=(const Hash& other)
            {
                memcpy(bytes, other.bytes, HASH_SIZE);
                return *this;
            }

            Hash& operator=(const std::array<std::uint8_t, HASH_SIZE>& other)
            {
                memcpy(bytes, other.data(), HASH_SIZE);
                return *this;
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


            Path(const std::vector<std::uint8_t>& bytes, std::size_t& position)
            {
                deserialise(bytes, position);
            }

            Path()
            {
            }

            // size_t max_index() const
            // {
            //     return 0;
            // }

            bool verify(const Hash& root) const
            {
                return false;
            }

            // const Hash leaf() const
            // {
            //     return Hash();
            // }

            void serialise(std::vector<std::uint8_t>& v) const
            {
            }

            void deserialise(const std::vector<std::uint8_t>& v, std::size_t& position)
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

            static std::shared_ptr<Path> from_query_result(const ozks::QueryResult& query_result)
            {
                return std::make_shared<Path>();
            }

        private:
            std::list<Element> elements_;
        };

        HistoryTreeAdapter(const std::vector<std::uint8_t>& v) : tree_(ozks::OZKSConfig { false, false })
        {
            deserialise(v);
        }

        HistoryTreeAdapter(const Hash& hash) : tree_(ozks::OZKSConfig { false, false })
        {
            insert(hash);
        }

        Hash root() const
        {
            Hash result;
            get_root(result);
            return result;
        }

        std::shared_ptr<Hash> past_root(size_t index) const
        {
            if (index >= previous_roots_.size())
                throw std::runtime_error("Invalid index");

            ozks::commitment_type commitment = previous_roots_[index];
            Hash root;
            get_root(commitment, root);
            return std::make_shared<Hash>(root);
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
            if (index >= leaves_.size())
                throw std::invalid_argument("Index is bigger than existing leaves");

            leaves_.resize(index + 1);
            previous_roots_.resize(index + 1);
        }

        std::shared_ptr<Path> path(size_t index) const
        {
            if (index >= leaves_.size())
                throw std::invalid_argument("Index is bigger than existing leaves");

            Hash hash = leaves_[index];
            ozks::key_type key;
            hash.to_key(key);

            ozks::QueryResult result = tree_.query(key);
            if (!result.is_member)
                throw std::runtime_error("A valid index should be present in tree");

            return Path::from_query_result(result);
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
            //get_root(commitment.root_commitment, root_hash_);
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

            // Save current root
            //root_hash_.serialise(v);
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

            // Read current root
            //root_hash_.deserialise(v, position);
        }

    private:
        ozks::OZKS tree_;
        std::vector<Hash> leaves_;
        std::vector<ozks::commitment_type> previous_roots_;
        //Hash root_hash_;

        void get_root(Hash& hash) const
        {
            ozks::Commitment commitment = tree_.get_commitment();
            get_root(commitment.root_commitment, hash);
        }

        void get_root(const ozks::commitment_type& commitment, Hash& hash) const
        {
            memcpy(hash.bytes, commitment.data(), Hash::HASH_SIZE);
        }
    };
}
