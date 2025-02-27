// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "crypto/verifier.h"
#include "ds/dl_list.h"
#include "ds/logger.h"
#include "ds/thread_messaging.h"
#include "endian.h"
#include "entities.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "node_signature_verify.h"
#include "nodes.h"
#include "signatures.h"
#include "tls/tls.h"

#include <array>
#include <deque>
#include <string.h>

#define HAVE_OPENSSL
#define HAVE_MBEDTLS
// merklecpp traces are off by default, even when CCF tracing is enabled
// #include "merklecpp_trace.h"
#include <merklecpp/merklecpp.h>

namespace fmt
{
  template <>
  struct formatter<kv::TxHistory::RequestID>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const kv::TxHistory::RequestID& p, FormatContext& ctx)
    {
      return format_to(
        ctx.out(), "<RID {0}, {1}>", std::get<0>(p), std::get<1>(p));
    }
  };
}

namespace ccf
{
  enum HashOp
  {
    APPEND,
    VERIFY,
    ROLLBACK,
    COMPACT
  };

  constexpr int MAX_HISTORY_LEN = 1000;

  static std::ostream& operator<<(std::ostream& os, HashOp flag)
  {
    switch (flag)
    {
      case APPEND:
        os << "append";
        break;

      case VERIFY:
        os << "verify";
        break;

      case ROLLBACK:
        os << "rollback";
        break;

      case COMPACT:
        os << "compact";
        break;
    }

    return os;
  }

  static inline void log_hash(const crypto::Sha256Hash& h, HashOp flag)
  {
    LOG_DEBUG_FMT("History [{}] {}", flag, h);
  }

  class NullTxHistoryPendingTx : public kv::PendingTx
  {
    kv::TxID txid;
    kv::Store& store;
    NodeId id;

  public:
    NullTxHistoryPendingTx(
      kv::TxID txid_, kv::Store& store_, const NodeId& id_) :
      txid(txid_),
      store(store_),
      id(id_)
    {}

    kv::PendingTxInfo call() override
    {
      auto sig = store.create_reserved_tx(txid);
      auto signatures =
        sig.template rw<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto serialised_tree = sig.template rw<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      PrimarySignature sig_value(id, txid.version);
      signatures->put(sig_value);
      serialised_tree->put({});
      return sig.commit_reserved();
    }
  };

  class NullTxHistory : public kv::TxHistory
  {
    kv::Store& store;
    NodeId id;

  protected:
    kv::Version version = 0;
    kv::Term term_of_last_version = 0;
    kv::Term term_of_next_version = 0;

  public:
    NullTxHistory(kv::Store& store_, const NodeId& id_, crypto::KeyPair&) :
      store(store_),
      id(id_)
    {}

    void append(const std::vector<uint8_t>&) override
    {
      version++;
    }

    kv::TxHistory::Result verify_and_sign(
      PrimarySignature&, kv::Term*, kv::Configuration::Nodes&) override
    {
      return kv::TxHistory::Result::OK;
    }

    bool verify(kv::Term*, ccf::PrimarySignature*) override
    {
      return true;
    }

    void set_term(kv::Term t) override
    {
      term_of_last_version = t;
      term_of_next_version = t;
    }

    void rollback(const kv::TxID& tx_id, kv::Term commit_term_) override
    {
      version = tx_id.version;
      term_of_last_version = tx_id.term;
      term_of_next_version = commit_term_;
    }

    void compact(kv::Version) override {}

    bool init_from_snapshot(const std::vector<uint8_t>&) override
    {
      return true;
    }

    std::vector<uint8_t> get_raw_leaf(uint64_t) override
    {
      return {};
    }

    void emit_signature() override
    {
      auto txid = store.next_txid();
      LOG_DEBUG_FMT("Issuing signature at {}.{}", txid.term, txid.version);
      store.commit(
        txid, std::make_unique<NullTxHistoryPendingTx>(txid, store, id), true);
    }

    void try_emit_signature() override {}

    bool add_request(
      kv::TxHistory::RequestID,
      const std::vector<uint8_t>&,
      const std::vector<uint8_t>&,
      uint8_t) override
    {
      return true;
    }

    crypto::Sha256Hash get_replicated_state_root() override
    {
      return crypto::Sha256Hash(std::to_string(version));
    }

    std::tuple<kv::TxID, crypto::Sha256Hash, kv::Term>
    get_replicated_state_txid_and_root() override
    {
      return {
        {term_of_last_version, version},
        crypto::Sha256Hash(std::to_string(version)),
        term_of_next_version};
    }

    std::vector<uint8_t> get_proof(kv::Version) override
    {
      return {};
    }

    bool verify_proof(const std::vector<uint8_t>&) override
    {
      return true;
    }

    std::vector<uint8_t> serialise_tree(size_t, size_t) override
    {
      return {};
    }
  };

  typedef merkle::TreeT<32, merkle::sha256_openssl> HistoryTree;

  class Proof
  {
  private:
    HistoryTree::Hash root;
    std::shared_ptr<HistoryTree::Path> path = nullptr;

  public:
    Proof() {}

    Proof(const std::vector<uint8_t>& v)
    {
      size_t position = 0;
      root.deserialise(v, position);
      path = std::make_shared<HistoryTree::Path>(v, position);
    }

    const HistoryTree::Hash& get_root() const
    {
      return root;
    }

    std::shared_ptr<HistoryTree::Path> get_path()
    {
      return path;
    }

    Proof(HistoryTree* tree, uint64_t index)
    {
      root = tree->root();
      path = tree->path(index);
    }

    Proof(const Proof&) = delete;

    bool verify(HistoryTree* tree) const
    {
      if (path->max_index() > tree->max_index())
      {
        return false;
      }
      else if (tree->max_index() == path->max_index())
      {
        return tree->root() == root && path->verify(root);
      }
      else
      {
        auto past_root = tree->past_root(path->max_index());
        return path->verify(*past_root);
      }
    }

    std::vector<uint8_t> to_v() const
    {
      std::vector<uint8_t> v;
      root.serialise(v);
      path->serialise(v);
      return v;
    }
  };

  template <class T>
  class MerkleTreeHistoryPendingTx : public kv::PendingTx
  {
    kv::TxID txid;
    kv::Consensus::SignableTxIndices commit_txid;
    kv::Store& store;
    kv::TxHistory& history;
    NodeId id;
    crypto::KeyPair& kp;

  public:
    MerkleTreeHistoryPendingTx(
      kv::TxID txid_,
      kv::Consensus::SignableTxIndices commit_txid_,
      kv::Store& store_,
      kv::TxHistory& history_,
      const NodeId& id_,
      crypto::KeyPair& kp_) :
      txid(txid_),
      commit_txid(commit_txid_),
      store(store_),
      history(history_),
      id(id_),
      kp(kp_)
    {}

    kv::PendingTxInfo call() override
    {
      auto sig = store.create_reserved_tx(txid);
      auto signatures =
        sig.template rw<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto serialised_tree = sig.template rw<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      crypto::Sha256Hash root = history.get_replicated_state_root();

      Nonce hashed_nonce;
      std::vector<uint8_t> primary_sig;
      auto consensus = store.get_consensus();
      if (consensus != nullptr && consensus->type() == ConsensusType::BFT)
      {
        auto progress_tracker = store.get_progress_tracker();
        CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
        auto r = progress_tracker->record_primary(
          txid, id, true, root, primary_sig, hashed_nonce);
        if (r != kv::TxHistory::Result::OK)
        {
          throw ccf::ccf_logic_error(fmt::format(
            "Expected success when primary added signature to the "
            "progress "
            "tracker. r:{}, view:{}, seqno:{}",
            r,
            txid.term,
            txid.version));
        }

        // The nonce is generated in progress_racker->record_primary so it must
        // exist.
        hashed_nonce = progress_tracker->get_node_hashed_nonce(txid).value();
      }
      else
      {
        hashed_nonce.h.fill(0);
      }

      primary_sig = kp.sign_hash(root.h.data(), root.h.size());

      PrimarySignature sig_value(
        id,
        txid.version,
        txid.term,
        commit_txid.version,
        commit_txid.term,
        root,
        hashed_nonce,
        primary_sig);

      if (consensus != nullptr && consensus->type() == ConsensusType::BFT)
      {
        auto progress_tracker = store.get_progress_tracker();
        CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
        progress_tracker->record_primary_signature(txid, primary_sig);
      }

      signatures->put(sig_value);
      serialised_tree->put(
        history.serialise_tree(commit_txid.previous_version, txid.version - 1));
      return sig.commit_reserved();
    }
  };

  class MerkleTreeHistory
  {
    HistoryTree* tree;

  public:
    MerkleTreeHistory(MerkleTreeHistory const&) = delete;

    MerkleTreeHistory(const std::vector<uint8_t>& serialised)
    {
      tree = new HistoryTree(serialised);
    }

    MerkleTreeHistory(crypto::Sha256Hash first_hash = {})
    {
      tree = new HistoryTree(merkle::Hash(first_hash.h));
    }

    ~MerkleTreeHistory()
    {
      delete (tree);
      tree = nullptr;
    }

    void deserialise(const std::vector<uint8_t>& serialised)
    {
      delete (tree);
      tree = new HistoryTree(serialised);
    }

    void append(crypto::Sha256Hash& hash)
    {
      tree->insert(merkle::Hash(hash.h));
    }

    crypto::Sha256Hash get_root() const
    {
      const merkle::Hash& root = tree->root();
      crypto::Sha256Hash result;
      std::copy(root.bytes, root.bytes + root.size(), result.h.begin());
      return result;
    }

    void operator=(const MerkleTreeHistory& rhs)
    {
      delete (tree);
      crypto::Sha256Hash root(rhs.get_root());
      tree = new HistoryTree(merkle::Hash(root.h));
    }

    void flush(uint64_t index)
    {
      LOG_TRACE_FMT("mt_flush_to index={}", index);
      tree->flush_to(index);
    }

    void retract(uint64_t index)
    {
      LOG_TRACE_FMT("mt_retract_to index={}", index);
      tree->retract_to(index);
    }

    Proof get_proof(uint64_t index)
    {
      if (index < begin_index())
      {
        throw std::logic_error(fmt::format(
          "Cannot produce proof for {}: index is too old and has been "
          "flushed from memory",
          index));
      }
      if (index > end_index())
      {
        throw std::logic_error(fmt::format(
          "Cannot produce proof for {}: index is not yet known", index));
      }
      return Proof(tree, index);
    }

    bool verify(const Proof& r)
    {
      return r.verify(tree);
    }

    std::vector<uint8_t> serialise()
    {
      LOG_TRACE_FMT("mt_serialize_size {}", tree->serialised_size());
      std::vector<uint8_t> output;
      tree->serialise(output);
      return output;
    }

    std::vector<uint8_t> serialise(size_t from, size_t to)
    {
      LOG_TRACE_FMT(
        "mt_serialize_size ({},{}) {}",
        from,
        to,
        tree->serialised_size(from, to));
      std::vector<uint8_t> output;
      tree->serialise(from, to, output);
      return output;
    }

    uint64_t begin_index()
    {
      return tree->min_index();
    }

    uint64_t end_index()
    {
      return tree->max_index();
    }

    bool in_range(uint64_t index)
    {
      return index >= begin_index() && index <= end_index();
    }

    crypto::Sha256Hash get_leaf(uint64_t index)
    {
      const merkle::Hash& leaf = tree->leaf(index);
      crypto::Sha256Hash result;
      std::copy(leaf.bytes, leaf.bytes + leaf.size(), result.h.begin());
      return result;
    }
  };

  template <class T>
  class HashedTxHistory : public kv::TxHistory
  {
    kv::Store& store;
    NodeId id;
    T replicated_state_tree;

    crypto::KeyPair& kp;

    threading::Task::TimerEntry emit_signature_timer_entry;
    size_t sig_tx_interval;
    size_t sig_ms_interval;

    std::mutex state_lock;
    kv::Term term_of_last_version = 0;
    kv::Term term_of_next_version;

  public:
    HashedTxHistory(
      kv::Store& store_,
      const NodeId& id_,
      crypto::KeyPair& kp_,
      size_t sig_tx_interval_ = 0,
      size_t sig_ms_interval_ = 0,
      bool signature_timer = false) :
      store(store_),
      id(id_),
      kp(kp_),
      sig_tx_interval(sig_tx_interval_),
      sig_ms_interval(sig_ms_interval_)
    {
      if (signature_timer)
      {
        start_signature_emit_timer();
      }
    }

    void start_signature_emit_timer()
    {
      struct EmitSigMsg
      {
        EmitSigMsg(HashedTxHistory<T>* self_) : self(self_) {}
        HashedTxHistory<T>* self;
      };

      auto emit_sig_msg = std::make_unique<threading::Tmsg<EmitSigMsg>>(
        [](std::unique_ptr<threading::Tmsg<EmitSigMsg>> msg) {
          auto self = msg->data.self;

          std::unique_lock<std::mutex> mguard(
            self->signature_lock, std::defer_lock);

          const int64_t sig_ms_interval = self->sig_ms_interval;
          int64_t delta_time_to_next_sig = sig_ms_interval;
          bool should_emit_signature = false;

          if (mguard.try_lock())
          {
            // NOTE: time is set on every thread via a thread message
            //       time_of_last_signature is a atomic that can be set by any
            //       thread
            auto time = threading::ThreadMessaging::thread_messaging
                          .get_current_time_offset()
                          .count();
            auto time_of_last_signature = self->time_of_last_signature.count();

            auto consensus = self->store.get_consensus();
            if (
              (consensus != nullptr) && consensus->can_replicate() &&
              self->store.commit_gap() > 0 && time > time_of_last_signature &&
              (time - time_of_last_signature) > sig_ms_interval)
            {
              should_emit_signature = true;
            }

            delta_time_to_next_sig =
              sig_ms_interval - (time - self->time_of_last_signature.count());

            if (
              delta_time_to_next_sig <= 0 ||
              delta_time_to_next_sig > sig_ms_interval)
            {
              delta_time_to_next_sig = sig_ms_interval;
            }
          }

          if (should_emit_signature)
          {
            msg->data.self->emit_signature();
          }

          self->emit_signature_timer_entry =
            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg),
              std::chrono::milliseconds(delta_time_to_next_sig));
        },
        this);

      emit_signature_timer_entry =
        threading::ThreadMessaging::thread_messaging.add_task_after(
          std::move(emit_sig_msg), std::chrono::milliseconds(1000));
    }

    ~HashedTxHistory()
    {
      threading::ThreadMessaging::thread_messaging.cancel_timer_task(
        emit_signature_timer_entry);
    }

    void set_node_id(const NodeId& id_)
    {
      id = id_;
    }

    bool init_from_snapshot(
      const std::vector<uint8_t>& hash_at_snapshot) override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      // The history can be initialised after a snapshot has been applied by
      // deserialising the tree in the signatures table and then applying the
      // hash of the transaction at which the snapshot was taken
      auto tx = store.create_read_only_tx();
      auto tree_h = tx.template ro<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      auto tree = tree_h->get();
      if (!tree.has_value())
      {
        LOG_FAIL_FMT("No tree found in serialised tree map");
        return false;
      }

      CCF_ASSERT_FMT(
        !replicated_state_tree.in_range(1),
        "Tree is not empty before initialising from snapshot");

      replicated_state_tree.deserialise(tree.value());

      crypto::Sha256Hash hash;
      std::copy_n(
        hash_at_snapshot.begin(), crypto::Sha256Hash::SIZE, hash.h.begin());
      replicated_state_tree.append(hash);
      return true;
    }

    crypto::Sha256Hash get_replicated_state_root() override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      return replicated_state_tree.get_root();
    }

    std::tuple<kv::TxID, crypto::Sha256Hash, kv::Term>
    get_replicated_state_txid_and_root() override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      return {
        {term_of_last_version,
         static_cast<kv::Version>(replicated_state_tree.end_index())},
        replicated_state_tree.get_root(),
        term_of_next_version};
    }

    kv::TxHistory::Result verify_and_sign(
      PrimarySignature& sig,
      kv::Term* term,
      kv::Configuration::Nodes& config) override
    {
      if (!verify(term, &sig))
      {
        return kv::TxHistory::Result::FAIL;
      }

      kv::TxHistory::Result result = kv::TxHistory::Result::OK;

      auto progress_tracker = store.get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      result = progress_tracker->record_primary(
        {sig.view, sig.seqno},
        sig.node,
        false,
        sig.root,
        sig.sig,
        sig.hashed_nonce,
        config);

      sig.node = id;
      sig.sig = kp.sign_hash(sig.root.h.data(), sig.root.h.size());

      return result;
    }

    bool verify(
      kv::Term* term = nullptr, PrimarySignature* signature = nullptr) override
    {
      auto tx = store.create_read_only_tx();
      auto signatures =
        tx.template ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto sig = signatures->get();
      if (!sig.has_value())
      {
        LOG_FAIL_FMT("No signature found in signatures map");
        return false;
      }
      auto& sig_value = sig.value();
      if (term)
      {
        *term = sig_value.view;
      }

      if (signature)
      {
        *signature = sig_value;
      }

      auto root = get_replicated_state_root();
      log_hash(root, VERIFY);
      return verify_node_signature(tx, sig_value.node, sig_value.sig, root);
    }

    std::vector<uint8_t> serialise_tree(size_t from, size_t to) override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      return replicated_state_tree.serialise(from, to);
    }

    void set_term(kv::Term t) override
    {
      // This should only be called once, when the store first knows about its
      // term
      std::lock_guard<std::mutex> guard(state_lock);
      term_of_last_version = t;
      term_of_next_version = t;
    }

    void rollback(
      const kv::TxID& tx_id, kv::Term term_of_next_version_) override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      LOG_TRACE_FMT("Rollback to {}.{}", tx_id.term, tx_id.version);
      term_of_last_version = tx_id.term;
      term_of_next_version = term_of_next_version_;
      replicated_state_tree.retract(tx_id.version);
      log_hash(replicated_state_tree.get_root(), ROLLBACK);
    }

    void compact(kv::Version v) override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      // Receipts can only be retrieved to the flushed index. Keep a range of
      // history so that a range of receipts are available.
      if (v > MAX_HISTORY_LEN)
      {
        replicated_state_tree.flush(v - MAX_HISTORY_LEN);
      }
      log_hash(replicated_state_tree.get_root(), COMPACT);
    }

    kv::Version last_signed_tx = 0;
    std::chrono::milliseconds time_of_last_signature =
      std::chrono::milliseconds(0);

    std::mutex signature_lock;

    void try_emit_signature() override
    {
      std::unique_lock<std::mutex> mguard(signature_lock, std::defer_lock);
      if (store.commit_gap() < sig_tx_interval || !mguard.try_lock())
      {
        return;
      }

      if (store.commit_gap() >= sig_tx_interval)
      {
        mguard.unlock();
        emit_signature();
      }
    }

    void emit_signature() override
    {
      // Signatures are only emitted when there is a consensus
      auto consensus = store.get_consensus();
      if (!consensus)
      {
        return;
      }

      // Signatures are only emitted when the consensus is establishing commit
      // over the node's own transactions
      auto signable_txid = consensus->get_signable_txid();
      if (!signable_txid.has_value())
      {
        return;
      }

      auto commit_txid = signable_txid.value();
      auto txid = store.next_txid();

      last_signed_tx = commit_txid.version;
      time_of_last_signature =
        threading::ThreadMessaging::thread_messaging.get_current_time_offset();

      LOG_DEBUG_FMT(
        "Signed at {} in view: {} commit was: {}.{} (previous .{})",
        txid.version,
        txid.term,
        commit_txid.term,
        commit_txid.version,
        commit_txid.previous_version);

      store.commit(
        txid,
        std::make_unique<MerkleTreeHistoryPendingTx<T>>(
          txid, commit_txid, store, *this, id, kp),
        true);
    }

    std::vector<uint8_t> get_proof(kv::Version index) override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      return replicated_state_tree.get_proof(index).to_v();
    }

    bool verify_proof(const std::vector<uint8_t>& v) override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      Proof proof(v);
      return replicated_state_tree.verify(proof);
    }

    std::vector<uint8_t> get_raw_leaf(uint64_t index) override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      auto leaf = replicated_state_tree.get_leaf(index);
      return {leaf.h.begin(), leaf.h.end()};
    }

    bool add_request(
      kv::TxHistory::RequestID id,
      const std::vector<uint8_t>& caller_cert,
      const std::vector<uint8_t>& request,
      uint8_t frame_format) override
    {
      LOG_DEBUG_FMT("HISTORY: add_request {0}", id);

      auto consensus = store.get_consensus();
      if (!consensus)
      {
        return false;
      }

      return consensus->on_request({id, request, caller_cert, frame_format});
    }

    void append(const std::vector<uint8_t>& data) override
    {
      std::lock_guard<std::mutex> guard(state_lock);
      crypto::Sha256Hash rh({data.data(), data.size()});
      log_hash(rh, APPEND);
      replicated_state_tree.append(rh);
    }
  };

  using MerkleTxHistory = HashedTxHistory<MerkleTreeHistory>;
}
