// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "backup_signatures.h"
#include "blit.h"
#include "consensus/aft/revealed_nonces.h"
#include "crypto/hash.h"
#include "crypto/verifier.h"
#include "kv/committable_tx.h"
#include "node_signature.h"
#include "node_signature_verify.h"
#include "tls/tls.h"
#include "view_change.h"

namespace ccf
{
  struct BftNodeSignature : public NodeSignature
  {
    bool is_primary;
    Nonce nonce;

    BftNodeSignature(const NodeSignature& ns) :
      NodeSignature(ns),
      is_primary(false)
    {}

    BftNodeSignature(
      const std::vector<uint8_t>& sig_,
      const NodeId& node_,
      Nonce hashed_nonce_) :
      NodeSignature(sig_, node_, hashed_nonce_),
      is_primary(false)
    {}
  };

  struct CommitCert
  {
    CommitCert(crypto::Sha256Hash& root_, Nonce my_nonce_) :
      root(root_),
      my_nonce(my_nonce_),
      have_primary_signature(true)
    {}

    CommitCert() = default;

    crypto::Sha256Hash root;
    std::map<NodeId, BftNodeSignature> sigs;
    std::set<NodeId> sig_acks;
    std::set<NodeId> nonce_set;
    std::map<NodeId, Nonce> unmatched_nonces;
    Nonce my_nonce;
    bool have_primary_signature = false;
    bool ack_sent = false;
    bool reply_and_nonce_sent = false;
    bool nonces_committed_to_ledger = false;
    bool wrote_sig_to_ledger = false;
  };

  class ProgressTrackerStore
  {
  public:
    virtual ~ProgressTrackerStore() = default;
    virtual void write_backup_signatures(const BackupSignatures& sig_value) = 0;
    virtual std::optional<BackupSignatures> get_backup_signatures() = 0;
    virtual std::optional<ViewChangeConfirmation> get_new_view() = 0;
    virtual void write_nonces(aft::RevealedNonces& nonces) = 0;
    virtual std::optional<aft::RevealedNonces> get_nonces() = 0;
    virtual bool verify_signature(
      const NodeId& node_id,
      crypto::Sha256Hash& root,
      size_t sig_size,
      uint8_t* sig) = 0;
    virtual void sign_view_change_request(
      ViewChangeRequest& view_change, ccf::View view) = 0;
    virtual bool verify_view_change_request(
      ViewChangeRequest& view_change,
      const NodeId& from,
      ccf::View view,
      ccf::SeqNo seqno) = 0;
    virtual ccf::SeqNo write_view_change_confirmation(
      ViewChangeConfirmation& new_view) = 0;
    virtual void sign_view_change_confirmation(
      ViewChangeConfirmation& new_view) = 0;
    virtual bool verify_view_change_request_confirmation(
      ViewChangeConfirmation& new_view, const NodeId& from) = 0;
  };

  class ProgressTrackerStoreAdapter : public ProgressTrackerStore
  {
  public:
    ProgressTrackerStoreAdapter(
      kv::AbstractStore& store_, crypto::KeyPair& kp_) :
      store(store_),
      kp(kp_),
      nodes(Tables::NODES),
      backup_signatures(Tables::BACKUP_SIGNATURES),
      revealed_nonces(Tables::NONCES),
      new_views(Tables::NEW_VIEWS)
    {}

    void write_backup_signatures(const BackupSignatures& sig_value) override
    {
      kv::CommittableTx tx(&store);
      auto backup_sig_view = tx.rw(backup_signatures);

      backup_sig_view->put(sig_value);
      auto r = tx.commit();
      LOG_TRACE_FMT("Adding signatures to ledger, result:{}", r);
      CCF_ASSERT_FMT(
        r == kv::CommitResult::SUCCESS,
        "Commiting backup signatures failed r:{}",
        r);
    }

    std::optional<BackupSignatures> get_backup_signatures() override
    {
      kv::ReadOnlyTx tx(&store);
      auto sigs_tv = tx.ro(backup_signatures);
      auto sigs = sigs_tv->get();
      if (!sigs.has_value())
      {
        LOG_FAIL_FMT("No signatures found in signatures map");
        throw ccf_logic_error("No signatures found in signatures map");
      }
      return sigs;
    }

    std::optional<ViewChangeConfirmation> get_new_view() override
    {
      kv::ReadOnlyTx tx(&store);
      auto new_views_tv = tx.ro(new_views);
      return new_views_tv->get();
    }

    void write_nonces(aft::RevealedNonces& nonces) override
    {
      kv::CommittableTx tx(&store);
      auto nonces_tv = tx.rw(revealed_nonces);

      nonces_tv->put(nonces);
      auto r = tx.commit();
      if (r != kv::CommitResult::SUCCESS)
      {
        LOG_FAIL_FMT(
          "Failed to write nonces, view:{}, seqno:{}",
          nonces.tx_id.view,
          nonces.tx_id.seqno);
        throw ccf_logic_error(fmt::format(
          "Failed to write nonces, view:{}, seqno:{}",
          nonces.tx_id.view,
          nonces.tx_id.seqno));
      }
    }

    std::optional<aft::RevealedNonces> get_nonces() override
    {
      kv::ReadOnlyTx tx(&store);
      auto nonces_tv = tx.ro(revealed_nonces);
      auto nonces = nonces_tv->get();
      if (!nonces.has_value())
      {
        LOG_FAIL_FMT("No signatures found in signatures map");
        throw ccf_logic_error("No signatures found in signatures map");
      }
      return nonces;
    }

    bool verify_signature(
      const NodeId& node_id,
      crypto::Sha256Hash& root,
      size_t sig_size,
      uint8_t* sig) override
    {
      kv::ReadOnlyTx tx(&store);
      return verify_node_signature(
        tx, node_id, sig, sig_size, root.h.data(), root.h.size());
    }

    void sign_view_change_request(
      ViewChangeRequest& view_change, ccf::View view) override
    {
      crypto::Sha256Hash h = hash_view_change(view_change, view);
      view_change.signature = kp.sign_hash(h.h.data(), h.h.size());
    }

    bool verify_view_change_request(
      ViewChangeRequest& view_change,
      const NodeId& from,
      ccf::View view,
      ccf::SeqNo seqno) override
    {
      crypto::Sha256Hash h = hash_view_change(view_change, view);

      kv::ReadOnlyTx tx(&store);
      return verify_node_signature(tx, from, view_change.signature, h);
    }

    bool verify_view_change_request_confirmation(
      ViewChangeConfirmation& new_view, const NodeId& from) override
    {
      crypto::Sha256Hash h = hash_new_view(new_view);
      kv::ReadOnlyTx tx(&store);
      return verify_node_signature(tx, from, new_view.signature, h);
    }

    void sign_view_change_confirmation(
      ViewChangeConfirmation& new_view) override
    {
      crypto::Sha256Hash h = hash_new_view(new_view);
      new_view.signature = kp.sign_hash(h.h.data(), h.h.size());
    }

    ccf::SeqNo write_view_change_confirmation(
      ViewChangeConfirmation& new_view) override
    {
      kv::CommittableTx tx(&store);
      auto new_views_tv = tx.rw(new_views);

      new_views_tv->put(new_view);
      auto r = tx.commit();
      if (r != kv::CommitResult::SUCCESS)
      {
        std::string msg =
          fmt::format("Failed to write new_view, view:{}", new_view.view);
        LOG_FAIL_FMT("{}", msg);
        throw ccf_logic_error(msg);
      }

      return tx.commit_version();
    }

    crypto::Sha256Hash hash_new_view(ViewChangeConfirmation& new_view)
    {
      auto ch = crypto::make_incremental_sha256();

      ch->update(new_view.view);

      for (auto it : new_view.view_change_messages)
      {
        ch->update(it.second.signature);
      }

      return ch->finalise();
    }

  private:
    kv::AbstractStore& store;
    crypto::KeyPair& kp;
    Nodes nodes;
    BackupSignaturesMap backup_signatures;
    aft::RevealedNoncesMap revealed_nonces;
    NewViewsMap new_views;

    crypto::Sha256Hash hash_view_change(
      const ViewChangeRequest& v, ccf::View view) const
    {
      auto ch = crypto::make_incremental_sha256();

      ch->update(view);
      ch->update(v.seqno);
      ch->update(v.root);

      for (auto& s : v.signatures)
      {
        ch->update(s.sig);
      }

      return ch->finalise();
    }
  };

  static constexpr uint32_t get_endorsement_threshold(uint32_t count)
  {
    return count * 2 / 3 + 1;
  }

  // Counts the number of endorsements (backup signatures, nonces,
  // view-changes) that come from a specific configuration.
  template <typename T>
  static uint32_t count_endorsements_in_config(
    T& messages, const kv::Configuration::Nodes& config)
  {
    uint32_t endorsements = 0;
    for (const auto& node : config)
    {
      if (messages.find(node.first) != messages.end())
      {
        ++endorsements;
      }
    }

    return endorsements;
  }
}
