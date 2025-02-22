// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "consensus/aft/raft.h"
#include "ds/logger.h"
#include "kv/test/stub_consensus.h"
#include "logging_stub.h"

#include <chrono>
#include <string>

using TRaft =
  aft::Aft<aft::LedgerStubProxy, aft::ChannelStubProxy, aft::StubSnapshotter>;
using Store = aft::LoggingStubStore;
using Adaptor = aft::Adaptor<Store>;

static std::vector<uint8_t> cert;

static const auto request_timeout = std::chrono::milliseconds(10);
static const auto election_timeout = std::chrono::milliseconds(100);

static aft::ChannelStubProxy* channel_stub_proxy(const TRaft& r)
{
  return (aft::ChannelStubProxy*)r.channels.get();
}

static void receive_message(
  TRaft& sender, TRaft& receiver, std::vector<uint8_t> contents)
{
  bool should_send = true;

  {
    // If this is AppendEntries, then append the serialised ledger entries to
    // the message before transmitting
    const uint8_t* data = contents.data();
    auto size = contents.size();
    auto msg_type = serialized::peek<aft::RaftMsgType>(data, size);
    if (msg_type == aft::raft_append_entries)
    {
      // Parse the indices to be sent to the recipient.
      auto ae = *(aft::AppendEntries*)data;

      TRaft* ps = &sender;
      const auto payload_opt =
        sender.ledger->get_append_entries_payload(ae, ps);
      if (payload_opt.has_value())
      {
        contents.insert(
          contents.end(), payload_opt->begin(), payload_opt->end());
      }
      else
      {
        should_send = false;
      }
    }
  }

  if (should_send)
  {
    receiver.recv_message(sender.id(), contents.data(), contents.size());
  }
}

template <typename AssertionArg, class NodeMap, class Assertion>
static size_t dispatch_all_and_DOCTEST_CHECK(
  NodeMap& nodes,
  const ccf::NodeId& from,
  aft::ChannelStubProxy::MessageList& messages,
  const Assertion& assertion)
{
  size_t count = 0;
  while (messages.size())
  {
    auto [tgt_node_id, contents] = messages.front();
    messages.pop_front();

    if constexpr (!std::is_same_v<AssertionArg, void>)
    {
      AssertionArg arg = *(AssertionArg*)contents.data();
      assertion(arg);
    }

    receive_message(*nodes[from], *nodes[tgt_node_id], contents);

    count++;
  }
  return count;
}

template <typename AssertionArg, class NodeMap, class Assertion>
static size_t dispatch_all_and_DOCTEST_CHECK(
  NodeMap& nodes, const ccf::NodeId& from, const Assertion& assertion)
{
  auto& messages = channel_stub_proxy(*nodes.at(from))->messages;
  return dispatch_all_and_DOCTEST_CHECK<AssertionArg>(
    nodes, from, messages, assertion);
}

template <class NodeMap>
static size_t dispatch_all(
  NodeMap& nodes,
  const ccf::NodeId& from,
  aft::ChannelStubProxy::MessageList& messages)
{
  return dispatch_all_and_DOCTEST_CHECK<void>(
    nodes, from, messages, [](const auto&) {
      // Pass
    });
}

template <class NodeMap>
static size_t dispatch_all(NodeMap& nodes, const ccf::NodeId& from)
{
  auto& messages = channel_stub_proxy(*nodes.at(from))->messages;
  return dispatch_all(nodes, from, messages);
}
