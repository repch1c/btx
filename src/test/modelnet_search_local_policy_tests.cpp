// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/search.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

using namespace modelnet;

BOOST_FIXTURE_TEST_SUITE(modelnet_search_local_policy_tests, BasicTestingSetup)

namespace {

ModelSearchRecord MakeRecord(const std::string& name, const std::vector<unsigned char>& pk,
                             const std::vector<unsigned char>& sk, uint8_t tag)
{
    ModelSearchRecord r;
    r.model_id.data[0] = tag;
    r.artifact_id.data[0] = static_cast<unsigned char>(tag + 1);
    r.canonical_name = name;
    r.display_name = name;
    r.pubkey = pk;
    r.published_at = tag;
    r.expires_at = 1'000'000;
    std::string err;
    BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
    r.signed_ok = true;
    return r;
}

size_t Hits(const SearchIndex& idx, const std::string& text)
{
    SearchQuery q;
    q.text = text;
    q.scope = SearchScope::LOCAL;
    return idx.Search(q, 10).size();
}

std::string Upper(std::string s)
{
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

BOOST_AUTO_TEST_CASE(hidden_models_and_muted_publishers_survive_a_reload)
{
    // hidesearchmodel and mutesearchpublisher are the local search policy
    // (doc/modelnet/directory.md). The index kept them in memory only, so a
    // helper restart, which loads search-index.json again, showed the hidden
    // models and the muted publishers' records again. A publisher id given in
    // upper case was stored as given and never matched the records.
    std::vector<unsigned char> pk_a, sk_a, pk_b, sk_b;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk_a, sk_a, err));
    BOOST_REQUIRE(GenerateMlDsa44(pk_b, sk_b, err));
    const auto spam = MakeRecord("Spam Model", pk_a, sk_a, 1);
    const auto other = MakeRecord("Other Model", pk_b, sk_b, 2);
    const auto kept = MakeRecord("Kept Model", pk_b, sk_b, 3);

    SearchIndex idx;
    BOOST_REQUIRE(idx.Put(spam, 10, err));
    BOOST_REQUIRE(idx.Put(other, 10, err));
    BOOST_REQUIRE(idx.Put(kept, 10, err));
    BOOST_REQUIRE_EQUAL(Hits(idx, "spam"), 1U);

    idx.MutePublisher(Upper(spam.publisher_identity.Hex()), true);
    BOOST_CHECK(idx.Muted(spam.publisher_identity.Hex()));
    BOOST_CHECK_EQUAL(Hits(idx, "spam"), 0U);
    idx.Hide(other.model_id, true);
    BOOST_CHECK_EQUAL(Hits(idx, "other"), 0U);
    BOOST_CHECK_EQUAL(Hits(idx, "kept"), 1U);

    const fs::path path = m_path_root / "search-local-policy" / "search-index.json";
    BOOST_REQUIRE(idx.Save(path, err));
    SearchIndex reloaded;
    BOOST_REQUIRE(reloaded.Load(path, 10, err));
    BOOST_CHECK(reloaded.Muted(spam.publisher_identity.Hex()));
    BOOST_CHECK(reloaded.Hidden(other.model_id));
    BOOST_CHECK_EQUAL(Hits(reloaded, "spam"), 0U);
    BOOST_CHECK_EQUAL(Hits(reloaded, "other"), 0U);
    BOOST_CHECK_EQUAL(Hits(reloaded, "kept"), 1U);

    // Undoing them is kept as well.
    reloaded.MutePublisher(spam.publisher_identity.Hex(), false);
    reloaded.Hide(other.model_id, false);
    BOOST_REQUIRE(reloaded.Save(path, err));
    SearchIndex again;
    BOOST_REQUIRE(again.Load(path, 10, err));
    BOOST_CHECK(!again.Muted(spam.publisher_identity.Hex()));
    BOOST_CHECK(!again.Hidden(other.model_id));
    BOOST_CHECK_EQUAL(Hits(again, "spam"), 1U);
    BOOST_CHECK_EQUAL(Hits(again, "other"), 1U);
}

BOOST_AUTO_TEST_CASE(hide_and_mute_refuse_an_id_they_cannot_apply)
{
    // hidesearchmodel ignored that the id did not resolve and hid the null
    // id; mutesearchpublisher took any string. Both answered as if they had
    // applied the policy.
    const fs::path dir = m_path_root / "search-local-policy-rpc";
    ModelCatalog cat{dir, 8 << 20};
    const auto call = [&](const std::string& method, const std::string& arg, UniValue& result, std::string& code) {
        UniValue params(UniValue::VARR);
        params.push_back(arg);
        UniValue req(UniValue::VOBJ);
        req.pushKV("method", method);
        req.pushKV("params", params);
        result = UniValue(UniValue::VOBJ);
        code.clear();
        std::string err;
        return DispatchHelperRpc(cat, req, result, code, err);
    };
    UniValue result;
    std::string code;
    BOOST_CHECK(!call("hidesearchmodel", "not-a-model", result, code));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");
    BOOST_CHECK(!call("mutesearchpublisher", "not-a-publisher", result, code));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");
    BOOST_CHECK(!call("mutesearchpublisher", std::string(95, 'a'), result, code));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");

    const std::string publisher = std::string(96, 'A');
    BOOST_REQUIRE_MESSAGE(call("mutesearchpublisher", publisher, result, code), code);
    BOOST_CHECK(result["muted"].get_bool());
    BOOST_REQUIRE_MESSAGE(call("unmutesearchpublisher", publisher, result, code), code);
    BOOST_CHECK(!result["muted"].get_bool());
}

BOOST_AUTO_TEST_CASE(policy_writes_load_existing_state_and_rollback_on_failed_save)
{
    const fs::path dir = m_path_root / "search-policy-write-recovery";
    const fs::path snapshot = dir / "search-index.json";
    const fs::path temporary = dir / "search-index.json.tmp";
    const std::string old_publisher(96, 'a');
    const std::string new_publisher(96, 'b');
    const std::string control_publisher(96, 'c');
    const std::string model_hex(96, 'd');
    Digest48 model_id;
    std::string err, code;
    BOOST_REQUIRE(Digest48::FromHex(model_hex, model_id, err));
    ModelSearchRecord record;
    record.model_id.data[0] = 1;
    record.artifact_id.data[0] = 2;
    record.canonical_name = "Retained Model";
    record.display_name = record.canonical_name;
    record.local_catalog = true;
    SearchIndex saved;
    BOOST_REQUIRE_MESSAGE(saved.Put(record, 10, err), err);
    saved.MutePublisher(old_publisher, true);
    BOOST_REQUIRE(saved.Save(snapshot, err));
    ModelCatalog cat{dir, 8 << 20};

    const auto call = [&](const std::string& method, const std::string& id) {
        UniValue params(UniValue::VARR);
        params.push_back(id);
        UniValue request(UniValue::VOBJ);
        request.pushKV("method", method);
        request.pushKV("params", params);
        UniValue result;
        code.clear();
        err.clear();
        return DispatchHelperRpc(cat, request, result, code, err);
    };
    const auto read_policy = [&] {
        SearchIndex reopened;
        std::string read_error;
        BOOST_REQUIRE(reopened.Load(snapshot, 10, read_error));
        return reopened;
    };

    // Write before any search/feed RPC has loaded the snapshot.
    BOOST_REQUIRE(call("mutesearchpublisher", new_publisher));
    BOOST_CHECK(read_policy().Muted(old_publisher));
    BOOST_CHECK(read_policy().Muted(new_publisher));
    BOOST_CHECK(read_policy().Get(record.model_id) != nullptr);

    BOOST_REQUIRE(fs::create_directory(temporary));
    const fs::path obstruction = temporary / "obstruction";
    {
        std::ofstream out(obstruction);
        out << "keep the temporary path blocked";
        BOOST_REQUIRE(out.good());
    }
    BOOST_CHECK(!call("unmutesearchpublisher", old_publisher));
    BOOST_CHECK_EQUAL(code, "IO_ERROR");
    BOOST_CHECK(!call("hidesearchmodel", model_hex));
    BOOST_CHECK_EQUAL(code, "IO_ERROR");
    BOOST_REQUIRE(fs::remove(obstruction));
    BOOST_REQUIRE(fs::remove(temporary));

    // An unrelated save must not persist either rejected in-memory change.
    BOOST_REQUIRE(call("mutesearchpublisher", control_publisher));
    const SearchIndex after_control = read_policy();
    BOOST_CHECK(after_control.Muted(old_publisher));
    BOOST_CHECK(after_control.Muted(new_publisher));
    BOOST_CHECK(after_control.Muted(control_publisher));
    BOOST_CHECK(!after_control.Hidden(model_id));

    BOOST_REQUIRE(call("unmutesearchpublisher", old_publisher));
    BOOST_REQUIRE(call("hidesearchmodel", model_hex));
    const SearchIndex after_retry = read_policy();
    BOOST_CHECK(!after_retry.Muted(old_publisher));
    BOOST_CHECK(after_retry.Muted(new_publisher));
    BOOST_CHECK(after_retry.Muted(control_publisher));
    BOOST_CHECK(after_retry.Hidden(model_id));
}

BOOST_AUTO_TEST_SUITE_END()
