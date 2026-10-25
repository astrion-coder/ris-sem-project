import unittest
from dataclasses import replace
from unittest import mock

from ris_sem_project import protocol
from ris_sem_project.index import ScanOutcome, scan_item
from ris_sem_project.params import PARAM_I, Lattice, setup
from ris_sem_project.parties import LoginProof, ProtocolAbort, RetrieveResponse
from ris_sem_project.parties.qpase_server import QPASEServer
from ris_sem_project.parties.qpase_user import QPASEUser
from ris_sem_project.primitives import signature, symmetric
from ris_sem_project.primitives.encoding import pack
from ris_sem_project.primitives.secret_sharing import NonIntegerLagrangeError
from ris_sem_project.primitives.symmetric import aes_key

PASSWORD = "correct horse battery staple"

DOCUMENTS = (
    (1, "medical", (1,), b"Blood panel, 14 Sep 2026. Haemoglobin 14.1 g/dL, LDL 2.9 mmol/L, HbA1c 5.2%. No follow-up."),
    (2, "travel", (2,), b"Booking KX42QP: Mumbai BOM to Lisbon LIS, 3 Nov 2026 09:40, seat 23A, one checked bag."),
    (3, "medical", (2, 3), b"Lumbar spine MRI: mild disc bulge at L4-L5, no nerve compression. Physiotherapy advised."),
    (4, "travel", (3,), b"Hotel Alfama confirmation 88231: 3-7 Nov 2026, 4 nights, double room, breakfast included."),
)
"""(item id i, keyword w, servers holding (Ct, C, i), document d). Item 3 is stored on two servers."""


def flip(data: bytes) -> bytes:
    middle = len(data) // 2
    return data[:middle] + bytes([data[middle] ^ 1]) + data[middle + 1 :]


def attempts(servers, user_id="alice"):
    """mu_u on every server."""
    return {i: server.users[user_id].fail_count for i, server in servers.items()}


class SetupServersTest(unittest.TestCase):
    def test_dkg_needs_one_share_from_every_server_addressed_to_the_receiver(self):
        pp = setup(PARAM_I, N=3, t=2, mu=1)
        servers = {i: QPASEServer(pp, i) for i in (1, 2, 3)}
        dealt = {i: server.dkg_genshare() for i, server in servers.items()}
        to_s1 = [dealt[i][1] for i in (1, 2, 3)]
        for name, shares in (
            ("missing", to_s1[:2]),
            ("duplicate sender", to_s1[:2] + [to_s1[1]]),
            ("addressed to S_2", to_s1[:2] + [dealt[3][2]]),
        ):
            with self.subTest(name), self.assertRaises(ProtocolAbort):
                servers[1].dkg_genkey(shares)
        self.assertIsNone(servers[1].key)
        servers[1].dkg_genkey(to_s1)
        self.assertIsNotNone(servers[1].key)

    def test_dkg_run_records_every_share_and_keys_every_server(self):
        pp = setup(PARAM_I, N=3, t=2, mu=1)
        servers = {i: QPASEServer(pp, i) for i in (1, 2, 3)}
        run = protocol.dkg(servers)
        self.assertEqual(
            {(i, j): (share.sender, share.receiver) for i, row in run.shares.items() for j, share in row.items()},
            {(i, j): (i, j) for i in (1, 2, 3) for j in (1, 2, 3)},
        )
        self.assertTrue(all(server.key is not None for server in servers.values()))


class RegisterLoginTest(unittest.TestCase):
    """Register and Login (Sec. IV-B, IV-C) at PARAM I with N = 3, t = 2."""

    @classmethod
    def setUpClass(cls):
        cls.pp = setup(PARAM_I, N=3, t=2, mu=10)
        cls.servers = protocol.setup_servers(cls.pp)
        cls.registrant = QPASEUser(cls.pp, "alice", PASSWORD)
        cls.registered = protocol.register(cls.registrant, cls.servers)
        cls.alice = QPASEUser(cls.pp, "alice", PASSWORD)
        cls.first_login = protocol.login(cls.alice, cls.servers, (1, 2))

    def test_register_stores_pk_u_and_the_hint_on_every_server(self):
        message = self.registered.key_message
        self.assertEqual(len(message.hint), self.pp.ell * self.pp.n // 8)
        for server in self.servers.values():
            record = server.users["alice"]
            self.assertEqual((record.user_pk, record.hint), (message.user_pk, message.hint))

    def test_login_on_either_integer_subset_recovers_the_registered_key(self):
        second_login = protocol.login(QPASEUser(self.pp, "alice", PASSWORD), self.servers, (2, 3))
        for run in (self.first_login, second_login):
            self.assertEqual(run.user_pk, self.registered.key_message.user_pk)
            self.assertEqual(run.k_u, self.registered.k_u)

    def test_subset_with_non_integer_lagrange_coefficients_is_refused_before_any_server_counts_it(self):
        before = attempts(self.servers)
        with self.assertRaises(NonIntegerLagrangeError):
            protocol.login(QPASEUser(self.pp, "alice", PASSWORD), self.servers, (1, 3))
        self.assertEqual(attempts(self.servers), before)

    def test_wrong_password_aborts_at_L2_after_one_counted_attempt_per_contacted_server(self):
        before = attempts(self.servers)
        with self.assertRaises(ProtocolAbort):
            protocol.login(QPASEUser(self.pp, "alice", PASSWORD + "!"), self.servers, (1, 2))
        self.assertEqual(attempts(self.servers), {1: before[1] + 1, 2: before[2] + 1, 3: before[3]})

    def test_L3_accepts_sig_u_once_and_counts_each_rejection(self):
        server = self.servers[1]
        before = attempts(self.servers)[1]
        sid = server.new_session("alice")
        proof = self.alice.login_verify(self.first_login.k_u, self.first_login.user_pk, sid)
        self.assertTrue(server.login_verify(proof))
        self.assertFalse(server.login_verify(proof))
        sid = server.new_session("alice")
        _, other_sk = signature.keypair_from_seed(bytes(32))
        forged = LoginProof(user_id="alice", session_id=sid, signature=signature.sign(other_sk, pack(b"alice", sid)))
        self.assertFalse(server.login_verify(forged))
        self.assertEqual(attempts(self.servers)[1], before + 2)

    def test_login_aborts_when_a_contacted_server_returns_another_pk_u_or_hint(self):
        record = self.servers[2].users["alice"]
        other_pk, _ = signature.keypair_from_seed(bytes(32))
        for field, forged in (("user_pk", other_pk), ("hint", bytes(len(record.hint)))):
            with self.subTest(field), mock.patch.object(record, field, forged), self.assertRaises(ProtocolAbort):
                protocol.login(QPASEUser(self.pp, "alice", PASSWORD), self.servers, (1, 2))
        self.assertEqual(record.user_pk, self.registered.key_message.user_pk)
        self.assertEqual(record.hint, self.registered.key_message.hint)

    def test_login_aborts_when_a_contacted_server_rejects_sig_u(self):
        with mock.patch.object(self.servers[2], "login_verify", return_value=False):
            with self.assertRaises(ProtocolAbort):
                protocol.login(QPASEUser(self.pp, "alice", PASSWORD), self.servers, (1, 2))

    def test_duplicate_register_is_refused_and_keeps_the_record(self):
        with self.assertRaises(ProtocolAbort):
            protocol.register(QPASEUser(self.pp, "alice", "a different password"), self.servers)
        for server in self.servers.values():
            self.assertEqual(server.users["alice"].user_pk, self.registered.key_message.user_pk)

    def test_no_session_survives_register(self):
        with self.assertRaises(ProtocolAbort):
            self.registrant.outsource("medical", b"d", 1)
        with self.assertRaises(ProtocolAbort):
            self.registrant.retrieve_request(["medical"])


class LoginLimitTest(unittest.TestCase):
    def test_attempt_mu_plus_one_is_refused_at_L1_even_with_the_right_password(self):
        pp = setup(PARAM_I, N=3, t=2, mu=2)
        servers = protocol.setup_servers(pp)
        protocol.register(QPASEUser(pp, "alice", PASSWORD), servers)
        with self.assertRaises(ProtocolAbort):
            protocol.login(QPASEUser(pp, "alice", "wrong password"), servers, (1, 2))
        alice = QPASEUser(pp, "alice", PASSWORD)
        protocol.login(alice, servers, (1, 2))
        requests = alice.toprf_request((1, 2))
        for i in (1, 2):
            with self.subTest(server=i), self.assertRaises(ProtocolAbort):
                servers[i].toprf_evaluate(requests[i])
        self.assertEqual(attempts(servers), {1: 2, 2: 2, 3: 0})
        self.assertEqual(servers[3].toprf_evaluate(requests[1]).user_pk, servers[1].users["alice"].user_pk)


class OutsourceRetrieveTest(unittest.TestCase):
    """Outsource and Retrieve (Sec. IV-D, IV-E) of four documents under two keywords on three servers."""

    @classmethod
    def setUpClass(cls):
        cls.pp = setup(PARAM_I, N=3, t=2, mu=10)
        cls.servers = protocol.setup_servers(cls.pp)
        cls.alice = QPASEUser(cls.pp, "alice", PASSWORD)
        cls.registered = protocol.register(cls.alice, cls.servers)
        protocol.login(cls.alice, cls.servers, (1, 2))
        cls.outsourced = {}
        for i, w, (first, *copies), d in DOCUMENTS:
            cls.outsourced[i] = protocol.outsource(cls.alice, cls.servers[first], w, d, i)
            for s in copies:
                cls.servers[s].outsource_store(cls.outsourced[i].request)

    def test_retrieve_returns_exactly_the_documents_filed_under_the_keyword(self):
        for keyword in ("medical", "travel"):
            with self.subTest(keyword=keyword):
                run = protocol.retrieve(self.alice, self.servers, keyword)
                filed = [(i, holders, d) for i, w, holders, d in DOCUMENTS if w == keyword]
                self.assertEqual([(o.item_id, o.server_ids, o.data) for o in run.opened], filed)
                self.assertEqual(run.documents, [d for _, _, d in filed])
                for server_id, scan in run.scans.items():
                    expected = {
                        i: ScanOutcome.MATCH if w == keyword else ScanOutcome.DECRYPT_FAILED
                        for i, w, holders, _ in DOCUMENTS
                        if server_id in holders
                    }
                    self.assertEqual({item.item_id: item.outcome for item in scan.items}, expected)
                if keyword == "medical":
                    responses = [scan.response for scan in run.scans.values()]
                    self.assertEqual(self.alice.retrieve_finalize([keyword], responses), run.documents)

    def test_absent_keyword_returns_nothing(self):
        run = protocol.retrieve(self.alice, self.servers, "taxes")
        self.assertEqual(run.documents, [])
        self.assertEqual(sum(len(scan.items) for scan in run.scans.values()), sum(len(h) for _, _, h, _ in DOCUMENTS))
        for scan in run.scans.values():
            self.assertEqual(scan.response.results, ())
            self.assertTrue(all(item.outcome is ScanOutcome.DECRYPT_FAILED for item in scan.items))

    def test_outsource_rejects_any_change_to_the_signed_item(self):
        request = self.outsourced[1].request
        item = request.item
        server = self.servers[1]
        stored = list(server.storage["alice"])
        for name, tampered in (
            ("Ct", replace(request, item=replace(item, index_ct=flip(item.index_ct)))),
            ("C", replace(request, item=replace(item, data_ct=flip(item.data_ct)))),
            ("i", replace(request, item=replace(item, item_id=99))),
            ("sig_Ct", replace(request, signature=flip(request.signature))),
        ):
            with self.subTest(name):
                self.assertFalse(server.outsource_store(tampered))
        self.assertEqual(server.storage["alice"], stored)

    def test_retrieve_request_without_a_valid_sig_dsk_aborts(self):
        request = self.alice.retrieve_request(["medical"])
        for name, tampered in (
            ("sig_dsk", replace(request, signature=flip(request.signature))),
            ("dsk", replace(request, search_keys=(flip(request.search_keys[0]),))),
        ):
            with self.subTest(name), self.assertRaises(ProtocolAbort):
                self.servers[1].retrieve_scan(tampered)

    def test_user_rejects_items_forged_by_a_server_that_saw_both_search_keys(self):
        aes = {w: aes_key(self.alice.search_key(w)) for w in ("medical", "travel")}
        medical, travel = self.outsourced[1].request.item, self.outsourced[2].request.item
        swapped_document = replace(medical, data_ct=travel.data_ct, item_id=11)
        travel_index = symmetric.decrypt(aes["travel"], travel.index_ct)
        moved_index = replace(travel, index_ct=symmetric.encrypt(aes["medical"], travel_index), item_id=12)
        garbage_index = replace(medical, index_ct=symmetric.encrypt(aes["medical"], b"no index"), item_id=13)
        response = RetrieveResponse(server_id=1, results=(medical, swapped_document, moved_index, garbage_index))
        opened = self.alice.retrieve_open(["medical"], [response])
        self.assertEqual(
            [(o.item_id, o.scan.outcome, o.data) for o in opened],
            [
                (1, ScanOutcome.MATCH, DOCUMENTS[0][3]),
                (11, ScanOutcome.SIGNATURE_INVALID, None),
                (12, ScanOutcome.PRF_MISMATCH, None),
                (13, ScanOutcome.MALFORMED, None),
            ],
        )

    def test_storage_replaces_by_id_and_keeps_the_newest_M_items(self):
        server = QPASEServer(self.pp, 1, capacity=3)
        server.register_user("alice")
        server.register_store_key(self.registered.key_message)
        revised = self.alice.outsource("medical", b"Blood panel, revised: LDL 2.7 mmol/L.", 1)
        for request in (self.outsourced[1].request, self.outsourced[2].request, revised):
            self.assertTrue(server.outsource_store(request))
        self.assertEqual(server.storage["alice"], [self.outsourced[2].request.item, revised.item])
        for i in (3, 4):
            self.assertTrue(server.outsource_store(self.outsourced[i].request))
        self.assertEqual([item.item_id for item in server.storage["alice"]], [1, 3, 4])

    def test_second_user_sees_only_their_own_documents(self):
        bob = QPASEUser(self.pp, "bob", "bob's own passphrase")
        protocol.register(bob, self.servers)
        bob_login = protocol.login(bob, self.servers, (2, 3))
        prescription = b"Prescription for Bob: amoxicillin 500 mg three times daily for 7 days."
        protocol.outsource(bob, self.servers[1], "medical", prescription, 1)
        run = protocol.retrieve(bob, self.servers, "medical")
        self.assertEqual(run.documents, [prescription])
        self.assertIn(self.outsourced[1].request.item, self.servers[1].storage["alice"])
        lattice, bob_dsk = Lattice.from_pp(self.pp), run.request.search_keys[0]
        for server in self.servers.values():
            for item in server.storage["alice"]:
                scan = scan_item(lattice, bob_login.user_pk, bob_dsk, item)
                self.assertIs(scan.outcome, ScanOutcome.DECRYPT_FAILED)
        with self.assertRaises(ProtocolAbort):
            self.servers[1].retrieve_scan(replace(run.request, user_id="alice"))


if __name__ == "__main__":
    unittest.main()
