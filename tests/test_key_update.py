import os
import unittest
from dataclasses import replace
from unittest import mock

import numpy as np

from ris_sem_project import protocol
from ris_sem_project.params import PARAM_I, setup
from ris_sem_project.parties import ProtocolAbort
from ris_sem_project.parties.qpase_server import PeerLink, QPASEServer, ShareOutcome
from ris_sem_project.parties.qpase_user import QPASEUser
from ris_sem_project.parties.types import KeyUpdateShare
from ris_sem_project.primitives import signature, symmetric
from ris_sem_project.primitives.encoding import int_bytes, pack
from ris_sem_project.primitives.linear_hash import linear_hash
from ris_sem_project.primitives.ring import Ring
from ris_sem_project.primitives.sampling import uniform
from ris_sem_project.primitives.secret_sharing import reconstruct

PASSWORD = "correct horse battery staple"
DOCUMENTS = (
    (1, "medical", b"Blood panel, 14 Sep 2026. Haemoglobin 14.1 g/dL, LDL 2.9 mmol/L, HbA1c 5.2%. No follow-up."),
    (2, "travel", b"Booking KX42QP: Mumbai BOM to Lisbon LIS, 3 Nov 2026 09:40, seat 23A, one checked bag."),
)
SUBSETS = ((1, 2), (2, 3))
"""The server subsets of {1, 2, 3} whose Lagrange coefficients at 0 are integers."""

SENDER, RECEIVER = 2, 1

RING = Ring(PARAM_I.q, PARAM_I.n)


def attempts(servers):
    """mu_u of alice on every server."""
    return {i: server.users["alice"].fail_count for i, server in servers.items()}


def state(server):
    """What S_i exposes about its key epoch: k_i, pk_i, omega and every mu_u."""
    return (
        server.key.k_i.tolist(),
        server.key.pk_i.tolist(),
        server.epoch,
        {user_id: record.fail_count for user_id, record in server.users.items()},
    )


def master_key(servers, ids):
    """K = sum_i lambda_i k_i over the servers in ids."""
    return reconstruct(RING, {i: servers[i].key.k_i for i in ids})


def storage_of(server):
    return {user_id: list(items) for user_id, items in server.storage.items()}


def registered_alice(pp, servers):
    """Register alice and log in once on {1, 2} and once on {2, 3}, so every server has mu_u > 0."""
    alice = QPASEUser(pp, "alice", PASSWORD)
    registered = protocol.register(alice, servers)
    for ids in SUBSETS:
        protocol.login(alice, servers, ids)
    return alice, registered


class KeyUpdateTest(unittest.TestCase):
    """One key update on N = 3, t = 2 after alice registered, logged in and outsourced two documents."""

    @classmethod
    def setUpClass(cls):
        cls.pp = setup(PARAM_I, N=3, t=2, mu=10)
        cls.servers = protocol.setup_servers(cls.pp)
        alice, cls.registered = registered_alice(cls.pp, cls.servers)
        for i, keyword, document in DOCUMENTS:
            protocol.outsource(alice, cls.servers[1], keyword, document, i)
        cls.attempts_before = attempts(cls.servers)
        cls.state_before = {i: state(server) for i, server in cls.servers.items()}
        cls.storage_before = {i: storage_of(server) for i, server in cls.servers.items()}
        cls.records_before = {i: replace(server.users["alice"]) for i, server in cls.servers.items()}
        cls.master_before = {ids: master_key(cls.servers, ids) for ids in SUBSETS}
        cls.k_before = {i: server.key.k_i for i, server in cls.servers.items()}
        cls.update = protocol.key_update(cls.servers)

    def test_every_key_share_and_public_key_changed_and_the_epoch_is_one(self):
        for i, server in self.servers.items():
            with self.subTest(server=i):
                k_before, pk_before, epoch_before, _ = self.state_before[i]
                self.assertEqual(epoch_before, 0)
                self.assertEqual(server.epoch, 1)
                self.assertNotEqual(server.key.k_i.tolist(), k_before)
                self.assertNotEqual(server.key.pk_i.tolist(), pk_before)

    def test_mu_u_is_reset_on_every_server(self):
        self.assertTrue(all(count > 0 for count in self.attempts_before.values()), "reset must not be vacuous")
        self.assertEqual(attempts(self.servers), {1: 0, 2: 0, 3: 0})

    def test_master_key_is_unchanged_for_every_integer_subset(self):
        for ids in SUBSETS:
            with self.subTest(ids=ids):
                np.testing.assert_array_equal(master_key(self.servers, ids), self.master_before[ids])

    def test_pre_update_user_logs_in_on_either_subset_with_the_same_pk_u_and_k_u(self):
        for ids in SUBSETS:
            with self.subTest(ids=ids):
                run = protocol.login(QPASEUser(self.pp, "alice", PASSWORD), self.servers, ids)
                self.assertEqual(run.user_pk, self.registered.key_message.user_pk)
                self.assertEqual(run.k_u, self.registered.k_u)

    def test_pre_update_documents_are_retrieved_byte_equal(self):
        alice = QPASEUser(self.pp, "alice", PASSWORD)
        protocol.login(alice, self.servers, (1, 2))
        for _, keyword, document in DOCUMENTS:
            with self.subTest(keyword=keyword):
                self.assertEqual(protocol.retrieve(alice, self.servers, keyword).documents, [document])

    def test_user_records_and_outsourced_items_are_untouched(self):
        for i, server in self.servers.items():
            with self.subTest(server=i):
                record = server.users["alice"]
                expected = self.records_before[i]
                self.assertEqual((record.user_pk, record.hint), (expected.user_pk, expected.hint))
                self.assertEqual(storage_of(server), self.storage_before[i])

    def test_run_records_nine_shares_and_the_commitment_check_of_each(self):
        pairs = [(j, i) for j in (1, 2, 3) for i in (1, 2, 3)]
        self.assertEqual(sorted(self.update.checks), pairs)
        for (j, i), check in self.update.checks.items():
            with self.subTest(sender=j, receiver=i):
                share = self.update.shares[j][i]
                self.assertEqual((share.sender, share.receiver, share.epoch), (j, i, 0))
                self.assertEqual(check.outcome, ShareOutcome.ACCEPTED)
                self.assertEqual(check.recomputed, check.committed)

    def test_key_shares_moved_along_a_line_through_zero(self):
        delta = {i: (server.key.k_i - self.k_before[i]) % PARAM_I.q for i, server in self.servers.items()}
        for i in (2, 3):
            with self.subTest(server=i):
                np.testing.assert_array_equal(delta[i], i * delta[1] % PARAM_I.q)


class Forger:
    """S_j as an adversary, signing with a key the test holds, so one field of a share can be wrong
    while the signature over it still verifies at the receiver."""

    def __init__(self, server, sender):
        self.sender = sender
        self.channel_key = server.peers[sender].channel_key
        self.verification_key, self._sk = signature.keypair_from_seed(os.urandom(signature.SEED_SIZE))
        self.link = PeerLink(verification_key=self.verification_key, channel_key=self.channel_key)
        self.receiver = server.server_id
        self.alpha = uniform(RING, (RING.n,))

    def share(self, *, epoch, commitment=None, plaintext=None, ciphertext=None):
        """The share S_j deals to the receiver for [F]_j(X) = alpha X, with the chosen field replaced.

        epoch is omega. commitment replaces h_1, plaintext replaces F_ji before it is encrypted, and
        ciphertext replaces E(i, F_ji) as it goes on the wire.
        """
        h = RING.to_bytes(linear_hash(RING, self.alpha)) if commitment is None else commitment
        f_ji = RING.to_bytes(self.alpha * self.receiver % RING.q) if plaintext is None else plaintext
        encrypted = symmetric.encrypt(self.channel_key, f_ji) if ciphertext is None else ciphertext
        signed = pack(int_bytes(self.sender), int_bytes(epoch), h, encrypted)
        return KeyUpdateShare(
            sender=self.sender,
            receiver=self.receiver,
            epoch=epoch,
            commitments=(h,),
            encrypted_share=encrypted,
            signature=signature.sign(self._sk, signed),
        )


def flip(data: bytes) -> bytes:
    middle = len(data) // 2
    return data[:middle] + bytes([data[middle] ^ 1]) + data[middle + 1 :]


class RejectedShareTest(unittest.TestCase):
    """S_1 refuses a share that is wrong in one way and applies nothing. No test here updates a key."""

    @classmethod
    def setUpClass(cls):
        cls.pp = setup(PARAM_I, N=3, t=2, mu=10)
        cls.servers = protocol.setup_servers(cls.pp)
        registered_alice(cls.pp, cls.servers)
        cls.receiver = cls.servers[RECEIVER]
        cls.dealt = {j: server.key_update_shares() for j, server in cls.servers.items()}
        cls.honest = {j: cls.dealt[j][RECEIVER] for j in cls.servers}

    def setUp(self):
        self.state_before = {i: state(server) for i, server in self.servers.items()}
        self.addCleanup(self.assert_nothing_changed)

    def assert_nothing_changed(self):
        self.assertEqual({i: state(server) for i, server in self.servers.items()}, self.state_before)

    def assert_rejected(self, shares, outcome):
        self.assertTrue(self.state_before[RECEIVER][3]["alice"] > 0, "mu_u must be nonzero for the reset to show")
        with self.assertRaises(ProtocolAbort):
            self.receiver.key_update_apply(shares)
        if outcome is not None:
            by_sender = {check.sender: check.outcome for check in self.receiver.key_update_check(shares)}
            self.assertEqual(by_sender[SENDER], outcome)

    def with_second_share(self, share):
        """S_1's three shares with the one from S_2 replaced, so shares before and after it are honest."""
        return [share if s.sender == SENDER else s for s in self.honest.values()]

    def test_honest_shares_pass_the_check_and_would_be_applied(self):
        checks = self.receiver.key_update_check(list(self.honest.values()))
        self.assertEqual([c.outcome for c in checks], [ShareOutcome.ACCEPTED] * 3)

    def test_forged_share_with_every_field_right_is_accepted(self):
        forger = Forger(self.receiver, SENDER)
        with mock.patch.dict(self.receiver.peers, {SENDER: forger.link}):
            share = forger.share(epoch=0)
            (check,) = self.receiver.key_update_check([share])
        self.assertEqual(check.outcome, ShareOutcome.ACCEPTED)

    def test_corrupted_commitment_is_rejected(self):
        forger = Forger(self.receiver, SENDER)
        bad = RING.to_bytes((linear_hash(RING, forger.alpha) + 1) % RING.q)
        share = forger.share(epoch=0, commitment=bad)
        with mock.patch.dict(self.receiver.peers, {SENDER: forger.link}):
            self.assert_rejected(self.with_second_share(share), ShareOutcome.COMMITMENT_MISMATCH)
            (check,) = self.receiver.key_update_check([share])
        self.assertNotEqual(check.recomputed, check.committed)

    def test_corrupted_share_value_is_rejected_by_the_commitment(self):
        forger = Forger(self.receiver, SENDER)
        wrong = RING.to_bytes((forger.alpha * RECEIVER + 1) % RING.q)
        with mock.patch.dict(self.receiver.peers, {SENDER: forger.link}):
            self.assert_rejected(
                self.with_second_share(forger.share(epoch=0, plaintext=wrong)), ShareOutcome.COMMITMENT_MISMATCH
            )

    def test_corrupted_encrypted_share_is_rejected(self):
        forger = Forger(self.receiver, SENDER)
        ciphertext = symmetric.encrypt(forger.channel_key, bytes(4 * RING.n))
        with mock.patch.dict(self.receiver.peers, {SENDER: forger.link}):
            self.assert_rejected(
                self.with_second_share(forger.share(epoch=0, ciphertext=flip(ciphertext))), ShareOutcome.DECRYPT_FAILED
            )

    def test_share_encrypted_under_another_pairs_key_is_rejected(self):
        forger = Forger(self.receiver, SENDER)
        other_key = self.receiver.peers[3].channel_key
        ciphertext = symmetric.encrypt(other_key, RING.to_bytes(forger.alpha * RECEIVER % RING.q))
        with mock.patch.dict(self.receiver.peers, {SENDER: forger.link}):
            self.assert_rejected(
                self.with_second_share(forger.share(epoch=0, ciphertext=ciphertext)), ShareOutcome.DECRYPT_FAILED
            )

    def test_share_value_not_reduced_mod_q_is_rejected(self):
        forger = Forger(self.receiver, SENDER)
        unreduced = (RING.q).to_bytes(4, "little") * RING.n
        with mock.patch.dict(self.receiver.peers, {SENDER: forger.link}):
            self.assert_rejected(
                self.with_second_share(forger.share(epoch=0, plaintext=unreduced)), ShareOutcome.MALFORMED
            )

    def test_bad_signature_is_rejected(self):
        share = self.honest[SENDER]
        other_key_signature = Forger(self.receiver, SENDER).share(epoch=0).signature
        for name, bad in (
            ("flipped signature", replace(share, signature=flip(share.signature))),
            ("signed by another key", replace(share, signature=other_key_signature)),
            ("tampered commitment", replace(share, commitments=(flip(share.commitments[0]),))),
            ("tampered ciphertext", replace(share, encrypted_share=flip(share.encrypted_share))),
        ):
            with self.subTest(name):
                self.assert_rejected(self.with_second_share(bad), ShareOutcome.BAD_SIGNATURE)

    def test_stale_or_future_epoch_is_rejected_even_when_signed(self):
        forger = Forger(self.receiver, SENDER)
        with mock.patch.dict(self.receiver.peers, {SENDER: forger.link}):
            for epoch in (1, 7, (1 << 32) - 1):
                with self.subTest(epoch=epoch):
                    self.assert_rejected(self.with_second_share(forger.share(epoch=epoch)), ShareOutcome.WRONG_EPOCH)

    def test_epoch_outside_the_wire_range_is_rejected(self):
        share = replace(self.honest[SENDER], epoch=1 << 32)
        self.assert_rejected(self.with_second_share(share), ShareOutcome.MALFORMED)

    def test_share_addressed_to_another_server_is_rejected(self):
        misaddressed = self.dealt[SENDER][3]
        self.assert_rejected(self.with_second_share(misaddressed), ShareOutcome.MALFORMED)

    def test_wrong_number_of_commitments_is_rejected(self):
        share = replace(self.honest[SENDER], commitments=())
        self.assert_rejected(self.with_second_share(share), ShareOutcome.MALFORMED)

    def test_one_share_from_each_of_the_n_servers_is_required(self):
        shares = list(self.honest.values())
        for name, bad in (
            ("a share missing", shares[:2]),
            ("a sender twice", shares[:2] + [shares[1]]),
            ("an extra share", shares + [shares[0]]),
            ("no shares", []),
        ):
            with self.subTest(name):
                self.assert_rejected(bad, None)

    def test_server_not_linked_to_its_peers_refuses_to_deal(self):
        with self.assertRaises(ProtocolAbort):
            QPASEServer(self.pp, 1).key_update_shares()

    def test_runner_applies_nothing_on_any_server_when_one_share_is_bad(self):
        real = self.servers[SENDER].key_update_shares

        def bad_signature_to_server_3():
            dealt = real()
            dealt[3] = replace(dealt[3], signature=flip(dealt[3].signature))
            return dealt

        with mock.patch.object(self.servers[SENDER], "key_update_shares", bad_signature_to_server_3):
            with self.assertRaises(ProtocolAbort):
                protocol.key_update(self.servers)


class RepeatedUpdateTest(unittest.TestCase):
    """Two updates in a row, then a replay of the first round's shares in the third."""

    @classmethod
    def setUpClass(cls):
        cls.pp = setup(PARAM_I, N=3, t=2, mu=10)
        cls.servers = protocol.setup_servers(cls.pp)
        _, cls.registered = registered_alice(cls.pp, cls.servers)
        cls.first = protocol.key_update(cls.servers)
        cls.second = protocol.key_update(cls.servers)

    def test_users_are_unaffected_after_two_updates(self):
        self.assertEqual({server.epoch for server in self.servers.values()}, {2})
        run = protocol.login(QPASEUser(self.pp, "alice", PASSWORD), self.servers, (2, 3))
        self.assertEqual((run.user_pk, run.k_u), (self.registered.key_message.user_pk, self.registered.k_u))

    def test_share_from_an_earlier_epoch_is_rejected_though_its_signature_verifies(self):
        receiver = self.servers[RECEIVER]
        dealt = {j: server.key_update_shares() for j, server in self.servers.items()}
        before = state(receiver)
        for name, run in (("epoch 1", self.second), ("epoch 0", self.first)):
            with self.subTest(name):
                stale = run.shares[SENDER][RECEIVER]
                shares = [stale if j == SENDER else dealt[j][RECEIVER] for j in self.servers]
                outcome = {c.sender: c.outcome for c in receiver.key_update_check(shares)}[SENDER]
                self.assertEqual(outcome, ShareOutcome.WRONG_EPOCH)
                with self.assertRaises(ProtocolAbort):
                    receiver.key_update_apply(shares)
                self.assertEqual(state(receiver), before)


if __name__ == "__main__":
    unittest.main()
