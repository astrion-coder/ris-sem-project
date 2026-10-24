import dataclasses
import unittest

import numpy as np

from ris_sem_project.params import PARAM_I, PARAM_II, Lattice, setup
from ris_sem_project.primitives.bp_prf import encode_input
from ris_sem_project.primitives.secret_sharing import NonIntegerLagrangeError, genkey, genshare, reconstruct
from ris_sem_project.primitives.toprf import blind, combine, evaluate, finalize, server_public_key

IDS = (1, 2, 3)


class ToprfTest(unittest.TestCase):
    """Pi_TOPRF at PARAM I with N = 3, t = 2 and keys from the DKG."""

    @classmethod
    def setUpClass(cls):
        pp = setup(PARAM_I, N=3, t=2, mu=5)
        lattice = Lattice.from_pp(pp)
        cls.ring, cls.a, cls.sigma = lattice.ring, lattice.a, pp.sigma
        dealt = [genshare(cls.ring, pp.t, IDS, pp.sigma) for _ in IDS]
        cls.keys = {j: genkey(cls.ring, [shares[j] for shares in dealt]) for j in IDS}
        cls.public_keys = {j: server_public_key(cls.ring, cls.a, k, cls.sigma) for j, k in cls.keys.items()}
        cls.ax = lattice.prf.a_x(encode_input(b"QPASE/test/psw/correct horse battery", pp.L))
        cls.ax_wrong = lattice.prf.a_x(encode_input(b"QPASE/test/psw/correct horse battery!", pp.L))
        cls.F_reg = cls.run_toprf(cls.ax, (1, 2))
        cls.k_u, cls.hint = finalize(cls.ring, cls.F_reg)

    @classmethod
    def run_toprf(cls, ax, ids):
        b, r = blind(cls.ring, cls.a, ax, cls.sigma)
        evaluations = {i: evaluate(cls.ring, b, cls.keys[i], cls.sigma) for i in ids}
        return combine(cls.ring, evaluations, {i: cls.public_keys[i] for i in ids}, r)

    def test_same_password_gives_the_same_key_every_login(self):
        self.assertEqual(len(self.k_u), self.ring.ell * self.ring.n // 8)
        for login in range(10):
            for ids in ((1, 2), (2, 3)):
                with self.subTest(login=login, ids=ids):
                    k_u, _ = finalize(self.ring, self.run_toprf(self.ax, ids), self.hint)
                    self.assertEqual(k_u, self.k_u)

    def test_login_differs_from_register_by_small_even_noise(self):
        for ids in ((1, 2), (2, 3)):
            with self.subTest(ids=ids):
                d = self.ring.centered(self.run_toprf(self.ax, ids) - self.F_reg)
                self.assertTrue((d % 2 == 0).all())
                self.assertLess(np.abs(d).max(), self.ring.q // 8)

    def test_combine_gives_a_x_times_master_key_plus_even_noise(self):
        master = reconstruct(self.ring, self.keys)
        d = self.ring.centered(self.F_reg - self.ring.mul(self.ax, master))
        self.assertTrue((d % 2 == 0).all())
        self.assertLess(np.abs(d).max(), self.ring.q // 8)

    def test_wrong_password_flips_about_half_the_key_bits(self):
        k_wrong, _ = finalize(self.ring, self.run_toprf(self.ax_wrong, (1, 2)), self.hint)
        flipped = np.count_nonzero(self.ring.unpack_bits(k_wrong) != self.ring.unpack_bits(self.k_u))
        self.assertAlmostEqual(flipped / (self.ring.ell * self.ring.n), 0.5, delta=0.05)

    def test_non_integer_lagrange_subset_raises(self):
        b, r = blind(self.ring, self.a, self.ax, self.sigma)
        evaluations = {i: evaluate(self.ring, b, self.keys[i], self.sigma) for i in (1, 3)}
        with self.assertRaises(NonIntegerLagrangeError):
            combine(self.ring, evaluations, {i: self.public_keys[i] for i in (1, 3)}, r)


class SetupTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pp = setup(PARAM_I, N=3, t=2, mu=5)

    def test_from_pp_parses_the_published_vectors(self):
        lattice = Lattice.from_pp(self.pp)
        self.assertEqual((self.pp.q, self.pp.n, self.pp.ell, self.pp.p, self.pp.L), (2**28 - 57, 512, 28, 2, 128))
        self.assertEqual(lattice.a.shape, (28, 512))
        self.assertEqual(lattice.ring.to_bytes(lattice.a), self.pp.a)
        self.assertEqual(len({self.pp.a, self.pp.a0, self.pp.a1}), 3)

    def test_param_ii_runs_in_x595_plus_1(self):
        lattice = Lattice.from_pp(setup(PARAM_II, N=2, t=2, mu=5))
        self.assertEqual((lattice.ring.n, lattice.a.shape), (595, (28, 595)))

    def test_setup_rejects_bad_server_settings(self):
        for N, t, mu in ((3, 0, 5), (2, 3, 5), (3, 2, 0)):
            with self.subTest(N=N, t=t, mu=mu), self.assertRaises(ValueError):
                setup(PARAM_I, N=N, t=t, mu=mu)

    def test_from_pp_rejects_malformed_params(self):
        out_of_range = (2**28 - 57).to_bytes(4, "little") + self.pp.a[4:]
        for change in (
            {"a": self.pp.a[:-4]},
            {"a1": out_of_range},
            {"p": 3},
            {"ell": 27},
            {"L": 257},
            {"sigma": 0.0},
            {"q": 2**28 - 56},
            {"t": 4},
        ):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                Lattice.from_pp(dataclasses.replace(self.pp, **change))


if __name__ == "__main__":
    unittest.main()
