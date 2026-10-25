import unittest

from ris_sem_project.params import PARAM_I, PARAM_II, Lattice, setup
from ris_sem_project.parties.qpase_user import QPASEUser
from ris_sem_project.primitives.sampling import gaussian, uniform
from ris_sem_project.root_attack import evaluate_at_minus_one, match_threshold, offline_password_test

PASSWORD = "correct horse battery staple"
WRONG = ("password", "letmein", "hunter2", "qwerty123", "iloveyou")


def phi_reference(coefficients, q):
    return sum((-1) ** i * int(c) for i, c in enumerate(coefficients)) % q


def captured_request(params):
    """What S_1 receives from a user with a real password, and the user's phi(r) read from the user."""
    pp = setup(params, N=3, t=2, mu=3)
    user = QPASEUser(pp, "alice", PASSWORD)
    request = user.toprf_request([1, 2])[1]
    ring = Lattice.from_pp(pp).ring
    true_phi_r = int(ring.centered(phi_reference(user._phase.r, ring.q)))
    return pp, request, true_phi_r


class HomomorphismTest(unittest.TestCase):
    def test_evaluation_at_minus_one_matches_the_alternating_sum(self):
        ring = Lattice.from_pp(setup(PARAM_II, N=1, t=1, mu=1)).ring
        a = uniform(ring, (3, ring.n))
        self.assertEqual(evaluate_at_minus_one(ring, a).tolist(), [phi_reference(row, ring.q) for row in a])

    def test_it_is_a_ring_homomorphism_exactly_when_n_is_odd(self):
        for params, is_homomorphism in ((PARAM_II, True), (PARAM_I, False)):
            with self.subTest(params.name):
                ring = Lattice.from_pp(setup(params, N=1, t=1, mu=1)).ring
                a, b = uniform(ring, (ring.n,)), uniform(ring, (ring.n,))
                product = int(evaluate_at_minus_one(ring, ring.mul(a, b)))
                expected = int(evaluate_at_minus_one(ring, a)) * int(evaluate_at_minus_one(ring, b)) % ring.q
                self.assertEqual(product == expected, is_homomorphism)


class OfflinePasswordTestTest(unittest.TestCase):
    def test_param_ii_picks_out_the_password_and_recovers_phi_r(self):
        pp, request, true_phi_r = captured_request(PARAM_II)
        tau = match_threshold(pp)
        results = {r.password: r for r in offline_password_test(pp, request, (*WRONG[:2], PASSWORD, *WRONG[2:]))}
        self.assertEqual({p for p, r in results.items() if r.matched}, {PASSWORD})
        self.assertEqual(results[PASSWORD].phi_r, true_phi_r)
        self.assertLess(results[PASSWORD].residual, tau)
        for password in WRONG:
            with self.subTest(password):
                self.assertIsNone(results[password].phi_r)
                self.assertGreater(results[password].residual, 100 * tau)

    def test_param_i_matches_nothing_not_even_the_real_password(self):
        pp, request, _ = captured_request(PARAM_I)
        results = offline_password_test(pp, request, (PASSWORD, *WRONG))
        self.assertEqual([r.matched for r in results], [False] * len(results))
        self.assertTrue(all(r.residual > 100 * match_threshold(pp) for r in results))

    def test_threshold_is_far_above_the_true_noise_and_far_below_a_random_residual(self):
        pp = setup(PARAM_II, N=1, t=1, mu=1)
        ring = Lattice.from_pp(pp).ring
        noise = ring.centered(2 * evaluate_at_minus_one(ring, gaussian(ring, (2000, ring.n), pp.sigma)))
        self.assertLess(abs(noise).max(), match_threshold(pp))
        self.assertLess(100 * match_threshold(pp), pp.q // 4)

    def test_malformed_request_raises(self):
        pp, request, _ = captured_request(PARAM_II)
        with self.assertRaises(ValueError):
            offline_password_test(pp, type(request)(user_id="alice", blinded_input=b"short"), [PASSWORD])


if __name__ == "__main__":
    unittest.main()
