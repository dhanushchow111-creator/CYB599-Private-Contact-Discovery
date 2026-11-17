import unittest
from src.bfv_demo import *
A=['+12025550101','+12025550102','+12025550103','+12025550104']
B=['+12025550102','+12025550104','+12025550105','+12025550106']
class BFVTests(unittest.TestCase):
    def test_roundtrip(self):
        h=BFVDemo(SMALL)
        for v in [0,1,65536,9876]: self.assertEqual(h.decrypt(h.encrypt(v)),v)
    def test_random_encryption(self):
        h=BFVDemo(SMALL); self.assertNotEqual(h.encrypt(4).a,h.encrypt(4).a)
    def test_additive_homomorphism(self):
        h=BFVDemo(SMALL); self.assertEqual(h.decrypt(h.add(h.encrypt(17),h.encrypt(23))),40)
    def test_scalar(self):
        h=BFVDemo(SMALL); self.assertEqual(h.decrypt(h.scale(h.encrypt(9),-3)),(-27)%T)
    def test_polynomial_zero(self):
        h=BFVDemo(SMALL); roots=[22,33,44]
        for z in [22,33,44]:
            powers=[h.encrypt(pow(z,k,T)) for k in range(1,SMALL.cap+1)]
            self.assertEqual(h.decrypt(evaluate(h,powers,roots)),0)
    def test_polynomial_nonzero(self):
        h=BFVDemo(SMALL); z=78
        powers=[h.encrypt(pow(z,k,T)) for k in range(1,SMALL.cap+1)]
        self.assertNotEqual(h.decrypt(evaluate(h,powers,[11,22])),0)
    def test_small_intersection(self): self.assertEqual(run_psi(A,B,SMALL)[0],sorted(A[1::2]))
    def test_large_intersection(self): self.assertEqual(run_psi(A,B,LARGE)[0],sorted(A[1::2]))
    def test_none(self): self.assertEqual(run_psi(A[:1],B,SMALL)[0],[])
    def test_full(self): self.assertEqual(run_psi(A[:2],A[:2],SMALL)[0],A[:2])
    def test_duplicates(self): self.assertEqual(run_psi([A[1]]*3,[A[1]]*3,SMALL)[0],[A[1]])
    def test_bad_phone(self):
        with self.assertRaises(ValueError): run_psi(['2025550101'],B,SMALL)
    def test_client_envelope(self):
        with self.assertRaises(ValueError): run_psi(A+B,[],SMALL)
    def test_server_envelope(self):
        with self.assertRaises(ValueError): run_psi([],[f'+1202555{i:04d}' for i in range(13)],SMALL)
    def test_bytes_fixed(self):
        x=run_psi([],[],SMALL)[1]; y=run_psi(A,B,SMALL)[1]
        self.assertEqual((x['upload_bytes'],x['download_bytes']),(y['upload_bytes'],y['download_bytes']))
    def test_constant_time_shape_counts(self):
        x=run_psi(A[:1],B,SMALL)[1]; y=run_psi(A,B,SMALL)[1]
        self.assertEqual(x['response_ciphertexts'],y['response_ciphertexts'])
if __name__=='__main__': unittest.main()
