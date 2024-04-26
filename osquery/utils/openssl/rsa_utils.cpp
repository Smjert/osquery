#include "rsa_utils.h"

namespace osquery {
/*
 * Define a scaling constant for our fixed point arithmetic.
 * This value must be a power of two because the base two logarithm code
 * makes this assumption.  The exponent must also be a multiple of three so
 * that the scale factor has an exact cube root.  Finally, the scale factor
 * should not be so large that a multiplication of two scaled numbers
 * overflows a 64 bit unsigned integer.
 */
constexpr unsigned int scale = 1 << 18;
constexpr unsigned int cbrt_scale = 1 << (2 * 18 / 3);

constexpr unsigned int log_2 = 0x02c5c8; /* scale * log(2) */
constexpr unsigned int log_e = 0x05c551; /* scale * log2(M_E) */
constexpr unsigned int c1_923 = 0x07b126; /* scale * 1.923 */
constexpr unsigned int c4_690 = 0x12c28f; /* scale * 4.690 */

/*
 * Multiply two scaled integers together and rescale the result.
 */
static inline std::uint64_t mul2(std::uint64_t a, std::uint64_t b) {
  return a * b / scale;
}

/*
 * Calculate the cube root of a 64 bit scaled integer.
 * Although the cube root of a 64 bit number does fit into a 32 bit unsigned
 * integer, this is not guaranteed after scaling, so this function has a
 * 64 bit return.  This uses the shifting nth root algorithm with some
 * algebraic simplifications.
 */
static std::uint64_t icbrt64(std::uint64_t x) {
  std::uint64_t r = 0;
  std::uint64_t b;
  int s;

  for (s = 63; s >= 0; s -= 3) {
    r <<= 1;
    b = 3 * r * (r + 1) + 1;
    if ((x >> s) >= b) {
      x -= b << s;
      r++;
    }
  }
  return r * cbrt_scale;
}

/*
 * Calculate the natural logarithm of a 64 bit scaled integer.
 * This is done by calculating a base two logarithm and scaling.
 * The maximum logarithm (base 2) is 64 and this reduces base e, so
 * a 32 bit result should not overflow.  The argument passed must be
 * greater than unity so we don't need to handle negative results.
 */
static std::uint32_t ilog_e(std::uint64_t v) {
  std::uint32_t i, r = 0;

  /*
   * Scale down the value into the range 1 .. 2.
   *
   * If fractional numbers need to be processed, another loop needs
   * to go here that checks v < scale and if so multiplies it by 2 and
   * reduces r by scale.  This also means making r signed.
   */
  while (v >= 2 * scale) {
    v >>= 1;
    r += scale;
  }
  for (i = scale / 2; i != 0; i /= 2) {
    v = mul2(v, v);
    if (v >= 2 * scale) {
      v >>= 1;
      r += i;
    }
  }
  r = (r * static_cast<std::uint64_t>(scale)) / log_e;
  return r;
}

// Lifted from OpenSSL; see ossl_ifc_ffc_compute_security_bits
/*
 * NIST SP 800-56B rev 2 Appendix D: Maximum Security Strength Estimates for IFC
 * Modulus Lengths.
 *
 * Note that this formula is also referred to in SP800-56A rev3 Appendix D:
 * for FFC safe prime groups for modp and ffdhe.
 * After Table 25 and Table 26 it refers to
 * "The maximum security strength estimates were calculated using the formula in
 * Section 7.5 of the FIPS 140 IG and rounded to the nearest multiple of eight
 * bits".
 *
 * The formula is:
 *
 * E = \frac{1.923 \sqrt[3]{nBits \cdot log_e(2)}
 *           \cdot(log_e(nBits \cdot log_e(2))^{2/3} - 4.69}{log_e(2)}
 * The two cube roots are merged together here.
 */
int RSABitsToSecurityBits(int n) {
  std::uint64_t x;
  std::uint32_t lx;
  std::uint16_t y, cap;

  /*
   * Look for common values as listed in standards.
   * These values are not exactly equal to the results from the formulae in
   * the standards but are defined to be canonical.
   */
  switch (n) {
  case 2048: /* SP 800-56B rev 2 Appendix D and FIPS 140-2 IG 7.5 */
    return 112;
  case 3072: /* SP 800-56B rev 2 Appendix D and FIPS 140-2 IG 7.5 */
    return 128;
  case 4096: /* SP 800-56B rev 2 Appendix D */
    return 152;
  case 6144: /* SP 800-56B rev 2 Appendix D */
    return 176;
  case 7680: /* FIPS 140-2 IG 7.5 */
    return 192;
  case 8192: /* SP 800-56B rev 2 Appendix D */
    return 200;
  case 15360: /* FIPS 140-2 IG 7.5 */
    return 256;
  }

  /*
   * The first incorrect result (i.e. not accurate or off by one low) occurs
   * for n = 699668.  The true value here is 1200.  Instead of using this n
   * as the check threshold, the smallest n such that the correct result is
   * 1200 is used instead.
   */
  if (n >= 687737)
    return 1200;
  if (n < 8)
    return 0;

  /*
   * To ensure that the output is non-decreasing with respect to n,
   * a cap needs to be applied to the two values where the function over
   * estimates the strength (according to the above fast path).
   */
  if (n <= 7680)
    cap = 192;
  else if (n <= 15360)
    cap = 256;
  else
    cap = 1200;

  x = n * static_cast<std::uint64_t>(log_2);
  lx = ilog_e(x);
  y = static_cast<std::uint16_t>(
      ((mul2(c1_923, icbrt64(mul2(mul2(x, lx), lx))) - c4_690)) / log_2);
  y = (y + 4) & ~7;
  if (y > cap)
    y = cap;
  return y;
}
} // namespace osquery
