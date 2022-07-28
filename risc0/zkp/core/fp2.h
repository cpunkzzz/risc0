// Copyright 2022 Risc0, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

/// \file
/// Defines Fp2, a finite field F_p^4, based on Fp via the irreducable polynomial x^4 - 11.

#include "risc0/zkp/core/fp.h"

namespace risc0 {

// Defines instead of constexpr to appease CUDAs limitations around constants.
// undef'd at the end of this file.
#define BETA Fp(11)
#define NBETA Fp(Fp::P - 11)

struct Fp2 {
  Fp elems[2];

  /// Default constructor makes the zero elements
  DEVSPEC constexpr Fp2() {}
  /// Initialize from uint32_t
  DEVSPEC explicit constexpr Fp2(uint32_t x) {
    elems[0] = x;
    elems[1] = 0;
  }
  /// Convert from Fp to Fp2.
  DEVSPEC explicit constexpr Fp2(Fp x) {
    elems[0] = x;
    elems[1] = 0;
  }
  /// Explicitly construct an Fp2 from parts
  DEVSPEC constexpr Fp2(Fp a, Fp b) {
    elems[0] = a;
    elems[1] = b;
  }

  /// Generate a random field element uniformly
  template <typename Rng> static Fp2 random(DEVADDR Rng& rng) {
    // Make sure there is only one Fp::random per statement so we get
    // deterministic ordering (see
    // https://en.cppreference.com/w/cpp/language/eval_order).
    Fp a = Fp::random(rng);
    Fp b = Fp::random(rng);
    return Fp2(a, b);
  }

  // Implement the addition/subtraction overloads
  DEVSPEC constexpr Fp2 operator+=(Fp2 rhs) {
    for (uint32_t i = 0; i < 2; i++) {
      elems[i] += rhs.elems[i];
    }
    return *this;
  }
  DEVSPEC constexpr Fp2 operator-=(Fp2 rhs) {
    for (uint32_t i = 0; i < 2; i++) {
      elems[i] -= rhs.elems[i];
    }
    return *this;
  }
  DEVSPEC constexpr Fp2 operator+(Fp2 rhs) const {
    Fp2 result = *this;
    result += rhs;
    return result;
  }
  DEVSPEC constexpr Fp2 operator-(Fp2 rhs) const {
    Fp2 result = *this;
    result -= rhs;
    return result;
  }
  DEVSPEC constexpr Fp2 operator-() const { return Fp2() - *this; }

  // Implement the simple multiplication case by the subfield Fp
  // Fp * Fp2 is done as a free function due to C++'s operator overloading rules.
  DEVSPEC constexpr Fp2 operator*=(Fp rhs) {
    for (uint32_t i = 0; i < 4; i++) {
      elems[i] *= rhs;
    }
    return *this;
  }
  DEVSPEC constexpr Fp2 operator*(Fp rhs) const {
    Fp2 result = *this;
    result *= rhs;
    return result;
  }

  // Now we get to the interesting case of multiplication.  Basically, multiply out the polynomial
  // representations, and then reduce module x^4 - B, which means powers >= 4 get shifted back 4 and
  // multiplied by -beta.  We could write this as a double loops with some if's and hope it gets
  // unrolled properly, but it'a small enough to just hand write.
  DEVSPEC constexpr Fp2 operator*(Fp2 rhs) const {
    // Rename the element arrays to something small for readability
#define a elems
#define b rhs.elems
    return Fp2(a[0] * b[0] + NBETA * a[1] * b[1],
               a[0] * b[1] + a[1] * b[0]);
#undef a
#undef b
  }
  DEVSPEC constexpr Fp2 operator*=(Fp2 rhs) {
    *this = *this * rhs;
    return *this;
  }

  // Equality
  DEVSPEC constexpr bool operator==(Fp2 rhs) const {
    for (uint32_t i = 0; i < 2; i++) {
      if (elems[i] != rhs.elems[i]) {
        return false;
      }
    }
    return true;
  }
  DEVSPEC constexpr bool operator!=(Fp2 rhs) const { return !(*this == rhs); }

  DEVSPEC constexpr Fp constPart() const { return elems[0]; }

#ifdef METAL
  constexpr Fp2 operator+(Fp2 rhs) device const { return Fp2(*this) + rhs; }
  constexpr Fp2 operator-(Fp2 rhs) device const { return Fp2(*this) - rhs; }
  constexpr Fp2 operator-() device const { return -Fp2(*this); }
  constexpr Fp2 operator*(Fp2 rhs) device const { return Fp2(*this) * rhs; }
  constexpr Fp2 operator*(Fp rhs) device const { return Fp2(*this) * rhs; }
  constexpr bool operator==(Fp2 rhs) device const { return Fp2(*this) == rhs; }
  constexpr bool operator!=(Fp2 rhs) device const { return Fp2(*this) != rhs; }
  constexpr Fp constPart() device const { return Fp2(*this).constPart(); }
#endif
};

/// Overload for case where LHS is Fp (RHS case is handled as a method)
DEVSPEC constexpr inline Fp2 operator*(Fp a, Fp2 b) {
  return b * a;
}

/// ostream support for Fp values
#ifdef CPU
inline std::ostream& operator<<(std::ostream& os, const Fp2& x) {
  os << x.elems[0] << "+" << x.elems[1] << "x";
  return os;
}
#endif

/// Raise an Fp2 to a power
DEVSPEC constexpr inline Fp2 pow(Fp2 x, size_t n) {
  Fp2 tot(1);
  while (n != 0) {
    if (n % 2 == 1) {
      tot *= x;
    }
    n = n / 2;
    x *= x;
  }
  return tot;
}

/// Compute the multiplicative inverse of an Fp2.
DEVSPEC constexpr inline Fp2 inv(Fp2 in) {
#define a in.elems
  // Compute the multiplicative inverse by basicly looking at Fp2 as a composite field and using the
  // same basic methods used to invert complex numbers.  We imagine that initially we have a
  // numerator of 1, and an denominator of a. i.e out = 1 / a; We set a' to be a with the first and
  // third components negated.  We then multiply the numerator and the denominator by a', producing
  // out = a' / (a * a'). By construction (a * a') has 0's in it's first and third elements.  We
  // call this number, 'b' and compute it as follows.
  Fp det = a[0] * a[0] + BETA * a[1] * a[1];
  Fp invdet = inv(det);
  return Fp2(a[0] * invdet, -a[1] * invdet);
#undef a
}

#undef BETA
#undef NBETA

} // namespace risc0
