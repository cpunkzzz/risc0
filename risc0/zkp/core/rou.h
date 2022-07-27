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
/// Provides tables for the roots of unity for Fp.
#include "risc0/zkp/core/fp.h"

namespace risc0 {

#if GOLDILOCKS

/// Maximum power of 2 for which we have a root of unity
size_t constexpr kMaxRouPo2 = 32;

static constexpr Fp kRouFwd[kMaxRouPo2 + 1] = {
  1ull,
  18446744069414584320ull,
  281474976710656ull,
  18446744069397807105ull,
  17293822564807737345ull,
  70368744161280ull,
  549755813888ull,
  17870292113338400769ull,
  13797081185216407910ull,
  1803076106186727246ull,
  11353340290879379826ull,
  455906449640507599ull,
  17492915097719143606ull,
  1532612707718625687ull,
  16207902636198568418ull,
  17776499369601055404ull,
  6115771955107415310ull,
  12380578893860276750ull,
  9306717745644682924ull,
  18146160046829613826ull,
  3511170319078647661ull,
  17654865857378133588ull,
  5416168637041100469ull,
  16905767614792059275ull,
  9713644485405565297ull,
  5456943929260765144ull,
  17096174751763063430ull,
  1213594585890690845ull,
  6414415596519834757ull,
  16116352524544190054ull,
  9123114210336311365ull,
  4614640910117430873ull,
  1753635133440165772ull,
};

static constexpr Fp kRouRev[kMaxRouPo2 + 1] = {
  1ull,
  18446744069414584320ull,
  18446462594437873665ull,
  1099511627520ull,
  68719476736ull,
  18446744069414322177ull,
  18302628881338728449ull,
  18442240469787213841ull,
  2117504431143841456ull,
  4459017075746761332ull,
  4295002282146690441ull,
  8548973421900915981ull,
  11164456749895610016ull,
  3968367389790187850ull,
  4654242210262998966ull,
  1553425662128427817ull,
  7868944258580147481ull,
  14744321562856667967ull,
  2513567076326282710ull,
  5089696809409609209ull,
  17260140776825220475ull,
  11898519751787946856ull,
  15307271466853436433ull,
  5456584715443070302ull,
  1219213613525454263ull,
  13843946492009319323ull,
  16884827967813875098ull,
  10516896061424301529ull,
  4514835231089717636ull,
  16488041148801377373ull,
  16303955383020744715ull,
  10790884855407511297ull,
  8554224884056360729ull,
};

#else  // GOLDILOCKS

/// Maximum power of 2 for which we have a root of unity
size_t constexpr kMaxRouPo2 = 27;

/// Array of 'forward' roots of unity.  These are critical for computing the NTT (see NTT.h).
/// Basically, we want `fwdRou[i] ^ (2^i) == 1 (mod P)`, but `fwdRou[i] ^ (2^(i-1)) != 1 (mod P)`.
/// Also, `fwdRou[i] = fwdRou[i+1] * fwdRou[i+1] (mod P)`.  To compute these values, we begin by
/// finding the smallest number, x, such that `x^(2^(maxRouPo2 - 1)) == -1 (mod P)`.  In
/// mathematicata, we find out x = 137 via:
/// `SelectFirst[Table[{i, PowerMod[i, 2^26, P]}, {i, 2, 500}], (#[[2]] == P - 1) &][[1]]`.
/// Then we compute `Table[PowerMod[137, (2^(27 - i)), P], {i, 0, 27}]`
static constexpr Fp kRouFwd[kMaxRouPo2 + 1] = {
    1,          2013265920, 284861408,  1801542727, 567209306,  740045640,  918899846,
    1881002012, 1453957774, 65325759,   1538055801, 515192888,  483885487,  157393079,
    1695124103, 2005211659, 1540072241, 88064245,   1542985445, 1269900459, 1461624142,
    825701067,  682402162,  1311873874, 1164520853, 352275361,  18769,      137};

/// Array of 'reverse' roots of unity.  These are just the multiplicative inverse of the forward
/// roots of unity.
static constexpr Fp kRouRev[kMaxRouPo2 + 1] = {
    1,          2013265920, 1728404513, 1592366214, 196396260,  1253260071, 72041623,
    1091445674, 145223211,  1446820157, 1030796471, 2010749425, 1827366325, 1239938613,
    246299276,  596347512,  1893145354, 246074437,  1525739923, 1194341128, 1463599021,
    704606912,  95395244,   15672543,   647517488,  584175179,  137728885,  749463956};

#endif // GOLDILOCKS
} // namespace risc0
