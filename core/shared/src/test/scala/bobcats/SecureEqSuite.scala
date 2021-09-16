/*
 * Copyright 2021 Typelevel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bobcats

import munit.DisciplineSuite
import cats.kernel.laws.discipline.EqTests
import scodec.bits.ByteVector
import org.scalacheck.Arbitrary

class SecureEqSuite extends DisciplineSuite {

  implicit val arbitraryByteVector: Arbitrary[ByteVector] = Arbitrary(
    Arbitrary.arbitrary[Vector[Byte]].map(ByteVector(_)))

  implicit val arbitraryByteVectorFunction: Arbitrary[ByteVector => ByteVector] = Arbitrary(
    Arbitrary
      .arbitrary[Vector[Byte] => Vector[Byte]]
      .map(
        _.compose[ByteVector](_.toIndexedSeq.toVector).andThen(ByteVector(_))
      ))

  checkAll("SequreEq[ByteVector]", EqTests(SecureEq[ByteVector]).eqv)

}
