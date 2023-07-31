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

import cats.kernel.laws.discipline.EqTests
import munit.DisciplineSuite
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Prop.forAll
import scodec.bits.ByteVector

class SecureEqSuite extends DisciplineSuite {

  implicit val arbitraryByteVector: Arbitrary[ByteVector] = Arbitrary(
    Arbitrary.arbitrary[Vector[Byte]].map(ByteVector(_)))

  implicit val cogenByteVector: Cogen[ByteVector] =
    Cogen[Vector[Byte]].contramap(_.toIndexedSeq.toVector)

  checkAll("SecureEq[ByteVector]", EqTests(SecureEq[ByteVector]).eqv)

  property("non-trivial reflexivity") {
    forAll { (bytes: Vector[Byte]) =>
      SecureEq[ByteVector].eqv(ByteVector(bytes), ByteVector(bytes))
    }
  }

}
