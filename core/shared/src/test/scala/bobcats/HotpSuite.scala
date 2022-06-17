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

package bobcats

import cats.Functor
import cats.effect.IO
import cats.effect.SyncIO
import munit.CatsEffectSuite
import cats.syntax.functor._

import scala.reflect.ClassTag
import scodec.bits.ByteVector

class HotpSuite extends CatsEffectSuite {

  val key = ByteVector.fromHex("3132333435363738393031323334353637383930").get

  val expectedValues = List(
    755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489
  )

  def tests[F[_]: Hotp: Functor](implicit ct: ClassTag[F[Nothing]]) = {
    expectedValues.zipWithIndex.foreach {
      case (expected, counter) =>
        test(s"RFC4226 test case ${counter} for ${ct.runtimeClass.getSimpleName()}") {
          Hotp[F]
            .generate(SecretKeySpec(key, HmacAlgorithm.SHA1), counter.toLong, digits = 6)
            .map { obtained => assertEquals(obtained, expected) }
        }
    }
  }

  if (Set("JVM", "NodeJS").contains(BuildInfo.runtime))
    tests[SyncIO]

  if (BuildInfo.runtime != "JVM")
    tests[IO]
}
