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

import cats.Functor
import cats.effect.IO
import cats.syntax.all._
import munit.CatsEffectSuite
import scodec.bits.ByteVector

import scala.reflect.ClassTag

class HmacSuite extends CatsEffectSuite {

  import HmacAlgorithm._

  val key = ByteVector.encodeAscii("key").toOption.get
  val data = ByteVector.encodeAscii("The quick brown fox jumps over the lazy dog").toOption.get

  def testHmac[F[_]: Hmac: Functor](algorithm: HmacAlgorithm, expect: String)(
      implicit ct: ClassTag[F[Nothing]]) =
    test(s"$algorithm with ${ct.runtimeClass.getSimpleName()}") {
      Hmac[F].digest(SecretKeySpec(key, algorithm), data).map { obtained =>
        assertEquals(
          obtained,
          ByteVector.fromHex(expect).get
        )
      }
    }

  def tests[F[_]: Hmac: Functor](implicit ct: ClassTag[F[Nothing]]) = {
    testHmac[F](SHA1, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
    testHmac[F](SHA256, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    testHmac[F](
      SHA512,
      "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a")
  }

  def testGenerateKey[F[_]: Functor: Hmac](algorithm: HmacAlgorithm)(
      implicit ct: ClassTag[F[Nothing]]) =
    test(s"generate key for ${algorithm} with ${ct.runtimeClass.getSimpleName()}") {
      Hmac[F].generateKey(algorithm).map {
        case SecretKeySpec(key, keyAlgorithm) =>
          assertEquals(algorithm, keyAlgorithm)
          assert(key.size >= algorithm.minimumKeyLength)
      }
    }

  tests[IO]

  List(SHA1, SHA256, SHA512).foreach(testGenerateKey[IO])
}
