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

import munit.CatsEffectSuite
import cats.effect.IO
import scodec.bits.ByteVector

class HmacSuite extends CatsEffectSuite {

  import HmacAlgorithm._

  val key = ByteVector.encodeAscii("key").toOption.get
  val data = ByteVector.encodeAscii("The quick brown fox jumps over the lazy dog").toOption.get

  def testHash(algorithm: HmacAlgorithm, expect: String) =
    test(algorithm.toString) {
      assertIO(
        Hmac[IO].digest(SecretKeySpec(key, algorithm), data),
        ByteVector.fromHex(expect).get
      )
    }

  testHash(SHA1, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
  testHash(SHA256, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
  testHash(
    SHA512,
    "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a")

  def testGenerateKey(algorithm: HmacAlgorithm) =
    test(s"generate key for ${algorithm}") {
      Hmac[IO].generateKey(algorithm).map {
        case SecretKeySpec(key, keyAlgorithm) =>
          assertEquals(algorithm, keyAlgorithm)
          assert(key.intSize.get > algorithm.minimumKeyLength)
      }
    }

  if (BuildInfo.runtime != "NodeJS") // Disabled until testing against Node 16
    List(SHA1, SHA256, SHA512).foreach(testGenerateKey)

}
