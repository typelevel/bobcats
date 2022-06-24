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
import scodec.bits._

import scala.reflect.ClassTag

class HmacSuite extends CatsEffectSuite {

  import HmacAlgorithm._

  case class TestCase(key: ByteVector, data: ByteVector, digest: ByteVector)

  // Test cases from RFC2022: https://datatracker.ietf.org/doc/html/rfc2202
  val sha1TestCases = List(
    TestCase(
      hex"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      ByteVector.encodeAscii("Hi There").toOption.get,
      hex"b617318655057264e28bc0b6fb378c8ef146be00"
    ),
    TestCase(
      ByteVector.encodeAscii("Jefe").toOption.get,
      ByteVector.encodeAscii("what do ya want for nothing?").toOption.get,
      hex"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    ),
    TestCase(
      hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ByteVector.fromHex("dd" * 50).get,
      hex"125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    ),
    TestCase(
      hex"0102030405060708090a0b0c0d0e0f10111213141516171819",
      ByteVector.fromHex("cd" * 50).get,
      hex"4c9007f4026250c6bc8414f9bf50c86c2d7235da"
    ),
    TestCase(
      hex"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      ByteVector.encodeAscii("Test With Truncation").toOption.get,
      hex"4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
    ),
    TestCase(
      ByteVector.fromHex("aa" * 80).get,
      ByteVector
        .encodeAscii("Test Using Larger Than Block-Size Key - Hash Key First")
        .toOption
        .get,
      hex"aa4ae5e15272d00e95705637ce8a3b55ed402112"
    ),
    TestCase(
      ByteVector.fromHex("aa" * 80).get,
      ByteVector
        .encodeAscii(
          "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")
        .toOption
        .get,
      hex"e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
    )
  )

  val key = ByteVector.encodeAscii("key").toOption.get
  val data = ByteVector.encodeAscii("The quick brown fox jumps over the lazy dog").toOption.get

  def testHmac[F[_]: Hmac: Functor](algorithm: HmacAlgorithm, expected: ByteVector)(
      implicit ct: ClassTag[F[Nothing]]) =
    test(s"$algorithm with ${ct.runtimeClass.getSimpleName()}") {
      Hmac[F].digest(SecretKeySpec(key, algorithm), data).map { obtained =>
        assertEquals(
          obtained,
          expected
        )
      }
    }

  def testHmacSha1[F[_]: Hmac: Functor](testCases: List[TestCase])(
      implicit ct: ClassTag[F[Nothing]]) =
    testCases.zipWithIndex.foreach {
      case (TestCase(key, data, expected), idx) =>
        test(s"SHA1 RFC2022 test case ${idx + 1} with ${ct.runtimeClass.getSimpleName()}") {
          Hmac[F].digest(SecretKeySpec(key, SHA1), data).map { obtained =>
            assertEquals(obtained, expected)
          }
        }
    }

  def tests[F[_]: Hmac: Functor](implicit ct: ClassTag[F[Nothing]]) = {
    testHmacSha1[F](sha1TestCases)
    testHmac[F](SHA1, hex"de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
    testHmac[F](SHA256, hex"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    testHmac[F](
      SHA512,
      hex"b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a")
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
