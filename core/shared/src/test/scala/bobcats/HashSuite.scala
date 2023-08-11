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

import cats.effect.IO
import scodec.bits._
import fs2.{Chunk, Stream}

class HashSuite extends CryptoSuite {

  import HashAlgorithm._

  val data = ByteVector.encodeAscii("The quick brown fox jumps over the lazy dog").toOption.get

  case class TestCase(algorithm: HashAlgorithm, data: ByteVector, digest: ByteVector)

  val testCases = List(
    TestCase(SHA1, data, hex"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
    TestCase(SHA1, ByteVector.empty, hex"da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    TestCase(
      SHA256,
      data,
      hex"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
    TestCase(
      SHA256,
      ByteVector.empty,
      hex"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    TestCase(
      SHA512,
      data,
      hex"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"),
    TestCase(
      SHA512,
      ByteVector.empty,
      hex"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ),
    TestCase(MD5, data, hex"9e107d9d372bb6826bd81d3542a419d6")
  )

  val supportedAlgorithms = {
    val all = Set[HashAlgorithm](MD5, SHA1, SHA256, SHA512)
    val browser = Set[HashAlgorithm](SHA1, SHA256, SHA512)
    Map(
      "JVM" -> all,
      "NodeJS" -> all,
      "Native" -> all,
      "Chrome" -> browser,
      "Firefox" -> browser
    )
  }

  testCases.zipWithIndex.foreach {
    case (TestCase(alg, data, digest), counter) =>
      test(s"Hash[IO].digest for ${alg} test case ${counter}") {
        assume(
          supportedAlgorithms(runtime).contains(alg),
          s"${runtime} does not support ${alg}")
        Hash[IO].digest(alg, data).assertEquals(digest)
      }
      test(s"Hash1[IO].digest for ${alg} test case ${counter}") {
        assume(
          supportedAlgorithms(runtime).contains(alg),
          s"${runtime} does not support ${alg}")
        Hash1.forAsync[IO](alg).use(_.digest(data)).assertEquals(digest)
      }
      test(s"Hash[IO].digestPipe for ${alg} test case ${counter}") {
        assume(!isBrowser, s"${runtime} does not support streaming")
        Stream
          .chunk(Chunk.byteVector(data))
          .through(Hash[IO].digestPipe(alg))
          .compile
          .to(ByteVector)
          .assertEquals(digest)
      }
      test(s"Hash1[IO].pipe for ${alg} test case ${counter}") {
        assume(!isBrowser, s"${runtime} does not support streaming")
        Hash1
          .forAsync[IO](alg)
          .use { hash1 =>
            Stream.chunk(Chunk.byteVector(data)).through(hash1.pipe).compile.to(ByteVector)
          }
          .assertEquals(digest)
      }
  }
}
