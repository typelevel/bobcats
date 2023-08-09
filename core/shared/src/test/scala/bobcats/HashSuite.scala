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
import scodec.bits.ByteVector
import fs2.{Chunk, Stream}

class HashSuite extends CryptoSuite {

  import HashAlgorithm._

  val data = ByteVector.encodeAscii("The quick brown fox jumps over the lazy dog").toOption.get

  def testHash(
      algorithm: HashAlgorithm,
      name: String,
      data: ByteVector,
      expect: String,
      ignoredRuntimes: Set[String]) =
    test(s"$algorithm for $name vector") {
      val runtime = BuildInfo.runtime
      assume(!ignoredRuntimes.contains(runtime), s"${runtime} does not support ${algorithm}")
      val bytes = ByteVector.fromHex(expect).get
      Hash[IO].digest(algorithm, data).assertEquals(bytes) *>
        Stream
          .chunk(Chunk.byteVector(data))
          .through(Hash[IO].digestPipe(algorithm))
          .compile
          .to(ByteVector)
          .assertEquals(bytes) *> Hash1
          .forSyncResource[IO](algorithm)
          .use(_.digest(data))
          .assertEquals(bytes)
    }

  def testVector(
      algorithm: HashAlgorithm,
      expect: String,
      ignoredRuntimes: Set[String] = Set()) =
    testHash(algorithm, "example", data, expect, ignoredRuntimes)

  def testEmpty(
      algorithm: HashAlgorithm,
      expect: String,
      ignoredRuntimes: Set[String] = Set()) =
    testHash(algorithm, "empty", ByteVector.empty, expect, ignoredRuntimes)

  testVector(SHA1, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
  testEmpty(SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
  testVector(SHA256, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
  testEmpty(SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  testVector(
    SHA512,
    "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6")
  testEmpty(
    SHA512,
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")

  testVector(MD5, "9e107d9d372bb6826bd81d3542a419d6", ignoredRuntimes = Set("Browser"))

}
