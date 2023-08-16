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

class AESGCMSuite extends CryptoSuite {

  import BlockCipherAlgorithm._

  val supportedTagLengths = {
    import AES.TagLength._
    val all = Set(`32`, `64`, `96`, `104`, `112`, `120`, `128`)

    Map(
      "JVM" -> Set(`96`, `104`, `112`, `120`, `128`),
      "Native" -> all,
      "NodeJS" -> all
    )
  }
  {
    import AESGCMEncryptTestVectors._

    allTestVectors.foreach {
      case TestVector(file, count, alg, key, iv, plainText, cipherText, tag, ad) =>
        val ptLen = plainText.length.toInt * 8
        val tagLen = new AES.TagLength(tag.length.toInt * 8)
        val adLen = ad.length * 8
        test(
          s"""${alg}.encrypt(pt=${ptLen}, tag=${tagLen.value}, iv=${iv.bitLength}, ad=${adLen})""") {
          assume(supportedTagLengths(runtime).contains(tagLen))

          for {
            key <- Cipher[IO].importKey(key, alg)
            obtained <- Cipher[IO].encrypt(
              key,
              AES.GCM.Params(iv, false, tagLen, ad),
              plainText)
            expected = cipherText ++ tag
          } yield assertEquals(
            obtained,
            expected,
            clue(
              obtained.toHex,
              expected.toHex,
              file,
              count
            )
          )
        }
    }
  }
}
