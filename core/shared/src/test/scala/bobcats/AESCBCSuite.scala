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

class AESCBCSuite extends CryptoSuite {

  import BlockCipherAlgorithm._

  import AESCBCTestVectors._

  allTestVectors.foreach {
    case TestVector(encrypt, file, count, alg, key, iv, plainText, cipherText) =>
      val ptLen = plainText.length.toInt * 8
      if (encrypt) {
        test(s"""${alg}.encrypt(pt=${ptLen}, iv=${iv.bitLength})""") {
          for {
            key <- Cipher[IO].importKey(key, alg)
            obtained <- Cipher[IO].encrypt(key, AES.CBC.Params(iv, false), plainText)
            expected = cipherText
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
