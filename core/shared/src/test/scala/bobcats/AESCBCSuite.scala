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
import cats.syntax.all._
import munit.CatsEffectSuite
import cats.effect.kernel.Async

class AESCBCSuite extends CatsEffectSuite {

  import CipherAlgorithm._

  def cbcTestVectorsNoPadding[F[_]: Async] = {
    val cipher = Cipher.forAsync[F]

    for {
      testDataType <- AESCBCTestVectors.allTestVectors
      testCase <- testDataType.encrypt.toList
    } yield {
      test(
        s"AESVS ${testDataType.dataType} test data for CBC - encrypt test case ${testCase.index} - No Padding") {
        for {
          key <- cipher.importKey(testCase.key, AESCBC256(PaddingMode.None))
          iv <- cipher.importIv(testCase.iv, AESCBC256(PaddingMode.None))
          obtained <- cipher.encrypt(key, iv, testCase.plainText)
          expected = testCase.cipherText
        } yield assertEquals(obtained, expected)
      }
    }

    for {
      testDataType <- AESCBCTestVectors.allTestVectors
      testCase <- testDataType.encrypt.toList
    } yield {
      test(
        s"AESVS ${testDataType.dataType} test data for CBC - decrypt test case ${testCase.index} - No Padding") {
        for {
          key <- cipher.importKey(testCase.key, AESCBC256(PaddingMode.None))
          iv <- cipher.importIv(testCase.iv, AESCBC256(PaddingMode.None))
          obtained <- cipher.decrypt(key, iv, testCase.cipherText)
          expected = testCase.plainText
        } yield assertEquals(obtained, expected)
      }
    }
  }

  def cbcTestVectorsPKCS7Padding[F[_]: Async] = {
    val cipher = Cipher.forAsync[F]

    // There's no point in trying the decrypt cases - they're not padded so they won't work.
    // Instead we round-trip the encryption test cases.
    for {
      testDataType <- AESCBCTestVectors.allTestVectors
      testCase <- testDataType.encrypt.toList
    } yield {
      test(
        s"AESVS ${testDataType.dataType} test data for CBC - test case ${testCase.index} - PKCS#7 Padding") {
        for {
          key <- cipher.importKey(testCase.key, AESCBC256(PaddingMode.PKCS7))
          iv <- cipher.importIv(testCase.iv, AESCBC256(PaddingMode.PKCS7))
          cipherText <- cipher.encrypt(key, iv, testCase.plainText)
          expected = testCase.cipherText
          plainText <- cipher.decrypt(key, iv, cipherText)
        } yield {
          assertEquals(cipherText.take(expected.length), expected)
          assertEquals(plainText, testCase.plainText)
        }
      }
    }
  }

  // Browser SubtleCrypto cannot disable padding
  if (Set("JVM", "NodeJS").contains(BuildInfo.runtime)) {
    cbcTestVectorsNoPadding[IO]
  }

  cbcTestVectorsPKCS7Padding[IO]
}
