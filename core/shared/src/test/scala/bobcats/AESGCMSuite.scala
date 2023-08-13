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

class AESGCMSuite extends CryptoSuite {

  import BlockCipherAlgorithm._
  import AESGCMTestVectors._

  val supportedTagLengths = {
    import AES.TagLength._
    Map(
      "JVM" -> Set(`96`, `104`, `112`, `120`, `128`)
    )
  }

  AESGCMTestVectors.allTestVectors.foreach {
    case TestVector(count, alg, key, iv, plainText, cipherText, tag, ad) =>
      val ptLen = plainText.length.toInt * 8
      val tagLen = new AES.TagLength(tag.length.toInt * 8)
      val ivLen = iv.length * 8
      val adLen = ad.map(_.length * 8).getOrElse(0)
      test(s"${alg} [count=${count}, ptLen=${ptLen} tagLen=${tagLen.value}, ivLen=${ivLen}, adLen=${adLen}]") {
        assume(supportedTagLengths(runtime).contains(tagLen))
        for {
          key <- Cipher[IO].importKey(key, alg)
          obtained <- Cipher[IO].encrypt(key, AES.GCM.Params(new IV(iv), tagLen, ad), plainText)
        } yield assertEquals(
          obtained,
          cipherText ++ tag
        )
      }
  }
}
