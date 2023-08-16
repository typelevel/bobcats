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

package bobcats.facade.browser

import scala.scalajs.js

private[bobcats] sealed trait Algorithm extends js.Object

// private[bobcats] object Algorithm {
//   def toWebCrypto[A <: CipherAlgorithm](iv: IvParameterSpec[A]) =
//     iv.algorithm match {
//       case CipherAlgorithm.AESCBC256(PaddingMode.None) =>
//         throw new UnsupportedOperationException
//       case CipherAlgorithm.AESGCM256(PaddingMode.None) =>
//         throw new UnsupportedOperationException
//       case CipherAlgorithm.AESCBC256(_) =>
//         AesCbcParams(iv.initializationVector.toUint8Array.buffer)
//       case CipherAlgorithm.AESGCM256(_) =>
//         AesGcmParams(iv.initializationVector.toUint8Array.buffer)
//     }
// }

private[bobcats] sealed trait AesCbcParams extends Algorithm

private[bobcats] object AesCbcParams {
  def apply(iv: js.typedarray.ArrayBuffer): AesCbcParams =
    js.Dynamic
      .literal(
        name = "AES-CBC",
        iv = iv
      )
      .asInstanceOf[AesCbcParams]
}

trait AesGcmParams extends Algorithm {
  val name: String
  val iv: js.typedarray.ArrayBuffer
  val additionalData: js.UndefOr[js.typedarray.Uint8Array] = js.undefined
}

private[bobcats] object AesGcmParams {
  def apply(
      _iv: js.typedarray.ArrayBuffer,
      _additionalData: js.UndefOr[js.typedarray.Uint8Array]): AesGcmParams =
    new AesGcmParams {
      val name = "AES-GCM"
      val iv = _iv
      override val additionalData = _additionalData
    }
}
