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
import bobcats.CipherAlgorithm
import bobcats.IvParameterSpec
import bobcats.PaddingMode

@js.native
private[bobcats] sealed trait Algorithm extends js.Any

private[bobcats] object Algorithm {
  def toWebCrypto[A <: CipherAlgorithm](iv: IvParameterSpec[A]) =
    iv.algorithm match {
      case CipherAlgorithm.AESCBC256(PaddingMode.None) =>
        throw new UnsupportedOperationException
      case CipherAlgorithm.AESGCM256(PaddingMode.None) =>
        throw new UnsupportedOperationException
      case CipherAlgorithm.AESCBC256(_) =>
        AesCbcParams(iv.initializationVector.toUint8Array.buffer)
      case CipherAlgorithm.AESGCM256(_) =>
        AesGcmParams(iv.initializationVector.toUint8Array.buffer)
    }
}

@js.native
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

@js.native
private[bobcats] sealed trait AesGcmParams extends Algorithm

private[bobcats] object AesGcmParams {
  def apply(iv: js.typedarray.ArrayBuffer): AesGcmParams =
    js.Dynamic
      .literal(
        name = "AES-GCM",
        iv = iv
      )
      .asInstanceOf[AesGcmParams]
}
