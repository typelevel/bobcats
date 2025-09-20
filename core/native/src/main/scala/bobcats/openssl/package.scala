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

import scala.scalanative.annotation.alwaysinline
import scala.scalanative.unsafe._
import scala.scalanative.meta.LinktimeInfo.isWindows

package object openssl {

  private[bobcats] type OSSL_LIB_CTX

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/OSSL_PARAM.html]]
   */
  private[bobcats] type OSSL_PARAM = CStruct5[CString, CUnsignedChar, Ptr[Byte], CSize, CSize]
  private[bobcats] object OSSL_PARAM {
    @alwaysinline private[bobcats] def init(
        param: OSSL_PARAM,
        key: CString,
        dataType: CUnsignedChar,
        data: Ptr[Byte],
        dataSize: CSize,
        returnSize: CSize): Unit = {
      param._1 = key
      param._2 = dataType
      param._3 = data
      param._4 = dataSize
      param._5 = returnSize
    }
  }

  private[bobcats] object platformCompat {
    @extern @link("libcrypto")
    object cryptoWin64 extends crypto
    @extern @link("libcrypto")
    object errWin64 extends err
    @extern @link("libcrypto")
    object evpWin64 extends evp

    @extern @link("crypto")
    object cryptoDefault extends crypto
    @extern @link("crypto")
    object errDefault extends err
    @extern @link("crypto")
    object evpDefault extends evp
  }

  private[bobcats] final val crypto =
    if (isWindows) platformCompat.cryptoWin64
    else platformCompat.cryptoDefault

  private[bobcats] final val err =
    if (isWindows) platformCompat.errWin64
    else platformCompat.errDefault

  private[bobcats] final val evp =
    if (isWindows) platformCompat.evpWin64
    else platformCompat.evpDefault
}
