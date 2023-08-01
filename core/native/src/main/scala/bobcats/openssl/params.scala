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
package openssl

import scala.scalanative.unsafe._
import scala.scalanative.annotation.alwaysinline
import scalanative.unsigned._

private[bobcats] object params {
  final val OSSL_PARAM_INTEGER = 1.toUByte
  final val OSSL_PARAM_UNSIGNED_INTEGER = 2.toUByte
  final val OSSL_PARAM_REAL = 3.toUByte
  final val OSSL_PARAM_UTF8_STRING = 4.toUByte
  final val OSSL_PARAM_OCTET_STRING = 5.toUByte

  /**
   * Compiles to `(size_t) - 1`.
   */
  final val OSSL_PARAM_UNMODIFIED: CSize = -1.toULong

  @alwaysinline def OSSL_PARAM_END(param: OSSL_PARAM): Unit =
    OSSL_PARAM.init(param, null, 0.toUByte, null, 0.toULong, 0.toULong)
  @alwaysinline def OSSL_PARAM_octet_string(
      param: OSSL_PARAM,
      key: CString,
      data: Ptr[Byte],
      data_size: CSize): Unit =
    OSSL_PARAM.init(
      param,
      key,
      OSSL_PARAM_OCTET_STRING,
      data,
      data_size,
      OSSL_PARAM_UNMODIFIED)

  @alwaysinline def OSSL_PARAM_int(param: OSSL_PARAM, key: CString, data: Ptr[CInt]): Unit =
    OSSL_PARAM.init(
      param,
      key,
      OSSL_PARAM_INTEGER,
      data.asInstanceOf[Ptr[Byte]],
      sizeof[CInt],
      OSSL_PARAM_UNMODIFIED)

  @alwaysinline def OSSL_PARAM_utf8_string(
      param: OSSL_PARAM,
      key: CString,
      data: Ptr[Byte],
      data_size: CSize): Unit =
    OSSL_PARAM.init(param, key, OSSL_PARAM_UTF8_STRING, data, data_size, OSSL_PARAM_UNMODIFIED)

  @alwaysinline def OSSL_DBRG_PARAM_CIPHER(
      param: OSSL_PARAM,
      cipher: CString,
      cipher_len: CSize): Unit =
    OSSL_PARAM_utf8_string(param, c"cipher", cipher, cipher_len)

  @alwaysinline def OSSL_MAC_PARAM_DIGEST(
      param: OSSL_PARAM,
      digest: CString,
      digest_len: CSize): Unit =
    OSSL_PARAM_utf8_string(param, c"digest", digest, digest_len)

  @alwaysinline def OSSL_MAC_PARAM_DIGEST_ONESHOT(param: OSSL_PARAM, oneshot: Ptr[CInt]): Unit =
    OSSL_PARAM_int(param, c"digest-oneshot", oneshot)

}
