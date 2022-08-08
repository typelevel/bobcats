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
import java.lang

@js.native
private[bobcats] sealed trait KeyGenParams extends js.Any

@js.native
private[bobcats] sealed trait HmacKeyGenParams extends js.Any

private[bobcats] object HmacKeyGenParams {
  def apply(hash: String): HmacKeyGenParams =
    js.Dynamic
      .literal(
        name = "HMAC",
        hash = hash
      )
      .asInstanceOf[HmacKeyGenParams]
}

@js.native
private[bobcats] sealed trait AesKeyGenParams extends js.Any

private[bobcats] object AesKeyGenParams {
  def apply[A <: CipherAlgorithm](algorithm: A): AesKeyGenParams =
    js.Dynamic
      .literal(
        name = algorithm.toStringWebCrypto,
        length = algorithm.keyLength * lang.Byte.SIZE
      )
      .asInstanceOf[AesKeyGenParams]
}
