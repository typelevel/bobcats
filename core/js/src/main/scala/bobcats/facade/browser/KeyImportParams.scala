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

sealed trait ImportParams extends js.Object

private[bobcats] trait HmacImportParams extends ImportParams {
  val name: String
  val hash: String
  val length: js.UndefOr[Int] = js.undefined
}

private[bobcats] object HmacImportParams {
  def apply(_hash: String): HmacImportParams =
    new HmacImportParams {
      val name = "HMAC"
      val hash = _hash
    }
}

private[bobcats] trait AesImportParams extends ImportParams {
  val name: String
}
