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
import scala.annotation.nowarn
import scala.scalanative.unsigned._

@extern
@link("crypto")
@nowarn("msg=never used")
private[bobcats] object err {

  def ERR_get_error(): ULong = extern
  def ERR_func_error_string(e: ULong): CString = extern
  def ERR_reason_error_string(e: ULong): CString = extern
}

private[bobcats] final class Error(private[openssl] message: String)
    extends GeneralSecurityException(message, null)

private[bobcats] object Error {

  import err._

  def apply(func: String, err: ULong): Error = {
    if (err == 0.toULong) {
      new Error(func)
    } else {
      val reason = fromCString(ERR_reason_error_string(err))
      new Error(func + ":" + err + ":" + reason)
    }
  }
}
