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

@extern
@link("crypto")
private[bobcats] object crypto {

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/OSSL_LIB_CTX_new.html]]
   */
  def OSSL_LIB_CTX_new(): Ptr[OSSL_LIB_CTX] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/OSSL_LIB_CTX_free.html]]
   */
  def OSSL_LIB_CTX_free(ctx: Ptr[OSSL_LIB_CTX]): Unit = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/CRYPTO_memcmp.html]]
   */
  def CRYPTO_memcmp(a: Ptr[Byte], b: Ptr[Byte], len: CSize): CInt = extern

}
