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

import scala.scalanative.unsafe._
import scala.annotation.nowarn

@extern
@link("crypto")
@nowarn
private[bobcats] object evp {

  type EVD_MD_CTX
  type EVD_MD
  type ENGINE

  final val EVP_MAX_MD_SIZE = 64

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/OpenSSL_add_all_algorithms.html]]
   */
  def OpenSSL_add_all_algorithms(): Unit = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MD_CTX_new.html]]
   */
  def EVP_MD_CTX_new(): Ptr[EVD_MD_CTX] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MD_CTX_free.html]]
   */
  def EVP_MD_CTX_free(ctx: Ptr[EVD_MD_CTX]): Unit = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_get_digestbyname.html]]
   */
  def EVP_get_digestbyname(s: CString): Ptr[EVD_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_cleanup.html]]
   */
  def EVP_cleanup(): Unit = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_md5.html]]
   */
  def EVP_md5(): Ptr[EVD_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_sha1.html]]
   */
  def EVP_sha1(): Ptr[EVD_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_sha256.html]]
   */
  def EVP_sha256(): Ptr[EVD_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_sha512.html]]
   */
  def EVP_sha512(): Ptr[EVD_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_DigestInit_ex.html]]
   */
  def EVP_DigestInit_ex(ctx: Ptr[EVD_MD_CTX], `type`: Ptr[EVD_MD], engine: Ptr[ENGINE]): CInt =
    extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_DigestUpdate.html]]
   */
  def EVP_DigestUpdate(ctx: Ptr[EVD_MD_CTX], d: Ptr[Byte], count: CSize): CInt = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_DigestFinal_ex.html]]
   */
  def EVP_DigestFinal_ex(ctx: Ptr[EVD_MD_CTX], md: Ptr[CUnsignedChar], s: Ptr[CInt]): CInt =
    extern

}

final class EvpException(msg: String) extends Exception(msg)
