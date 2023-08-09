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

@extern
@link("crypto")
@nowarn("msg=never used")
private[bobcats] object evp {

  type EVP_MD_CTX
  type EVP_MD
  type ENGINE

  final val EVP_MAX_MD_SIZE = 64

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MD_fetch.html]]
   */
  def EVP_MD_fetch(
      ctx: Ptr[OSSL_LIB_CTX],
      algorithm: CString,
      properties: CString): Ptr[EVP_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MD_free.html]]
   */
  def EVP_MD_free(ctx: Ptr[EVP_MD]): Unit = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MD_CTX_new.html]]
   */
  def EVP_MD_CTX_new(): Ptr[EVP_MD_CTX] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MD_CTX_reset.html]]
   */
  def EVP_MD_CTX_reset(ctx: Ptr[EVP_MD_CTX]): CInt = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MD_CTX_free.html]]
   */
  def EVP_MD_CTX_free(ctx: Ptr[EVP_MD_CTX]): Unit = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_get_digestbyname.html]]
   */
  def EVP_get_digestbyname(s: CString): Ptr[EVP_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MD_get0_name.html]]
   */
  def EVP_MD_get0_name(md: Ptr[EVP_MD]): CString = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_md5.html]]
   */
  def EVP_md5(): Ptr[EVP_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_sha1.html]]
   */
  def EVP_sha1(): Ptr[EVP_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_sha256.html]]
   */
  def EVP_sha256(): Ptr[EVP_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_sha512.html]]
   */
  def EVP_sha512(): Ptr[EVP_MD] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_DigestInit_ex.html]]
   */
  def EVP_DigestInit_ex(ctx: Ptr[EVP_MD_CTX], `type`: Ptr[EVP_MD], engine: Ptr[ENGINE]): CInt =
    extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_DigestUpdate.html]]
   */
  def EVP_DigestUpdate(ctx: Ptr[EVP_MD_CTX], d: Ptr[Byte], count: CSize): CInt = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_DigestFinal_ex.html]]
   */
  def EVP_DigestFinal_ex(ctx: Ptr[EVP_MD_CTX], md: Ptr[CUnsignedChar], s: Ptr[CInt]): CInt =
    extern

  type EVP_MAC
  type EVP_MAC_CTX

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MAC_fetch.html]]
   */
  def EVP_MAC_fetch(
      libctx: Ptr[OSSL_LIB_CTX],
      algoritm: CString,
      properties: CString): Ptr[EVP_MAC] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MAC_CTX_new.html]]
   */
  def EVP_MAC_CTX_new(mac: Ptr[EVP_MAC]): Ptr[EVP_MAC_CTX] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MAC_CTX_free.html]]
   */
  def EVP_MAC_CTX_free(ctx: Ptr[EVP_MAC_CTX]): Unit = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MAC_init.html]]
   */
  def EVP_MAC_init(
      ctx: Ptr[EVP_MAC_CTX],
      key: Ptr[CUnsignedChar],
      keylen: CSize,
      params: Ptr[OSSL_PARAM]): CInt = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MAC_update.html]]
   */
  def EVP_MAC_update(
      ctx: Ptr[EVP_MAC_CTX],
      data: Ptr[CUnsignedChar],
      datalen: CSize
  ): CInt = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_MAC_final.html]]
   */
  def EVP_MAC_final(
      ctx: Ptr[EVP_MAC_CTX],
      out: Ptr[CUnsignedChar],
      outl: Ptr[CSize],
      outsize: CSize
  ): CInt = extern

  type EVP_RAND
  type EVP_RAND_CTX

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_RAND_fetch.html]]
   */
  def EVP_RAND_fetch(
      libctx: Ptr[OSSL_LIB_CTX],
      algoritm: CString,
      properties: CString): Ptr[EVP_RAND] = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_RAND_CTX_new.html]]
   */
  def EVP_RAND_CTX_new(rand: Ptr[EVP_RAND], parent: Ptr[EVP_RAND_CTX]): Ptr[EVP_RAND_CTX] =
    extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_RAND_CTX_free.html]]
   */
  def EVP_RAND_CTX_free(ctx: Ptr[EVP_RAND_CTX]): Unit = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_RAND_instantiate.html]]
   */
  def EVP_RAND_instantiate(
      ctx: Ptr[EVP_RAND_CTX],
      strength: CUnsignedInt,
      prediction_resistance: Int,
      pstr: CString,
      pstr_len: CSize,
      params: Ptr[OSSL_PARAM]): CInt = extern

  /**
   * See [[https://www.openssl.org/docs/man3.1/man3/EVP_RAND_generate.html]]
   */
  def EVP_RAND_generate(
      ctx: Ptr[EVP_RAND_CTX],
      out: Ptr[CUnsignedChar],
      outlen: CSize,
      strength: CUnsignedInt,
      prediction_resistance: Int,
      addin: Ptr[CUnsignedChar],
      addin_len: CSize): CInt = extern

}
