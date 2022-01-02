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

package bobcats.util

import bobcats.{AsymmetricKeyAlg, PKCS8KeySpec, SPKIKeySpec}

import scala.util.Try

trait PEMUtils {
  type PKCS8_PEM = String
  type SPKI_PEM = String

  /**
   * Even though the keytype is in the PKCS8 key, the JS Web Crypto API requires prior knowledge
   * of the type
   */
  def getPrivateKeyFromPEM(
      pemStr: PKCS8_PEM,
      keyType: AsymmetricKeyAlg // this is only needed for the JS-crypto API. Bouncy in Java can determine the key type
  ): Try[PKCS8KeySpec[AsymmetricKeyAlg]]

  /**
   * Even though the keytype is in the SPKI key, the JS Web Crypto API requires prior knowledge
   * of it
   */
  def getPublicKeyFromPEM(
      pemStr: SPKI_PEM,
      keyType: AsymmetricKeyAlg // this is only needed for the JS-crypto API. Bouncy in Java can determine the key type
  ): Try[SPKIKeySpec[AsymmetricKeyAlg]]
}
