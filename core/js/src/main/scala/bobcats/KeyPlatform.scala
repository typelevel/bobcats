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

import bobcats.AsymmetricKeyAlg.{RSA, RSA_PKCS_Sig, RSA_PSS_Sig}
import cats.effect.kernel.Async
import org.scalajs.dom
import cats.syntax.all._
import org.scalajs.dom.crypto.subtle
import org.scalajs.dom.{EcKeyImportParams, EcdsaParams, HashAlgorithmIdentifier, KeyAlgorithm, RsaHashedImportParams, RsaPssParams}

import scala.scalajs.js
import scala.scalajs.js.Promise

private[bobcats] trait KeyPlatform
private[bobcats] trait PublicKeyPlatform
private[bobcats] trait PrivateKeyPlatform
private[bobcats] trait SecretKeyPlatform

private[bobcats] trait SecretKeySpecPlatform[+A <: Algorithm]
private[bobcats] trait PrivateKeySpecPlatform[+A <: AsymmetricKeyAlg] {
  self: PrivateKeySpec[A] =>
  def toWebCryptoKey[F[_]](signature: AsymmetricKeyAlg.Signature)(
      implicit F0: Async[F]
  ): F[org.scalajs.dom.CryptoKey] =
    F0.fromPromise(F0.delay[Promise[org.scalajs.dom.CryptoKey]]{
      subtle.importKey(
          dom.KeyFormat.pkcs8,
          key.toJSArrayBuffer,
          JSKeySpec.importAlgorithm(algorithm, signature),
          true,
          js.Array(dom.KeyUsage.sign)
        )
    })
}
private[bobcats] trait PublicKeySpecPlatform[+A <: AsymmetricKeyAlg] {
  self: PublicKeySpec[A] =>
  def toWebCryptoKey[F[_]](signature: AsymmetricKeyAlg.Signature)(
      implicit F0: Async[F]
  ): F[org.scalajs.dom.CryptoKey] =
    F0.fromPromise(F0.delay {
      subtle.importKey(
          dom.KeyFormat.spki,
          key.toJSArrayBuffer,
          JSKeySpec.importAlgorithm(algorithm, signature),
          true, // todo: do we always want extractable?
          js.Array(dom.KeyUsage.verify) // todo: we may want other key usages?
        )
    })
}

object JSKeySpec {
  def importAlgorithm(
      algorithm: AsymmetricKeyAlg,
      signature: AsymmetricKeyAlg.Signature
  ): KeyAlgorithm =
    algorithm match {
      case rsaAlg: RSA =>
        new RsaHashedImportParams {
          override val name: String = rsaAlg.toStringWebCrypto
          override val hash: HashAlgorithmIdentifier = signature.hash.toStringWebCrypto
        }
      case ecAlg @ bobcats.AsymmetricKeyAlg.ECKey(p) =>
        new EcKeyImportParams {
          override val name: String = ecAlg.toStringWebCrypto
          override val namedCurve: String = p.toString
        }
    }

  def signatureAlgorithm(sig: AsymmetricKeyAlg.Signature): dom.Algorithm = {
    sig match {
      case rsapss: RSA_PSS_Sig =>
        new RsaPssParams {
          override val name: String = rsapss.toStringWebCrypto
          override val saltLength: Double = rsapss.saltLength
        }
      case sig: RSA_PKCS_Sig =>
        new dom.Algorithm {
          override val name: String = sig.toStringWebCrypto
        }
      case ec: AsymmetricKeyAlg.EC_Sig =>
        new EcdsaParams {
          override val hash: HashAlgorithmIdentifier = ec.hash.toStringWebCrypto
          override val name: String = ec.toStringWebCrypto
        }
    }
  }

}
