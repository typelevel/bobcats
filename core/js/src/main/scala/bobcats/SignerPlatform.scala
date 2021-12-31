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

import bobcats.AsymmetricKeyAlg.{RSA_PSS_Sig, RSA_PKCS_Sig}
import cats.effect.kernel.Async
import cats.syntax.all._
import scodec.bits.ByteVector
import org.scalajs.dom
import dom.{EcdsaParams, HashAlgorithmIdentifier, crypto}

import scala.scalajs.js

private[bobcats] trait SignerPlatform[F[_]]

private[bobcats] trait SignerCompanionPlatform {
	implicit def forAsync[F[_]](implicit FA: Async[F]): Signer[F] =
		new UnsealedSigner[F] {
			/** Given a Private Key specification and a Signature type,
			 * return a function from Byte Vector to signatures
			 *   */
			override def sign(spec: PrivateKeySpec[_], sig: AsymmetricKeyAlg.Signature)(
			  data: ByteVector
			): F[ByteVector] = {
				spec.toWebCryptoKey(sig).flatMap{ (key: dom.CryptoKey) =>
					//todo: optimise so that key is only calculated once
					val algId: org.scalajs.dom.Algorithm = sig match {
						case rsapss: RSA_PSS_Sig => new org.scalajs.dom.RsaPssParams {
							override val saltLength: Double = rsapss.saltLength
							override val name: String = "RSA-PSS"
						}
						case _: RSA_PKCS_Sig => new org.scalajs.dom.Algorithm {
							override val name: String = "RSASSA-PKCS1-v1_5"
						}
						case ec: bobcats.AsymmetricKeyAlg.EC_Sig => new EcdsaParams {
								override val hash: HashAlgorithmIdentifier = ec.hash.toStringWebCrypto
								override val name: String = ec.toStringWebCrypto
							}
					}
					FA.fromPromise(FA.delay(crypto.subtle.sign(algId,key,data.toUint8Array)))
					  .map(any => ByteVector.fromJSArrayBuffer(any.asInstanceOf[js.typedarray.ArrayBuffer]))
				}
			}
		}
}
