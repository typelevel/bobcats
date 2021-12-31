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

import bobcats.AsymmetricKeyAlg.{RSA_PKCS_Sig, RSA_PSS_Sig}
import cats.effect.kernel.Async
import cats.implicits.toFunctorOps
import cats.syntax.all._
import org.scalajs.dom
import org.scalajs.dom.{EcdsaParams, HashAlgorithmIdentifier, crypto}
import scodec.bits.ByteVector

import scala.scalajs.js

private[bobcats] trait VerifierPlatform[F[_]]

private[bobcats] trait VerifierCompanionPlatform {
		implicit def forAsync[F[_]](implicit FA: Async[F]): Verifier[F] =
			new UnsealedVerifier[F] {
				override def verify(spec: PublicKeySpec[_], sig: AsymmetricKeyAlg.Signature)(
				  signingStr: ByteVector, signature: ByteVector
				): F[Boolean] = {
					//todo: optimise so that key is only calculated once
					val algId: org.scalajs.dom.Algorithm = sig match {
						case rsapss: RSA_PSS_Sig => new org.scalajs.dom.RsaPssParams {
								override val saltLength: Double = rsapss.saltLength
								override val name: String = rsapss.toStringWebCrypto
							}
						case sig: RSA_PKCS_Sig => new org.scalajs.dom.Algorithm {
							override val name: String = sig.toStringWebCrypto
						}
						case ec: bobcats.AsymmetricKeyAlg.EC_Sig => {
							new EcdsaParams {
								override val hash: HashAlgorithmIdentifier = ec.hash.toStringWebCrypto
								override val name: String = ec.toStringWebCrypto
							}
						}
					}
					spec.toWebCryptoKey(sig).flatMap { (key: dom.CryptoKey) =>
						FA.fromPromise(FA.delay {
							crypto.subtle.verify( //todo: report to dom that this should really return a Boolean promise
								algId, key, signature.toJSArrayBuffer, signingStr.toJSArrayBuffer
							)
						}).fmap[Boolean] { (any: js.Any) =>
							any.toString match { //attempting transformation to bool
								case "true" => true
								case 	_ => false
							}
						}
					}
				}
			}
}
