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

import scodec.bits.ByteVector

/** Signer must be created with a PrivateKey and a Signature Algorithm */
sealed trait Verifier[F[_]] extends VerifierPlatform[F] {
	//the first two arguments set up a verifier for a public key and signature type
	//returning a function that takes a signing string and a signature
	def verify(
	  spec: PublicKeySpec[_], sig: AsymmetricKeyAlg.Signature
	)(
	  signingStr: ByteVector, signature: ByteVector
	): F[Boolean]
}

private[bobcats] trait UnsealedVerifier[F[_]] extends Verifier[F]

object Verifier extends VerifierCompanionPlatform {

	def apply[F[_]](implicit verifier: Verifier[F]): verifier.type = verifier

}