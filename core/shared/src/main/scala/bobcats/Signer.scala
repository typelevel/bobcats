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
sealed trait Signer[F[_]] extends SignerPlatform[F] {
	//todo: the type of the signature should dependent on the private key type
	/** Given a Private Key specification and a Signature type,
	 * return a function from Byte Vector to signatures
	 **/
	def sign( //[A<:PrivateKeyAlg, S<: PKA.Signature] <- these make coding difficult for no benefit
	  spec: PrivateKeySpec[_], sig: AsymmetricKeyAlg.Signature
	)(
	  data: ByteVector
	): F[ByteVector]
}

private[bobcats] trait UnsealedSigner[F[_]] extends Signer[F]

object Signer extends SignerCompanionPlatform {

	def apply[F[_]](implicit signer: Signer[F]): signer.type = signer

}


