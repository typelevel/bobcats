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

/**
 * Signer must be created with a PrivateKey and a Signature Algorithm
 */
sealed trait Verifier[F[_]] extends VerifierPlatform[F] {
  type SigningString = ByteVector
  type Signature = ByteVector
  /*
   * the first two arguments set up a reusable verifier fnct for a public key and signature type.
   * This verifier function takes a signing string and a signature to a boolean,
   * i.e. it is a Predicate corresponding to HasSignature(signingString, signature)
   * This is returned in the Context F to allow for asynchronous execution (eg. in the
   * browser), and also captures two places where errors can occur: In the builing of the
   * verifier using the spec (e.g. a mangled certificate) and in the verification of a signature.
  */
  def verify(
      spec: SPKIKeySpec[_],
      sig: AsymmetricKeyAlg.Signature
  ): F[(SigningString, Signature) => F[Boolean]]
}

private[bobcats] trait UnsealedVerifier[F[_]] extends Verifier[F]

object Verifier extends VerifierCompanionPlatform {

  def apply[F[_]](implicit verifier: Verifier[F]): verifier.type = verifier

}
